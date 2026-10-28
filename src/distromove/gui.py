"""GTK wizard and GUI-only validation. GTK is imported only when launched."""
from __future__ import annotations

import json
import threading
import time
import uuid

from .i18n import LANGUAGE, tr


def validate_form(form: dict) -> list[str]:
    """Validate values before asking the privileged helper to plan or execute."""
    issues = []
    targets = form.get("targets") or []
    if not targets or len({item.get("volume_id") for item in targets}) != len(targets):
        issues.append("targets_required")
    for item in targets:
        if (not item.get("disk") or not isinstance(item.get("size_bytes"), int)
                or item["size_bytes"] <= 0):
            issues.append("invalid_target")
            break
    if form.get("encrypted"):
        password = form.get("passphrase", "")
        confirmation = form.get("confirm_passphrase", "")
        if not password:
            issues.append("passphrase_required")
        elif password != confirmation:
            issues.append("passphrase_mismatch")
        if len(password.encode("utf-8")) > 1024:
            issues.append("passphrase_too_long")
    plan = form.get("plan") or {}
    spans = {}
    for item in [*plan.get("partitions", []), *plan.get("swaps", [])]:
        start = item.get("start_sectors")
        size = item.get("size_sectors")
        if not isinstance(start, int) or not isinstance(size, int) or start < 0 or size <= 0:
            issues.append("invalid_target")
            continue
        spans.setdefault(item.get("disk"), []).append((start, start + size))
    if any(right[0] < left[1] for ranges in spans.values()
           for left, right in zip(sorted(ranges), sorted(ranges)[1:])):
        issues.append("overlapping_targets")
    return list(dict.fromkeys(issues))


def describe_plan(plan: dict, source: dict | None = None, *, language: str = "en") -> list[str]:
    """Plain action preview; every partition, swap and excluded mount is visible."""
    lines = []
    for item in plan.get("targets", []):
        volume = item.get("volume", {})
        identity = item.get("volume_id") or volume.get("volume_id", "")
        mount = f" ({volume['mountpoint']})" if volume.get("mountpoint") else ""
        lines.append(f"{identity}{mount} → {item['disk']} · {item['size_bytes'] / 1024**3:.1f} GiB")
    for item in plan.get("init_gpt", []):
        lines.append(f"{tr('gpt_label', language)}: {item['disk']} — {item['disk_identity']}")
    for item in plan.get("partitions", []):
        label = item['role'] if item['role'] == item.get('volume_id') else f"{item['role']} {item.get('volume_id', '')}"
        lines.append(f"{label}: {item['disk']} "
                     f"{tr('sectors', language)} {item['start_sectors']}–{item['start_sectors'] + item['size_sectors'] - 1}")
    for item in plan.get("swaps", []):
        lines.append(f"{tr('swap', language)} {item.get('volume_id', '')}: {item['disk']} "
                     f"{tr('sectors', language)} {item['start_sectors']}–{item['start_sectors'] + item['size_sectors'] - 1}")
    esp = plan.get("esp", {})
    lines.append(f"ESP: {esp.get('mode', '?')} {esp.get('disk', '')}")
    for mount in (source or {}).get("unmigrated_mounts", []):
        lines.append(f"{tr('not_migrated', language)}: {mount['target']}")
    return lines


def database_warnings(activity: list[str]) -> list[str]:
    return [f"{name}: {tr('database_notice')}" for name in activity]


def pause_commands(activity: list[str]) -> list[str]:
    """Commands for known writers; each stop is followed by its restart."""
    names = {item.lower() for item in activity if not item.startswith("SQLite:")}
    writers = {item.rsplit("(", 1)[-1].removesuffix(")").lower()
               for item in activity if item.startswith("SQLite:") and "(" in item}
    pairs = []
    if "fail2ban-server" in writers:
        pairs.append(("sudo systemctl stop fail2ban", "sudo systemctl start fail2ban"))
    if "vnstatd" in writers:
        pairs.append(("sudo systemctl stop vnstat", "sudo systemctl start vnstat"))
    if "nextcloud" in writers:
        pairs.append(("nextcloud --quit", "nextcloud --background"))
    if "docker" in names:
        pairs.append(("sudo systemctl stop docker.service docker.socket",
                      "sudo systemctl start docker.socket docker.service"))
    if "postgresql" in names:
        pairs.append(("sudo systemctl stop postgresql", "sudo systemctl start postgresql"))
    if "mysql/mariadb" in names:
        pairs.append(("sudo systemctl stop mariadb", "sudo systemctl start mariadb"))
    return [command for pair in pairs for command in pair]


def reused_esp_disk(source: dict, disks: list[dict]) -> str:
    """Show the disk that actually contains the existing ESP in the reuse row."""
    path = source["esp"]["partition"]["parent_disk"]
    if path not in {disk["path"] for disk in disks}:
        raise ValueError("existing ESP disk is missing from disk inventory")
    return path


def deletion_details(state: dict, *, delete_old_esp: bool = False,
                     language: str = "en") -> list[str]:
    done = set(state.get("deletion_done", []))
    volumes = [*state.get("old_volumes", [])]
    if delete_old_esp:
        volumes.append(state["old_esp"])
    lines = []
    for item in volumes:
        token = (f"old_esp:{item['partuuid']}" if item["role"] == "esp" else
                 f"partition:{item['partuuid']}")
        suffix = f" ({tr('already_removed', language)})" if token in done else ""
        lines.append(f"{item['role']} {item['partuuid']}{suffix}")
    return lines


def confirmation_matches(typed: str, shown: str) -> bool:
    """Every line of the deletion text, exactly, ignoring only surrounding blank space.

    Invisible leading or trailing whitespace must not read as a different list of
    partitions, and nothing inside a line is allowed to differ.
    """
    return typed.strip() == shown.strip() and bool(shown.strip())


def gpt_init_prompt(disk: dict, *, language: str = "en") -> str | None:
    """A missing table is offered only after a successful, signature-free scan."""
    if disk.get("signatures") != [] or not (disk.get("serial") or disk.get("wwn") or disk.get("by_id")):
        return None
    identity = disk.get("serial") or disk.get("wwn") or disk.get("by_id")
    return f"{disk['path']} ({identity}): {tr('gpt_notice', language)}"


def back_enabled(name: str, *, busy: bool, result_ok: bool | None) -> bool:
    """Back returns on the wizard pages, and on a result that stopped, to retry."""
    if busy:
        return False
    if name == "result":
        return result_ok is False
    return name in {"destination", "encryption", "summary"}


def event_text(event: dict) -> str:
    """One progress line.  A failure names the phase that stopped and its kind."""
    phase = event.get("phase") or event.get("kind") or ""
    if phase in {"copy_detail", "verify_detail"}:
        action = "copy" if phase == "copy_detail" else "verify"
        step = event.get("step", "")
        number = event.get("number")
        total = event.get("total")
        count = f" ({number}/{total})" if number is not None and total else ""
        return f"{action}: {step}{count}"
    if phase and event.get("kind") and event["kind"] != phase:
        return f"{phase}: {event['kind']}" + (f": {event['detail']}"
                                              if event.get("detail") else "")
    if event.get("findings"):
        return f"{phase}: " + "; ".join(
            f"{item.get('severity')} {item.get('check')}: {item.get('detail')}"
            for item in event["findings"])
    if phase != "error":
        return phase
    failed, kind = event.get("failed_phase"), event.get("error")
    if kind and event.get("command"):
        kind = f"{kind}: {event['command']} exit {event.get('exit_code')}"
    detail = f"{failed} ({kind})" if failed and kind else failed or kind
    return f"error: {detail}" if detail else "error"


def duration_text(seconds: int) -> str:
    return f"{seconds // 60}:{seconds % 60:02d}"


def failure_detail(result: dict | None, error: str | None) -> str:
    """What stopped the run: the local error, else the helper's kind, else its phase."""
    result = result or {}
    return error or result.get("error") or result.get("phase") or "unknown"


def _read_exact(stream, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = stream.read_bytes(length - len(data), None).get_data()
        if not chunk:
            raise EOFError("privileged helper closed the protocol")
        data.extend(chunk)
    return bytes(data)


def _write_frame(stream, payload: bytes) -> None:
    stream.write_all(len(payload).to_bytes(4, "big") + payload, None)


def helper_request(request: dict, secret: bytes | None = None, on_event=None) -> dict:
    """Use the installed polkit helper and one binary framing format."""
    from gi.repository import Gio

    flags = (Gio.SubprocessFlags.STDIN_PIPE | Gio.SubprocessFlags.STDOUT_PIPE |
             Gio.SubprocessFlags.STDERR_SILENCE)
    process = Gio.Subprocess.new(["pkexec", "/usr/lib/distromove/helper"], flags)
    stdin = process.get_stdin_pipe()
    message = dict(request)
    message["has_secret"] = secret is not None
    _write_frame(stdin, json.dumps(message, ensure_ascii=False,
                                   separators=(",", ":")).encode("utf-8"))
    if secret is not None:
        if len(secret) > 1024:
            raise ValueError("passphrase exceeds protocol limit")
        _write_frame(stdin, secret)
    stdin.close(None)
    stdout = process.get_stdout_pipe()
    final = None
    while True:
        try:
            length = int.from_bytes(_read_exact(stdout, 4), "big")
        except EOFError:
            break
        if length > 16 * 1024 * 1024:
            raise ValueError("invalid helper frame")
        item = json.loads(_read_exact(stdout, length).decode("utf-8"))
        if not isinstance(item, dict):
            raise ValueError("invalid helper event")
        if "ok" in item:
            final = item
            break
        if on_event is not None:
            on_event(item)
    process.wait(None)
    if final is None:
        raise RuntimeError("privileged helper did not return a result")
    return final


def launch() -> int:
    import gi
    gi.require_version("Gtk", "3.0")
    from gi.repository import Gio, GLib, Gtk, Pango

    class Window(Gtk.ApplicationWindow):
        def __init__(self, app):
            super().__init__(application=app, title=tr("title"))
            self.set_icon_name("org.syslinuxos.DistroMove")
            self.set_default_size(880, 680)
            self.set_size_request(680, 480)
            self.source = None
            self.base_source = None
            self.disks = []
            self.activity = []
            self.state = None
            self.plan = None
            self.gpt_confirmations = {}
            self.included = []
            self.rows = []
            self.busy = False
            self.result_ok = None
            self.progress_active = False
            self.progress_step = ""
            self.progress_started = 0.0
            self.last_progress_event = 0.0
            self.migration_id = uuid.uuid4().hex
            self.pages = ["source", "destination", "encryption", "summary",
                          "progress", "result", "delete_old"]
            css = Gtk.CssProvider()
            css.load_from_data(b"""
                #distromove .brand { background: #123448; color: #f7fbfc;
                    padding: 20px; border-radius: 10px; }
                #distromove .brand-title { font-size: 23pt; font-weight: 700; }
                #distromove .brand-subtitle { color: #d2e6eb; }
                #distromove .section-title { font-size: 13pt; font-weight: 600; }
                #distromove .note { color: alpha(@theme_fg_color, 0.73); }
                #distromove .error { color: #b33428; }
                #distromove .stage { border: 1px solid alpha(@theme_fg_color, 0.18);
                    background: @theme_base_color; border-radius: 8px; padding: 18px; }
                #distromove button.suggested-action { background-image: none;
                    background-color: #087f78; color: #ffffff; border-color: #087f78; }
                #distromove button:focus, #distromove entry:focus {
                    outline: 2px solid @theme_selected_bg_color; outline-offset: 2px; }
            """)
            Gtk.StyleContext.add_provider_for_screen(
                self.get_screen(), css, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
            self.set_name("distromove")

            outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
            self.add(outer)
            header = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
            header.get_style_context().add_class("brand")
            title = Gtk.Label(label=tr("title"), xalign=0)
            title.get_style_context().add_class("brand-title")
            header.pack_start(title, False, False, 0)
            subtitle = Gtk.Label(label=tr("tagline"), xalign=0)
            subtitle.get_style_context().add_class("brand-subtitle")
            header.pack_start(subtitle, False, False, 0)
            outer.pack_start(header, False, False, 0)
            self.step_label = Gtk.Label(xalign=0)
            self.step_label.set_margin_start(20)
            self.step_label.set_margin_top(13)
            self.step_label.get_style_context().add_class("note")
            outer.pack_start(self.step_label, False, False, 0)
            self.step_bar = Gtk.ProgressBar()
            self.step_bar.set_margin_start(20)
            self.step_bar.set_margin_end(20)
            self.step_bar.set_margin_top(7)
            outer.pack_start(self.step_bar, False, False, 0)
            self.status = Gtk.Label(xalign=0)
            self.status.set_margin_start(20)
            self.status.set_margin_top(8)
            self.status.set_margin_bottom(8)
            self.status.set_line_wrap(True)
            outer.pack_start(self.status, False, False, 0)
            self.stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.SLIDE_LEFT_RIGHT)
            self.stack.set_hexpand(True)
            self.stack.set_vexpand(True)
            outer.pack_start(self.stack, True, True, 0)
            self.content = {}
            for name in self.pages:
                scroll = Gtk.ScrolledWindow()
                scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
                box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
                box.set_border_width(20)
                box.set_margin_start(18)
                box.set_margin_end(18)
                box.set_margin_top(8)
                box.set_margin_bottom(18)
                box.get_style_context().add_class("stage")
                scroll.add(box)
                self.stack.add_named(scroll, name)
                self.content[name] = box
            controls = Gtk.Box(spacing=10)
            controls.set_border_width(14)
            outer.pack_end(controls, False, False, 0)
            self.delete_nav = Gtk.Button(label=tr("delete_old"))
            self.delete_nav.connect("clicked", lambda *_: self.show_page("delete_old"))
            controls.pack_start(self.delete_nav, False, False, 0)
            self.back = Gtk.Button(label=tr("back"))
            self.back.connect("clicked", self.go_back)
            controls.pack_end(self.back, False, False, 0)
            self.next = Gtk.Button(label=tr("next"))
            self.next.get_style_context().add_class("suggested-action")
            self.next.connect("clicked", self.go_next)
            controls.pack_end(self.next, False, False, 0)
            self.close_button = Gtk.Button(label=tr("close"))
            self.close_button.get_style_context().add_class("suggested-action")
            self.close_button.connect("clicked", lambda *_: self.close())
            controls.pack_end(self.close_button, False, False, 0)
            self._build_source()
            self._build_encryption()
            self._build_summary()
            self._build_progress()
            GLib.timeout_add(200, self.tick_progress)
            self._build_result()
            self._build_delete()
            self.show_page("source")
            self.reload()

        def label(self, text, *, style=None):
            item = Gtk.Label(label=text, xalign=0)
            item.set_line_wrap(True)
            item.set_line_wrap_mode(Pango.WrapMode.WORD_CHAR)
            item.set_selectable(True)
            if style:
                item.get_style_context().add_class(style)
            return item

        def heading(self, box, key):
            title = self.label(tr(key), style="section-title")
            title.set_selectable(False)
            box.pack_start(title, False, False, 0)
            return title

        def clear(self, box):
            for child in list(box.get_children()):
                box.remove(child)

        def show_page(self, name):
            self.stack.set_visible_child_name(name)
            if name == "delete_old":
                self.step_label.set_text(tr("delete_old"))
                self.step_bar.set_fraction(1)
            else:
                flow = ["source", "destination"]
                if self.source and (any(v["luks"] for v in self.source["volumes"]) or
                                    any(s["luks"] for s in self.source.get("swaps", []))):
                    flow.append("encryption")
                flow.extend(("summary", "progress", "result"))
                position = flow.index(name) + 1
                self.step_label.set_text(tr("step_of").format(current=position, total=len(flow)) +
                                         " · " + tr(name))
                self.step_bar.set_fraction(position / len(flow))
            self.back.set_sensitive(back_enabled(name, busy=self.busy,
                                                 result_ok=self.result_ok))
            self.next.set_visible(name in {"source", "destination", "encryption", "summary"})
            self.close_button.set_visible(name == "result" and self.result_ok is True)
            self.next.set_sensitive(not self.busy and self.source is not None)
            self.next.set_label(tr("start") if name == "summary" else tr("next"))
            self.delete_nav.set_visible(bool(self.state and self.state.get("phase") in
                                         {"ACTIVATED", "DELETING"}) and name != "delete_old")
            if name == "delete_old":
                self.refresh_delete()

        def run_async(self, request, callback, secret=None):
            self.busy = True
            self.next.set_sensitive(False)
            self.back.set_sensitive(False)
            for widget in self._form_inputs():
                widget.set_sensitive(False)
            self.status.set_text(tr("working"))

            def worker():
                try:
                    result = helper_request(request, secret,
                                            lambda event: GLib.idle_add(self.show_event, event))
                    GLib.idle_add(self.finish_request, callback, result, None)
                except Exception as exc:
                    GLib.idle_add(self.finish_request, callback, None, type(exc).__name__)

            threading.Thread(target=worker, daemon=True).start()

        def finish_request(self, callback, result, error):
            self.busy = False
            for widget in self._form_inputs():
                widget.set_sensitive(True)
            if hasattr(self, "esp_mode"):
                self.esp_disk.set_sensitive(self.esp_mode.get_active_id() == "new")
            if error or not result or not result.get("ok"):
                self.status.set_text(f"{tr('failed')} ({failure_detail(result, error)})")
                self.next.set_sensitive(self.source is not None)
                self.back.set_sensitive(True)
                if callback == self.migration_finished:
                    self.migration_finished(result or {"ok": False})
                return False
            self.status.set_text("")
            callback(result)
            return False

        def _form_inputs(self):
            items = [self.password, self.confirm_password,
                     self.erase_luks, self.old_esp, self.delete_entry]
            if hasattr(self, "mount_checks"):
                items.extend(check for _, check in self.mount_checks)
            if hasattr(self, "esp_mode"):
                items.extend((self.esp_mode, self.esp_disk))
            for _, disk, size in self.rows:
                items.extend((disk, size))
            return items

        def show_event(self, event):
            text = event_text(event)
            if self.stack.get_visible_child_name() == "progress":
                now = time.monotonic()
                if text != self.progress_step:
                    self.progress_step = text
                    self.progress_started = now
                self.last_progress_event = now
                self.progress_label.set_text(text)
                self.log_buffer.insert(self.log_buffer.get_end_iter(), text + "\n")
                self.log_view.scroll_to_iter(self.log_buffer.get_end_iter(), 0, False, 0, 0)
                if event.get("freeze_seconds") is not None:
                    self.freeze_label.set_text(f"{event['freeze_seconds']:.1f} s")
            return False

        def tick_progress(self):
            if self.progress_active and self.stack.get_visible_child_name() == "progress":
                self.progress_bar.pulse()
                now = time.monotonic()
                elapsed = int(now - self.progress_started)
                since = int(now - self.last_progress_event)
                self.activity_label.set_text(tr("progress_times").format(
                    elapsed=duration_text(elapsed), since=duration_text(since)))
            return True

        def reload(self):
            self.run_async({"op": "probe"}, self.loaded)

        def loaded(self, result):
            self.base_source = result["source"]
            self.source = result["source"]
            self.disks = result["disks"]
            self.activity = result.get("activity", [])
            self.state = result.get("state")
            self.render_source()
            self.show_page("source")

        def _build_source(self):
            box = self.content["source"]
            self.heading(box, "source")
            box.pack_start(self.label(tr("source_intro")), False, False, 0)
            box.pack_start(self.label(tr("copy_limit"), style="note"), False, False, 0)
            self.source_details = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
            box.pack_start(self.source_details, False, False, 0)
            button = Gtk.Button(label=tr("refresh"))
            button.connect("clicked", lambda *_: self.reload())
            box.pack_start(button, False, False, 0)

        def render_source(self):
            box = self.source_details
            self.clear(box)
            src = self.base_source
            self.heading(box, "pause_services")
            box.pack_start(self.label(tr("pause_intro"), style="note"), False, False, 0)
            commands = pause_commands(self.activity)
            for stop, start in zip(commands[::2], commands[1::2]):
                box.pack_start(self.label(f"{tr('pause_stop')}: {stop}"), False, False, 0)
                box.pack_start(self.label(f"{tr('pause_start')}: {start}"), False, False, 0)
            if "nextcloud --quit" in commands:
                box.pack_start(self.label(tr("pause_nextcloud"), style="note"), False, False, 0)
            if "Docker" in self.activity:
                box.pack_start(self.label(tr("pause_docker"), style="note"), False, False, 0)
            box.pack_start(self.label(f"{tr('source_type')}: {src['kind']} · {src['os_id']}"), False, False, 0)
            encrypted = [v for v in src["volumes"] if v["luks"]]
            box.pack_start(self.label(f"{tr('encrypted')}: {len(encrypted)}"), False, False, 0)
            for volume in src["volumes"]:
                box.pack_start(self.label(f"{volume['mountpoint']} · {volume['fs']} · "
                                          f"{tr('space_used')}: {volume['used_bytes'] / 1024**3:.1f} GiB"),
                               False, False, 0)
            if self.activity:
                for warning in database_warnings(self.activity):
                    box.pack_start(self.label(warning, style="error"), False, False, 0)
            self.mount_checks = []
            if src.get("unmigrated_mounts"):
                self.heading(box, "unmigrated")
                for mount in src["unmigrated_mounts"]:
                    check = Gtk.CheckButton(label=f"{tr('include_mount')}: {mount['target']}")
                    check.set_active(mount["target"] in self.included)
                    box.pack_start(check, False, False, 0)
                    self.mount_checks.append((mount["target"], check))
            box.show_all()

        def _build_destination(self):
            box = self.content["destination"]
            self.clear(box)
            self.heading(box, "destination")
            grid = Gtk.Grid(column_spacing=14, row_spacing=10)
            box.pack_start(grid, False, False, 0)
            for column, key in enumerate(("volume", "disk", "size_gib")):
                grid.attach(self.label(tr(key), style="section-title"), column, 0, 1, 1)
            self.rows = []
            for index, volume in enumerate(self.source["volumes"], 1):
                grid.attach(self.label(f"{volume['mountpoint']} ({volume['fs']})"), 0, index, 1, 1)
                disk = Gtk.ComboBoxText()
                for item in self.disks:
                    disk.append(item["path"], f"{item.get('model') or item['path']} · {item['path']}")
                disk.set_active(0)
                disk.set_hexpand(True)
                disk.get_accessible().set_name(f"{tr('disk')}: {volume['mountpoint']}")
                grid.attach(disk, 1, index, 1, 1)
                size = Gtk.Entry()
                size.set_text(f"{volume['partition']['size_bytes'] / 1024**3:.1f}")
                size.set_input_purpose(Gtk.InputPurpose.NUMBER)
                size.set_width_chars(10)
                size.get_accessible().set_name(f"{tr('size_gib')}: {volume['mountpoint']}")
                grid.attach(size, 2, index, 1, 1)
                self.rows.append((volume, disk, size))
            if self.source.get("swaps"):
                self.heading(box, "swap")
                for swap in self.source["swaps"]:
                    box.pack_start(self.label(f"{swap['volume_id']} · {swap['kind']} · "
                                              f"{swap['size_bytes'] / 1024**3:.1f} GiB"),
                                   False, False, 0)
            self.heading(box, "esp")
            self.esp_mode = Gtk.ComboBoxText()
            self.esp_mode.append("reuse", tr("esp_reuse"))
            self.esp_mode.append("new", tr("esp_new"))
            self.esp_mode.set_active_id("reuse")
            box.pack_start(self.esp_mode, False, False, 0)
            self.esp_disk = Gtk.ComboBoxText()
            for item in self.disks:
                self.esp_disk.append(item["path"], f"{item.get('model') or item['path']} · {item['path']}")
            self.esp_disk.set_active_id(reused_esp_disk(self.source, self.disks))
            box.pack_start(self.esp_disk, False, False, 0)
            self.esp_mode.connect("changed", lambda *_: self.esp_disk.set_sensitive(
                self.esp_mode.get_active_id() == "new"))
            self.esp_disk.set_sensitive(False)
            box.show_all()

        def _build_encryption(self):
            box = self.content["encryption"]
            self.heading(box, "encryption")
            box.pack_start(self.label(tr("password_hint")), False, False, 0)
            self.password = Gtk.Entry()
            self.password.set_visibility(False)
            self.password.set_input_purpose(Gtk.InputPurpose.PASSWORD)
            self.password.get_accessible().set_name(tr("new_passphrase"))
            box.pack_start(self.label(tr("new_passphrase")), False, False, 0)
            box.pack_start(self.password, False, False, 0)
            self.confirm_password = Gtk.Entry()
            self.confirm_password.set_visibility(False)
            self.confirm_password.set_input_purpose(Gtk.InputPurpose.PASSWORD)
            self.confirm_password.get_accessible().set_name(tr("repeat_passphrase"))
            box.pack_start(self.label(tr("repeat_passphrase")), False, False, 0)
            box.pack_start(self.confirm_password, False, False, 0)

        def _build_summary(self):
            box = self.content["summary"]
            self.heading(box, "summary")
            box.pack_start(self.label(tr("preview_hint"), style="note"), False, False, 0)
            box.pack_start(self.label(tr("old_kept"), style="note"), False, False, 0)
            self.summary_text = self.label("")
            box.pack_start(self.summary_text, False, False, 0)

        def _build_progress(self):
            box = self.content["progress"]
            self.heading(box, "progress")
            self.progress_label = self.label(tr("working"))
            box.pack_start(self.progress_label, False, False, 0)
            self.progress_bar = Gtk.ProgressBar()
            box.pack_start(self.progress_bar, False, False, 0)
            self.activity_label = self.label("")
            box.pack_start(self.activity_label, False, False, 0)
            self.freeze_label = self.label("")
            box.pack_start(self.freeze_label, False, False, 0)
            view = Gtk.TextView(editable=False, cursor_visible=False, monospace=True,
                                wrap_mode=Gtk.WrapMode.WORD_CHAR)
            self.log_buffer = view.get_buffer()
            self.log_view = view
            scroll = Gtk.ScrolledWindow()
            scroll.set_min_content_height(240)
            scroll.add(view)
            box.pack_start(scroll, True, True, 0)

        def _build_result(self):
            box = self.content["result"]
            self.heading(box, "result")
            self.result_label = self.label("")
            box.pack_start(self.result_label, False, False, 0)
            self.heading(box, "progress")
            view = Gtk.TextView(buffer=self.log_buffer, editable=False,
                                cursor_visible=False, monospace=True,
                                wrap_mode=Gtk.WrapMode.WORD_CHAR)
            scroll = Gtk.ScrolledWindow()
            scroll.set_min_content_height(240)
            scroll.add(view)
            box.pack_start(scroll, True, True, 0)
            self.result_log_view = view

        def _build_delete(self):
            box = self.content["delete_old"]
            self.heading(box, "delete_old")
            box.pack_start(self.label(tr("delete_intro")), False, False, 0)
            self.delete_list = self.label("")
            box.pack_start(self.delete_list, False, False, 0)
            self.erase_luks = Gtk.CheckButton(label=tr("erase_luks"))
            self.old_esp = Gtk.CheckButton(label=tr("delete_esp"))
            for check in (self.erase_luks, self.old_esp):
                check.connect("toggled", lambda *_: self.refresh_delete())
                box.pack_start(check, False, False, 0)
            box.pack_start(self.label(tr("type_confirmation")), False, False, 0)
            self.confirmation_text = self.label("")
            box.pack_start(self.confirmation_text, False, False, 0)
            self.delete_entry = Gtk.TextView(wrap_mode=Gtk.WrapMode.WORD_CHAR)
            self.delete_entry.set_size_request(-1, 120)
            box.pack_start(self.delete_entry, False, False, 0)
            self.delete_button = Gtk.Button(label=tr("delete_action"))
            self.delete_button.get_style_context().add_class("destructive-action")
            self.delete_button.connect("clicked", self.delete_confirmed)
            box.pack_start(self.delete_button, False, False, 0)
            self.delete_button.set_sensitive(False)

        def form(self):
            targets = []
            for volume, disk, size in self.rows:
                try:
                    amount = int(float(size.get_text().replace(",", ".")) * 1024**3)
                except (ValueError, OverflowError):
                    amount = 0
                targets.append({"volume_id": volume["volume_id"], "disk": disk.get_active_id(),
                                "size_bytes": amount})
            encrypted = any(v["luks"] for v in self.source["volumes"]) or any(
                s["luks"] for s in self.source.get("swaps", []))
            return {"targets": targets, "encrypted": encrypted,
                    "passphrase": self.password.get_text(),
                    "confirm_passphrase": self.confirm_password.get_text(),
                    "esp_mode": self.esp_mode.get_active_id(), "plan": self.plan}

        def plan_request(self):
            current = self.form()
            return {"op": "plan", "include_mounts": self.included,
                    "targets": current["targets"],
                    "esp": {"mode": current["esp_mode"], "disk": self.esp_disk.get_active_id()},
                    "gpt_confirmations": self.gpt_confirmations}

        def go_back(self, *_):
            name = self.stack.get_visible_child_name()
            prior = {"destination": "source", "encryption": "destination",
                     "summary": "encryption" if self.form()["encrypted"] else "destination",
                     "result": "source"}
            if name in prior:
                if name == "result":
                    self.result_ok = None
                    self.migration_id = uuid.uuid4().hex
                    self.reload()
                    return
                self.show_page(prior[name])

        def go_next(self, *_):
            page = self.stack.get_visible_child_name()
            if page == "source":
                self.included = [path for path, check in self.mount_checks if check.get_active()]
                self.run_async({"op": "probe", "include_mounts": self.included},
                               self.included_loaded)
            elif page == "destination":
                if not self.disks or not self.rows:
                    self.status.set_text(tr("validation_error"))
                    return
                if any(not item["disk"] or item["size_bytes"] <= 0 for item in self.form()["targets"]):
                    self.status.set_text(tr("validation_error"))
                    return
                if self.form()["encrypted"]:
                    self.show_page("encryption")
                else:
                    self.prepare_summary()
            elif page == "encryption":
                if validate_form(self.form()):
                    self.status.set_text(tr("validation_error"))
                    return
                self.prepare_summary()
            elif page == "summary":
                if self.plan is not None and not validate_form(self.form()):
                    self.start_migration()
                else:
                    self.status.set_text(tr("validation_error"))

        def included_loaded(self, result):
            self.source = result["source"]
            self.disks = result["disks"]
            self.plan = None
            self._build_destination()
            self.show_page("destination")

        def prepare_summary(self):
            self.run_async(self.plan_request(), self.planned)

        def planned(self, result):
            if result.get("needs_gpt_confirmation"):
                for item in result["needs_gpt_confirmation"]:
                    dialog = Gtk.MessageDialog(
                        transient_for=self, modal=True, message_type=Gtk.MessageType.WARNING,
                        buttons=Gtk.ButtonsType.OK_CANCEL,
                        text=tr("gpt_notice"))
                    dialog.format_secondary_text(item["disk_identity"] + "\n" +
                                                 item["confirmation"])
                    entry = Gtk.Entry()
                    entry.get_accessible().set_name(item["disk_identity"])
                    dialog.get_content_area().pack_start(entry, False, False, 8)
                    dialog.show_all()
                    accepted = dialog.run() == Gtk.ResponseType.OK and entry.get_text() == item["confirmation"]
                    dialog.destroy()
                    if not accepted:
                        self.status.set_text(tr("validation_error"))
                        return
                    self.gpt_confirmations[item["disk"]] = item["confirmation"]
                self.prepare_summary()
                return
            self.plan = result["plan"]
            self.source = result["source"]
            self.summary_text.set_text("\n".join(describe_plan(self.plan, self.source,
                                                               language=LANGUAGE)))
            self.show_page("summary")

        def start_migration(self):
            current = self.form()
            secret = current["passphrase"].encode("utf-8") if current["encrypted"] else None
            self.log_buffer.set_text("")
            self.progress_step = ""
            self.progress_started = self.last_progress_event = time.monotonic()
            self.progress_active = True
            self.show_page("progress")
            self.run_async({"op": "migrate", "migration_id": self.migration_id,
                            "source": self.source, "plan": self.plan,
                            "include_mounts": self.included}, self.migration_finished, secret)

        def migration_finished(self, result):
            self.progress_active = False
            self.result_ok = bool(result.get("ok"))
            self.result_label.set_text(tr("complete") if result.get("ok") else tr("failed"))
            self.show_page("result")
            self.result_log_view.scroll_to_iter(self.log_buffer.get_end_iter(), 0,
                                                False, 0, 0)

        def refresh_delete(self):
            if not self.state:
                self.delete_list.set_text(tr("no_state"))
                return
            self.delete_list.set_text("\n".join(deletion_details(
                self.state, delete_old_esp=self.old_esp.get_active(), language=LANGUAGE)))
            self.delete_button.set_sensitive(False)
            self.run_async({"op": "preview_delete", "delete_old_esp": self.old_esp.get_active(),
                            "erase_luks_header": self.erase_luks.get_active()},
                           self.delete_previewed)

        def delete_previewed(self, result):
            self.confirmation_text.set_text(result["confirmation"])
            self.delete_button.set_sensitive(result["allowed"])
            if not result["allowed"]:
                self.status.set_text("\n".join(result["reasons"]))

        def delete_confirmed(self, *_):
            buffer = self.delete_entry.get_buffer()
            typed = buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), True)
            shown = self.confirmation_text.get_text()
            if not confirmation_matches(typed, shown):
                self.status.set_text(tr("confirmation_mismatch"))
                return
            self.run_async({"op": "delete_old", "confirmation": shown.strip(),
                            "delete_old_esp": self.old_esp.get_active(),
                            "erase_luks_header": self.erase_luks.get_active()},
                           self.deleted)

        def deleted(self, result):
            self.status.set_text(result["phase"])
            self.delete_button.set_sensitive(False)
            self.reload()

    class Application(Gtk.Application):
        def __init__(self):
            super().__init__(application_id="org.syslinuxos.DistroMove",
                             flags=Gio.ApplicationFlags.FLAGS_NONE)

        def do_activate(self):
            if not self.get_active_window():
                window = Window(self)
                window.show_all()
                window.show_page("source")
            self.get_active_window().present()

    return Application().run([])
