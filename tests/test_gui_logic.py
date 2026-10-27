from distromove.gui import (confirmation_matches, database_warnings, deletion_details, describe_plan,
                            duration_text, event_text, failure_detail, gpt_init_prompt, pause_commands,
                            reused_esp_disk, validate_form)


def test_reused_esp_disk_is_existing_esp_parent_not_first_inventory_disk():
    source = {"esp": {"partition": {"path": "/dev/nvme0n1p1",
                                   "parent_disk": "/dev/nvme0n1"}}}
    disks = [{"path": "/dev/sda"}, {"path": "/dev/nvme0n1"}]
    assert reused_esp_disk(source, disks) == "/dev/nvme0n1"


def form(**changes):
    value = {
        "targets": [{"volume_id": "root", "disk": "/dev/disk/by-id/disk-a",
                     "size_bytes": 30 * 1024**3}],
        "encrypted": True, "passphrase": "long secret", "confirm_passphrase": "long secret",
        "esp_mode": "reuse", "plan": None,
    }
    value.update(changes)
    return value


def test_validate_form_rejects_empty_or_mismatched_passphrase():
    assert "passphrase_required" in validate_form(form(passphrase="", confirm_passphrase=""))
    assert "passphrase_mismatch" in validate_form(form(confirm_passphrase="other"))
    assert "passphrase_too_long" in validate_form(form(passphrase="é" * 513,
                                                     confirm_passphrase="é" * 513))


def test_validate_form_rejects_overlapping_targets():
    plan = {"partitions": [
        {"disk": "/dev/a", "start_sectors": 2048, "size_sectors": 4096},
        {"disk": "/dev/a", "start_sectors": 4096, "size_sectors": 4096},
    ], "swaps": []}
    assert "overlapping_targets" in validate_form(form(plan=plan))


def test_describe_plan_lists_partitions_swaps_esp_choice_unmigrated_mounts():
    plan = {
        "targets": [{"volume_id": "root", "disk": "/dev/a", "size_bytes": 1024**3}],
        "partitions": [{"volume_id": "root", "role": "root", "disk": "/dev/a",
                        "start_sectors": 2048, "size_sectors": 4096}],
        "swaps": [{"volume_id": "swap-1", "role": "swap", "disk": "/dev/a",
                   "start_sectors": 8192, "size_sectors": 4096}],
        "esp": {"mode": "new", "disk": "/dev/a", "size_bytes": 512 * 1024**2},
        "init_gpt": [],
    }
    source = {"unmigrated_mounts": [{"target": "/data"}]}
    result = "\n".join(describe_plan(plan, source))
    assert "root" in result and "swap-1" in result
    assert "ESP" in result and "new" in result and "/data" in result


def test_database_warnings_postgres_docker():
    warnings = database_warnings(["PostgreSQL", "Docker"])
    assert len(warnings) == 2
    assert "PostgreSQL" in warnings[0]
    assert "Docker" in warnings[1]


def test_pause_commands_cover_detected_writers_and_their_restart():
    lines = pause_commands([
        "SQLite: /var/lib/fail2ban/fail2ban.sqlite3 (fail2ban-server)",
        "SQLite: /var/lib/vnstat/vnstat.db (vnstatd)",
        "SQLite: /home/user/.local/share/Nextcloud/sync.db (nextcloud)",
        "Docker", "PostgreSQL",
    ])

    assert "sudo systemctl stop fail2ban" in lines
    assert "sudo systemctl start fail2ban" in lines
    assert "sudo systemctl stop vnstat" in lines
    assert "sudo systemctl start vnstat" in lines
    assert "nextcloud --quit" in lines
    assert "nextcloud --background" in lines
    assert "sudo systemctl stop docker.service docker.socket" in lines
    assert "sudo systemctl start docker.socket docker.service" in lines
    assert "sudo systemctl stop postgresql" in lines
    assert "sudo systemctl start postgresql" in lines
    assert all("mariadb" not in line for line in lines)


def test_pause_commands_do_not_confuse_a_database_path_with_its_writer():
    assert pause_commands(["SQLite: /home/user/Nextcloud/app.db (firefox)"]) == []


def test_delete_page_lists_all_old_partitions():
    state = {"migration_id": "migration-1", "deletion_done": ["partition:part-1"],
             "old_volumes": [{"role": "root", "partuuid": "part-1"},
                             {"role": "home", "partuuid": "part-2"}],
             "old_esp": {"role": "esp", "partuuid": "esp-1"}}
    lines = "\n".join(deletion_details(state, delete_old_esp=True))
    assert "part-1" in lines and "part-2" in lines and "esp-1" in lines
    assert "already removed" in lines


def test_confirmation_matches_despite_a_trailing_newline_or_spaces():
    shown = ("Delete old system for migration abc:\n"
             "root 1111-2222 disk=0xaa start=2048 size=4096")
    assert confirmation_matches(shown + "\n", shown)
    assert confirmation_matches("  " + shown + " \n\n", shown)
    assert confirmation_matches(shown, shown)


def test_confirmation_refuses_a_changed_or_missing_line():
    shown = ("Delete old system for migration abc:\n"
             "root 1111-2222 disk=0xaa start=2048 size=4096\n"
             "esp 3333-4444 disk=0xaa start=2048 size=1024")
    assert not confirmation_matches(shown.rsplit("\n", 1)[0], shown)
    assert not confirmation_matches(shown.replace("2048", "2049"), shown)
    assert not confirmation_matches(shown.replace("root 1111", "root  1111"), shown)
    assert not confirmation_matches("", shown)


def test_gpt_init_prompt_only_when_wipefs_clean():
    clean = {"path": "/dev/a", "signatures": [], "serial": "SERIAL",
             "size_bytes": 10 * 1024**3, "logical_sector": 512}
    assert "no recognised signatures" in gpt_init_prompt(clean).lower()
    assert "SERIAL" in gpt_init_prompt(clean)
    assert gpt_init_prompt({**clean, "signatures": ["ext4"]}) is None
    assert gpt_init_prompt({**clean, "signatures": None}) is None


def test_event_text_names_the_phase_that_stopped_and_the_error_kind():
    assert event_text({"phase": "copy"}) == "copy"
    assert event_text({"phase": "error", "failed_phase": "preflight",
                       "error": "UnsupportedKdf"}) == "error: preflight (UnsupportedKdf)"
    assert event_text({"phase": "error"}) == "error"
    assert event_text({"phase": "verify_detail", "step": "copy integrity",
                       "number": 2, "total": 3}) == "verify: copy integrity (2/3)"
    assert duration_text(185) == "3:05"


def test_failure_detail_prefers_the_error_over_the_phase():
    assert failure_detail({"ok": False, "phase": "preflight",
                           "error": "UnsupportedKdf"}, None) == "UnsupportedKdf"
    assert failure_detail({"ok": False, "phase": "copy"}, None) == "copy"
    assert failure_detail(None, "RuntimeError") == "RuntimeError"
    assert failure_detail(None, None) == "unknown"


def test_event_text_names_the_failed_command_and_its_exit_code():
    assert event_text({"phase": "error", "failed_phase": "create_storage",
                       "error": "RunnerError", "command": "sfdisk",
                       "exit_code": 1}) == "error: create_storage (RunnerError: sfdisk exit 1)"


def test_event_text_lists_the_failed_verification_checks():
    event = {"phase": "verify_findings", "findings": [
        {"severity": "error", "check": "initramfs", "detail": "missing cryptsetup hook"},
        {"severity": "warning", "check": "esp", "detail": "extra loader directory"}]}
    assert event_text(event) == ("verify_findings: error initramfs: missing cryptsetup hook; "
                                 "warning esp: extra loader directory")


def test_event_text_shows_what_the_reconciliation_did():
    assert event_text({"phase": "reconcile", "kind": "manual_review",
                       "detail": "owned destination residues require manual review"}) == (
        "reconcile: manual_review: owned destination residues require manual review")
    assert event_text({"phase": "reconcile", "kind": "rolled_back",
                       "detail": "2909"}) == "reconcile: rolled_back: 2909"


def test_back_is_available_again_after_a_stopped_migration():
    from distromove.gui import back_enabled
    assert back_enabled("destination", busy=False, result_ok=None) is True
    assert back_enabled("destination", busy=True, result_ok=None) is False
    # A stopped run must be retryable without restarting the program.
    assert back_enabled("result", busy=False, result_ok=False) is True
    # A finished migration is not undone by walking back through the wizard.
    assert back_enabled("result", busy=False, result_ok=True) is False
    assert back_enabled("progress", busy=False, result_ok=None) is False
