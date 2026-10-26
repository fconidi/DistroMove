from distromove.gui import (database_warnings, deletion_details, describe_plan,
                            gpt_init_prompt, validate_form)


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


def test_delete_page_lists_all_old_partitions():
    state = {"migration_id": "migration-1", "deletion_done": ["partition:part-1"],
             "old_volumes": [{"role": "root", "partuuid": "part-1"},
                             {"role": "home", "partuuid": "part-2"}],
             "old_esp": {"role": "esp", "partuuid": "esp-1"}}
    lines = "\n".join(deletion_details(state, delete_old_esp=True))
    assert "part-1" in lines and "part-2" in lines and "esp-1" in lines
    assert "already removed" in lines


def test_gpt_init_prompt_only_when_wipefs_clean():
    clean = {"path": "/dev/a", "signatures": [], "serial": "SERIAL",
             "size_bytes": 10 * 1024**3, "logical_sector": 512}
    assert "no recognised signatures" in gpt_init_prompt(clean).lower()
    assert "SERIAL" in gpt_init_prompt(clean)
    assert gpt_init_prompt({**clean, "signatures": ["ext4"]}) is None
    assert gpt_init_prompt({**clean, "signatures": None}) is None
