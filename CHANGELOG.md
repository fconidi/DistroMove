# Changelog

## 0.1.1

- Allow a migration to start on a system that is being written to: usage counters no longer count as a change of the source between planning and the move.
- Keep copying when a live file changes or disappears during the first, hot copy passes; the final frozen passes and the verification stay strict.
- Initialise a blank destination disk correctly (an empty GPT has no partition list).
- Accept the destination volume mounted below the running system, and a separate `/boot` volume.
- Check free space on the source only where read-only Btrfs snapshots are held.
- Read `/etc/os-release` through its link, and recognise Btrfs subvolume mounts when checking volume identities.
- Report the reason when the final verification of the copy fails.

## 0.1.0

- Add a GTK wizard for moving a running Debian-based system to new ext4 or Btrfs partitions.
- Preserve encryption with new LUKS containers and support a separate EFI system partition.
- Verify the copied system before adding its UEFI boot entry.
- Keep the old system available until its explicit, guarded removal after reboot.
- Provide English, Italian, French, German and Spanish interface text.
