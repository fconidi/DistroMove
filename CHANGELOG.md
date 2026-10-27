# Changelog

## 0.1.11

- Accept the planned encrypted root mapper during final configuration checks.
- Ignore only the expected timestamp changes to runtime directories during copy verification.
- Keep the progress indicator moving, show time since the last update, and report copy and verification steps in order.

## 0.1.10

- Clear filesystem headers left in free space from a previous partition, which refused the format of a new encrypted volume.

## 0.1.9

- Remove the loader directory installed on a reused EFI system partition when a migration is rolled back, so the next attempt is not refused.
- Report what the reconciliation did or why it needs attention.
- Return to the wizard from the result of a stopped migration to try again.

## 0.1.8

- Show which checks the final verification failed, in the progress log and in the root-only log.

## 0.1.7

- Create the destination partitions when the reused EFI system partition is mounted on the same disk; the table and the kernel view are still verified afterwards.

## 0.1.6

- Keep the failed command, its exit code and its output in a root-only log, so a stopped migration can be explained.

## 0.1.5

- Name the failed command and its exit code when an external command stops a migration.

## 0.1.4

- Recognise GRUB's ability to open an encrypted boot volume on systems where XTS support is built into GRUB itself, instead of refusing the migration.
- Name the phase that stopped and the kind of failure in the progress log and in the result message.

## 0.1.3

- Show the disk containing the reused EFI system partition in the destination form.

## 0.1.2

- Read Btrfs subvolume paths consistently when a temporary top-level mount is present.
- Show commands to pause and restart detected database writers before copying.

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
