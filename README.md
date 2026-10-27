# DistroMove

DistroMove moves a running Debian-based Linux installation to newly created
partitions. A GTK wizard lets you choose the destination disk and size for each
system volume, keep or create an EFI system partition, and review the plan before
starting. The existing installation stays available until you boot the new one
and explicitly approve removal of the old partitions.

## Before you start

Make a verified backup of important data. DistroMove does not resize existing
partitions. It creates new ones in available GPT space and changes boot entries
only after checking the copy. A live copy cannot guarantee application-level
consistency for databases or containers; stop those services before migrating.
On Btrfs, the program creates temporary read-only snapshots of source
subvolumes. It also records a small operation journal on the running system.

The first version supports Debian-based x86-64 systems using UEFI, GRUB,
initramfs-tools, GPT, ext4 or single-device Btrfs, with or without LUKS. It does
not support BIOS boot, LVM, RAID, ZFS or multi-device Btrfs. A destination disk
without a partition table can be initialised as GPT only after a scan finds no
recognised signatures and you type its hardware identity. That scan does not
prove the disk is free of data.

## Install and use

Install the Debian package and start **DistroMove** from the SysLinuxOS Tools
menu, or run `distromove`. The interface stays in your user session and asks for
administrator authentication when it starts its privileged helper. Review the
source volumes and any active database warning; select a disk and size for each
volume, then review the read-only plan. If the source is encrypted, enter a new
passphrase twice. The same passphrase is used for the new encrypted volumes.

After migration completes, reboot into the new system and confirm that its
volumes and data are present. Only then use **Delete old system**. The removal
screen lists the exact old partitions and requires the full confirmation text.

## When a migration stops

The progress log names the phase that stopped the run and, when an external
command refused, its name and exit code. The full output of that command is
kept for the administrator in `/var/lib/distromove/last-error.log`, which only
root can read. Check the system before retrying.

## License

GNU General Public License version 3; see `LICENSE` in the source tree or
`copyright` in the installed package.
