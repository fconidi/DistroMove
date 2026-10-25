# DistroMove

DistroMove migrates a running Debian-based Linux system onto new partitions,
optionally with encryption, and sets up the boot loader so the copy starts on its own.

The source system stays untouched while you keep using it. Every destructive step
is planned first, shown to you and confirmed before anything is written to a disk.

## Requirements

- Debian or a Debian-based distribution (including SysLinuxOS)
- Python 3.11 or later
- Root privileges for the steps that change disks

## Usage

    python3 -m distromove --version

## License

See the LICENSE file.
