import sys

from . import __version__


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] in ("--version", "-V"):
        print(f"distromove {__version__}")
        return 0
    print("usage: python3 -m distromove [--version]")
    return 0 if not args or args[0] in ("-h", "--help") else 2


if __name__ == "__main__":
    sys.exit(main())
