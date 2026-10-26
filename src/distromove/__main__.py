import sys

from . import __version__


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] in ("--version", "-V"):
        print(f"distromove {__version__}")
        return 0
    if args and args[0] in ("-h", "--help"):
        print("usage: python3 -m distromove [--version]")
        return 0
    if args:
        print("usage: python3 -m distromove [--version]", file=sys.stderr)
        return 2
    from .gui import launch
    return launch()


if __name__ == "__main__":
    sys.exit(main())
