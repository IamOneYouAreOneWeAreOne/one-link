"""PyInstaller entry point for the isolated One Link update helper."""

from one_link.update_helper import helper_main


if __name__ == "__main__":
    raise SystemExit(helper_main())
