"""mcddos entrypoint."""
import sys

from .cli import main_sync

if __name__ == "__main__":
    sys.exit(main_sync())
