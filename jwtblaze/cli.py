import argparse
import sys
import logging
from .core import crack_jwt

logger = logging.getLogger(__name__)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="JWTBlaze — JWT Secret Auditor (GPU + CPU, Windows/Linux)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="  GitHub: https://github.com/srsoumyax11",
    )
    parser.add_argument("--token",      required=True,   help="Full JWT token string (3 parts)")
    parser.add_argument("--wordlist",   required=True,   help="Path to wordlist file")
    parser.add_argument("--workers",    type=int,        help="CPU worker count (default: all cores)")
    parser.add_argument("--cpu",        action="store_true",
                        help="Force CPU mode (skip hashcat even if installed)")
    parser.add_argument("--version", action="store_true", help="Show version and exit")

    args = parser.parse_args(argv)

    from . import __version__

    if args.version:
        print(__version__)
        return 0

    success = crack_jwt(args.token, args.wordlist,
                        force_cpu=args.cpu,
                        num_workers=args.workers)
    return 0 if success else 2


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    sys.exit(main())
