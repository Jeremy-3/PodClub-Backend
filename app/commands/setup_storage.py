import sys

from app.services.media import setup_bucket


def main() -> None:
    try:
        print(f"Storage bucket ready: {setup_bucket()}")
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
