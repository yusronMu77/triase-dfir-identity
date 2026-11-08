"""Jalankan layanan: `astria-identity` atau `python -m astria_identity`."""

from astria_common.app import run

from astria_identity.main import build_app
from astria_identity.settings import Settings


def main() -> None:
    settings = Settings()
    run(build_app(settings), settings)


if __name__ == "__main__":
    main()
