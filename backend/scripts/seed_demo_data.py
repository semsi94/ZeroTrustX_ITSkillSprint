import argparse
import asyncio

from db.session import SessionLocal
from services.demo_seed_service import reset_demo_data, seed_demo_data


async def _run(reset_only: bool, reset_first: bool) -> None:
    async with SessionLocal() as db:
        if reset_only:
            result = await reset_demo_data(db)
        else:
            result = await seed_demo_data(db, reset_first=reset_first)
        print(result)


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed ZeroTrustX demo data")
    parser.add_argument("--reset", action="store_true", help="Delete demo records only")
    parser.add_argument("--no-reset-first", action="store_true", help="Do not clear demo rows before seeding")
    args = parser.parse_args()
    asyncio.run(_run(reset_only=args.reset, reset_first=not args.no_reset_first))


if __name__ == "__main__":
    main()
