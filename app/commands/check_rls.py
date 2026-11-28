import sys

from sqlalchemy import create_engine, text

from app.core.config import settings


def main() -> int:
    engine = create_engine(
        settings.DATABASE_URL,
        pool_pre_ping=True,
        pool_recycle=300,
        pool_size=5,
        max_overflow=5,
    )
    try:
        with engine.connect() as connection:
            tables_without_rls = connection.execute(
                text(
                    """
                    SELECT relation.relname
                    FROM pg_class AS relation
                    JOIN pg_namespace AS namespace
                        ON namespace.oid = relation.relnamespace
                    WHERE namespace.nspname = 'public'
                        AND relation.relkind IN ('r', 'p')
                        AND NOT relation.relrowsecurity
                    ORDER BY relation.relname
                    """
                )
            ).scalars().all()
    finally:
        engine.dispose()

    if tables_without_rls:
        print("Public tables without row-level security:")
        for table_name in tables_without_rls:
            print(f"  {table_name}")
        return 1

    print("No public tables without RLS.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
