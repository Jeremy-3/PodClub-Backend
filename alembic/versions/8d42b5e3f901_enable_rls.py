"""enable row-level security on public tables

Revision ID: 8d42b5e3f901
Revises: 7c31a4d2e8f0
Create Date: 2026-11-28 10:31:00.000000

"""
from typing import Sequence, Union

from alembic import op


revision: str = "8d42b5e3f901"
down_revision: Union[str, Sequence[str], None] = "7c31a4d2e8f0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        DO $$
        DECLARE
            public_table RECORD;
            has_anon BOOLEAN;
            has_authenticated BOOLEAN;
        BEGIN
            SELECT EXISTS (
                SELECT 1 FROM pg_roles WHERE rolname = 'anon'
            ) INTO has_anon;
            SELECT EXISTS (
                SELECT 1 FROM pg_roles WHERE rolname = 'authenticated'
            ) INTO has_authenticated;

            FOR public_table IN
                SELECT relation.relname
                FROM pg_class AS relation
                JOIN pg_namespace AS namespace
                    ON namespace.oid = relation.relnamespace
                WHERE namespace.nspname = 'public'
                    AND relation.relkind IN ('r', 'p')
            LOOP
                EXECUTE format(
                    'ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY',
                    'public',
                    public_table.relname
                );
                IF has_anon THEN
                    EXECUTE format(
                        'REVOKE ALL PRIVILEGES ON TABLE %I.%I FROM anon',
                        'public',
                        public_table.relname
                    );
                END IF;
                IF has_authenticated THEN
                    EXECUTE format(
                        'REVOKE ALL PRIVILEGES ON TABLE %I.%I FROM authenticated',
                        'public',
                        public_table.relname
                    );
                END IF;
            END LOOP;
        END;
        $$;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DO $$
        DECLARE
            public_table RECORD;
        BEGIN
            FOR public_table IN
                SELECT relation.relname
                FROM pg_class AS relation
                JOIN pg_namespace AS namespace
                    ON namespace.oid = relation.relnamespace
                WHERE namespace.nspname = 'public'
                    AND relation.relkind IN ('r', 'p')
            LOOP
                EXECUTE format(
                    'ALTER TABLE %I.%I DISABLE ROW LEVEL SECURITY',
                    'public',
                    public_table.relname
                );
            END LOOP;
        END;
        $$;
        """
    )
