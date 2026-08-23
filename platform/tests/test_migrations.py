"""The migration runner's own guards.

Issue #35 (DRAFT-042). Every check here exists because the corresponding bug
happened, on 2026-08-22, during the first deployment to the platform LXC.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

PLATFORM_DIR = Path(__file__).resolve().parent.parent

# migrations/ is a directory of scripts, not a package, so load run.py by path
# rather than restructuring the tree to make an import work.
_spec = importlib.util.spec_from_file_location(
    "migration_runner", PLATFORM_DIR / "migrations" / "run.py"
)
run = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(run)


class FakeConn:
    """Minimal stand-in returning one scalar from execute().fetchone().

    Real connections cannot produce the bytes case without a SQL_ASCII
    database, and creating one per test costs more than it proves -- the
    behaviour under test is the decode, not Postgres.
    """

    def __init__(self, value):
        self._value = value

    def execute(self, _sql):
        return self

    def fetchone(self):
        return (self._value,)


def test_sql_ascii_is_refused_when_reported_as_bytes():
    """The actual 2026-08-22 failure.

    Under SQL_ASCII psycopg returns bytes for every text column -- including
    the answer to `SHOW server_encoding`. A naive == "SQL_ASCII" comparison
    passes, the runner proceeds, and then applied() builds a dict keyed by
    b'0001_jobs.sql' which `path.name` can never match. Every migration looks
    pending forever, and the runner re-applies the schema on every run.
    """
    problem = run.check_encoding(FakeConn(b"SQL_ASCII"))
    assert problem is not None
    assert "UTF8" in problem, "the error must say how to fix it"


def test_sql_ascii_is_refused_when_reported_as_str():
    assert run.check_encoding(FakeConn("SQL_ASCII")) is not None


@pytest.mark.parametrize("encoding", [b"UTF8", "UTF8", "LATIN1"])
def test_decodable_encodings_pass(encoding):
    assert run.check_encoding(FakeConn(encoding)) is None


def test_real_test_database_passes_the_guard(conn):
    """The suite's own database must not be the broken configuration."""
    assert run.check_encoding(conn) is None


# --- transaction-control guard -------------------------------------------

def test_plpgsql_block_begin_is_not_transaction_control(tmp_path):
    """A function body's BEGIN is a block delimiter.

    The first version of this guard rejected 0002_triggers.sql for exactly
    this reason.
    """
    sql = tmp_path / "0009_fn.sql"
    sql.write_text(
        "CREATE FUNCTION f() RETURNS trigger AS $$\n"
        "BEGIN\n"
        "    RETURN NEW;\n"
        "END;\n"
        "$$ LANGUAGE plpgsql;\n"
    )
    assert run.check_no_transaction_control(sql) is None


def test_real_commit_is_rejected(tmp_path):
    """A COMMIT closes the runner's transaction early, so the schema lands
    and its bookkeeping row does not -- half-applied and unrecorded."""
    sql = tmp_path / "0009_bad.sql"
    sql.write_text("CREATE TABLE t (i int);\nCOMMIT;\n")
    problem = run.check_no_transaction_control(sql)
    assert problem is not None and "COMMIT" in problem


def test_commit_inside_a_function_body_is_ignored(tmp_path):
    """Masking must survive the word appearing inside $$ ... $$."""
    sql = tmp_path / "0009_fn2.sql"
    sql.write_text(
        "CREATE FUNCTION f() RETURNS void AS $body$\n"
        "BEGIN\n"
        "    -- COMMIT;\n"
        "END;\n"
        "$body$ LANGUAGE plpgsql;\n"
    )
    assert run.check_no_transaction_control(sql) is None


def test_shipped_migrations_pass_both_guards():
    """Whatever is in migrations/ right now must be acceptable to the runner
    -- otherwise a deploy fails at the point it is least welcome."""
    for path in run.discover():
        assert run.check_no_transaction_control(path) is None, path.name
