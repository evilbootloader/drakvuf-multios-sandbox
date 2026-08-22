"""Fixtures for the queue tests.

Issue #35 (DRAFT-042).

Against a REAL Postgres, deliberately. FOR UPDATE SKIP LOCKED, transactional
visibility and LISTEN/NOTIFY are the things under test and none of them exists
in a substitute.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import psycopg
import pytest

PLATFORM_DIR = Path(__file__).resolve().parent.parent
DSN = os.environ.get("TEST_DATABASE_URL", "postgresql:///sandbox_platform_test")


@pytest.fixture(scope="session", autouse=True)
def migrated() -> None:
    """Bring the test database up to the current schema, once per run.

    Invokes the real runner rather than loading the .sql files directly, so
    the tests exercise the same path a deployment uses -- a migration that
    only applies when a test applies it is not a migration anyone can trust.
    """
    subprocess.run(
        [sys.executable, str(PLATFORM_DIR / "migrations" / "run.py")],
        env={**os.environ, "DATABASE_URL": DSN},
        check=True,
        capture_output=True,
    )


@pytest.fixture
def conn():
    """A clean database and an autocommit connection.

    autocommit because several tests open ADDITIONAL connections, in threads,
    and must see each other's committed rows. Wrapping a test in one
    transaction would hide precisely the concurrency this suite exists to
    check.

    RESTART IDENTITY resets queue_seq, so "the head of the queue" is
    deterministic per test rather than depending on execution order.
    """
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute("TRUNCATE jobs, worker_pipelines, workers RESTART IDENTITY CASCADE")
        yield c


# --- helpers ---------------------------------------------------------------
#
# Jobs are inserted straight to 'queued' here. Admission is the API's (#36);
# this suite tests the queue, and going through an admission path that does
# not exist yet would test nothing but the fixture.

def enqueue(conn, target_os: str, required_mib: int, filename: str | None = None):
    """Put one job on the queue and return its id."""
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO jobs (target_os, submitted_filename, required_mib, state)
            VALUES (%s, %s, %s, 'queued')
            RETURNING id
            """,
            (target_os, filename or f"{target_os}-{required_mib}.bin", required_mib),
        )
        return cur.fetchone()[0]


def state_of(conn, job_id) -> str:
    with conn.cursor() as cur:
        cur.execute("SELECT state FROM jobs WHERE id = %s", (job_id,))
        return cur.fetchone()[0]


def count_in_state(conn, state: str) -> int:
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM jobs WHERE state = %s", (state,))
        return cur.fetchone()[0]