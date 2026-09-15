"""How `Settings` parses booleans, for every boolean it has.

`REQUIRE_ACCESS_JWT=true` used to mean False. It was the one bool on `Settings`
not routed through `_bool()` -- it compared against the literal `"1"` -- so the
spelling an operator learns from `CONSOLE_ENABLED` and `REGISTRATION_OPEN`
silently left Cloudflare Access verification off on the browser listener. That
flag fails OPEN: `auth.access_identity` returns None without ever reading the
header when it is false, so a typo did not close a door, it removed one.

These tests are therefore not about that field. They REFLECT over the dataclass:
every field annotated `bool` must read `1`, `true`, `yes` and `on` as True and
anything else as False. A hand-written list of field names would drift out of
date exactly the way the hand-written parse did, which is the defect rather than
a way to test for it -- so the only thing written by hand here is the set of
spellings.
"""

from __future__ import annotations

import ast
import dataclasses
import importlib.util
import sys
from pathlib import Path

import pytest

from sandbox_platform import config

CONFIG_PATH = Path(config.__file__)

# Case and surrounding whitespace are not part of the spelling: `_bool` strips
# and lowercases before it compares, and an environment block edited by hand is
# where a stray trailing space comes from.
TRUE_SPELLINGS = ["1", "true", "yes", "on", "TRUE", "Yes", "  on  ", "On"]

# `ture` is the typo `_bool`'s docstring is written around. The rest are the
# near-misses that look affirmative to a person: a flag must not open because
# someone wrote the word they meant rather than the word that is accepted.
FALSE_SPELLINGS = [
    "0", "false", "no", "off", "", "   ", "ture", "y", "t", "2", "-1",
    "enabled", "yes please", "true-ish",
]


def _declared_bool_fields() -> dict[str, str]:
    """Field name -> environment variable, read from the SOURCE of `Settings`.

    From the source because the variable name survives nowhere at runtime: the
    class keeps the parsed value and forgets what it was read from, so there is
    no object to ask.

    The name is the first string literal in the assignment, by position, which
    holds for both spellings this file has carried -- `_bool("X", False)` and
    the `os.environ.get("X", "") == "1"` this suite exists because of. So a
    field that reintroduces the hand-written form is still discovered here, and
    still has to pass everything below.
    """
    module = ast.parse(CONFIG_PATH.read_text())
    (klass,) = [node for node in module.body
                if isinstance(node, ast.ClassDef) and node.name == "Settings"]

    found: dict[str, str] = {}
    for node in klass.body:
        if not isinstance(node, ast.AnnAssign) or node.value is None:
            continue
        if getattr(node.annotation, "id", None) != "bool":
            continue
        literals = sorted(
            (n for n in ast.walk(node.value)
             if isinstance(n, ast.Constant) and isinstance(n.value, str)),
            # ast.walk is breadth-first, so `... == "1"` would otherwise hand
            # back the comparison's literal before the variable's name.
            key=lambda n: (n.lineno, n.col_offset),
        )
        assert literals, (
            f"{node.target.id} is a bool with no string literal in its "
            f"default; this parser cannot tell which variable it reads"
        )
        found[node.target.id] = literals[0].value
    return found


BOOL_FIELDS = _declared_bool_fields()


def load(monkeypatch, variable: str, raw: str | None):
    """A fresh `Settings`, with `variable` set to `raw` (None to unset it).

    `Settings` reads the environment at CLASS CREATION, so every default is
    baked into the class object the moment `config.py` is first imported and
    setting a variable afterwards changes nothing. Re-executing the file is
    what makes the parse observable at all.

    Under a private module name rather than `importlib.reload`: reloading the
    real module rebinds `sandbox_platform.config.settings` to a new object for
    the rest of the session, while every module that did `from .config import
    settings` goes on holding the old one -- two snapshots, disagreeing, and a
    later failure somewhere else that points at nothing. This copy is reachable
    only from this function.
    """
    if raw is None:
        monkeypatch.delenv(variable, raising=False)
    else:
        monkeypatch.setenv(variable, raw)

    spec = importlib.util.spec_from_file_location("_config_probe", CONFIG_PATH)
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolves the defining module out of sys.modules while
    # deciding whether a string annotation is a ClassVar. monkeypatch drops the
    # entry again at teardown, so the probe never outlives the test.
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    return module.Settings()


def test_reflection_agrees_with_the_dataclass():
    """Every bool field was found by the source parser, and nothing else was.

    The parametrised tests below run once per entry in `BOOL_FIELDS`, so a
    field the parser fails to see is not a failing test -- it is no test. This
    is what turns that silence into a failure.
    """
    annotated = {
        f.name for f in dataclasses.fields(config.Settings)
        # `from __future__ import annotations` leaves every annotation a
        # string; the type object is accepted too so this does not quietly
        # match nothing if that import is ever dropped.
        if f.type in ("bool", bool)
    }
    assert set(BOOL_FIELDS) == annotated


@pytest.mark.parametrize("field_name,variable", sorted(BOOL_FIELDS.items()))
@pytest.mark.parametrize("raw", TRUE_SPELLINGS)
def test_every_true_spelling_is_accepted(monkeypatch, field_name, variable, raw):
    assert getattr(load(monkeypatch, variable, raw), field_name) is True


@pytest.mark.parametrize("field_name,variable", sorted(BOOL_FIELDS.items()))
@pytest.mark.parametrize("raw", FALSE_SPELLINGS)
def test_anything_else_is_false(monkeypatch, field_name, variable, raw):
    assert getattr(load(monkeypatch, variable, raw), field_name) is False


@pytest.mark.parametrize("field_name,variable", sorted(BOOL_FIELDS.items()))
def test_unset_is_off(monkeypatch, field_name, variable):
    """Every one of these flags opens something, so none may default to on.

    True of all four today -- console, Access enforcement, the opening grant,
    the unauthenticated listener -- and asserted for the whole set rather than
    for the four, because the question a new flag has to answer is the same
    one. A field that genuinely wants to default on has to come here and argue
    with this test, which is the point.
    """
    assert getattr(load(monkeypatch, variable, None), field_name) is False


def test_require_access_jwt_reads_true(monkeypatch):
    """The regression, named, because the general test does not say what broke.

    `REQUIRE_ACCESS_JWT=1` is unchanged -- `_bool` accepts it -- so a unit
    already written that way parses identically; it is the other spellings that
    stopped meaning False.
    """
    assert load(monkeypatch, "REQUIRE_ACCESS_JWT", "true").require_access_jwt
    assert load(monkeypatch, "REQUIRE_ACCESS_JWT", "1").require_access_jwt