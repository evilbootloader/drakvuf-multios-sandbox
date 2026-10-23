"""Falco's condition language: parse, expand lists, compile to a function.

The grammar is libsinsp's filter grammar as falcosecurity/rules uses it:
`not` binds tighter than `and`, `and` tighter than `or`; a check is a field,
an operator and a value; a bare word without a dot is a macro; a parenthesised
value list may name a list, which is expanded in place.

**Evaluation is three-valued, which is where this departs from Falco.** Falco
reads a field it cannot extract as false, so `not proc.pname in (...)` is true
for a process whose parent it never saw. Over a DRAKVUF trace far more is
unknowable -- a syscall's result without sysret, a process's arguments when it
was running before the trace -- and reading every gap as false would turn
each negated check into an alert. So a field the trace cannot provide returns
`UNKNOWN`, `and`/`or`/`not` follow Kleene's logic, and only a definite True
is an alert. A field that the trace does provide but that has no value (a
container field on a VM, a parent past the root) returns None and behaves as
Falco's unextractable field does: every comparison is false.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass
from typing import Callable, Dict, FrozenSet, Iterable, Optional, Set, Tuple, Union


class ConditionError(ValueError):
    """The condition does not parse, or names something that does not exist."""


class UnsupportedField(ConditionError):
    """A field this evaluator has no extractor for."""


class _Unknown:
    __slots__ = ()

    def __repr__(self) -> str:
        return "UNKNOWN"

    def __bool__(self) -> bool:  # pragma: no cover - a bug if ever reached
        raise TypeError("UNKNOWN has no truth value; compare with `is`")


UNKNOWN = _Unknown()


class Multi:
    """A field with several values, as `proc.aname` without an index.

    A check is true when any value satisfies it, as in libsinsp. `complete`
    is False when the values are known to be only part of the truth (an
    ancestry that runs into a process the trace never saw, environment
    variables procmon was not told to print), so that a check none of them
    satisfies is unknown rather than false.
    """
    __slots__ = ("values", "complete")

    def __init__(self, values: Iterable, complete: bool = True) -> None:
        self.values = tuple(values)
        self.complete = complete

    def decides(self, test) -> bool:
        """Whether a test none of the values passed is false after all."""
        return False


class Environment(Multi):
    """`proc.env`: the `NAME=value` pairs of the variables procmon printed.

    Incomplete, because procmon prints only the names on its list. But a
    `contains`/`icontains` test for one of those names, which is how Falco's
    rules ask (`proc.env icontains GLIBC_TUNABLES`), is decided: the variable
    would have been printed had it been set.
    """
    __slots__ = ("names",)

    def __init__(self, values: Iterable, names: Iterable[str]) -> None:
        super().__init__(values, complete=False)
        self.names = frozenset(names)

    def decides(self, test) -> bool:
        op, needle = getattr(test, "op", None), getattr(test, "needle", None)
        if op not in ("contains", "icontains") or not needle:
            return False
        name = needle.split("=", 1)[0]
        if op == "contains":
            return name in self.names
        return name.lower() in {n.lower() for n in self.names}

    def __repr__(self) -> str:
        return f"Multi({list(self.values)!r}, complete={self.complete})"


# --- the syntax tree ----------------------------------------------------------

@dataclass(frozen=True)
class And:
    items: Tuple["Node", ...]


@dataclass(frozen=True)
class Or:
    items: Tuple["Node", ...]


@dataclass(frozen=True)
class Not:
    item: "Node"


@dataclass(frozen=True)
class MacroRef:
    name: str


@dataclass(frozen=True)
class FieldRef:
    name: str
    arg: Optional[str]
    transformer: Optional[str] = None

    def __str__(self) -> str:
        text = self.name + (f"[{self.arg}]" if self.arg is not None else "")
        return f"{self.transformer}({text})" if self.transformer else text


@dataclass(frozen=True)
class Check:
    field: FieldRef
    op: str
    # A string, a tuple of strings for list operators, a FieldRef for
    # `val(...)`, or None for `exists`.
    value: Union[str, Tuple[str, ...], FieldRef, None]


Node = Union[And, Or, Not, MacroRef, Check]

SYMBOLIC_OPS = ("==", "!=", "<=", ">=", "=", "<", ">")
WORD_OPS = frozenset({
    "contains", "icontains", "bcontains", "startswith", "bstartswith",
    "endswith", "glob", "iglob", "in", "intersects", "pmatch", "regex",
    "exists",
})
LIST_OPS = frozenset({"in", "intersects", "pmatch"})
TRANSFORMERS = frozenset({"tolower", "toupper", "b64", "basename", "len"})

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_.]*")
_BRACKET = re.compile(r"\[([^\]]*)\]")
_WORD = re.compile(r"[A-Za-z_]+")
_BARE_VALUE = re.compile(r"[^\s()]+")
_BARE_ITEM = re.compile(r"[^\s(),]+")
_SPACE = re.compile(r"\s*")


class _Parser:
    def __init__(self, text: str, lists: Dict[str, list]) -> None:
        self.text = text
        self.pos = 0
        self.lists = lists

    # -- scanning ---------------------------------------------------------

    def _skip(self) -> None:
        self.pos = _SPACE.match(self.text, self.pos).end()

    def _peek(self, s: str) -> bool:
        self._skip()
        return self.text.startswith(s, self.pos)

    def _keyword(self, word: str) -> bool:
        """Consume `word` if it is the next whole word."""
        self._skip()
        m = _WORD.match(self.text, self.pos)
        if m and m.group(0) == word:
            self.pos = m.end()
            return True
        return False

    def _expect(self, s: str) -> None:
        if not self._peek(s):
            raise self._error(f"expected {s!r}")
        self.pos += len(s)

    def _error(self, what: str) -> ConditionError:
        near = self.text[self.pos:self.pos + 40]
        return ConditionError(f"{what} at offset {self.pos}: {near!r}")

    def _string(self) -> Optional[str]:
        """A quoted string, unescaped, or None if none starts here."""
        self._skip()
        if self.pos >= len(self.text) or self.text[self.pos] not in "\"'":
            return None
        quote = self.text[self.pos]
        out = []
        i = self.pos + 1
        while i < len(self.text):
            c = self.text[i]
            if c == "\\" and i + 1 < len(self.text):
                nxt = self.text[i + 1]
                out.append({"n": "\n", "t": "\t", "r": "\r"}.get(nxt, nxt))
                i += 2
                continue
            if c == quote:
                self.pos = i + 1
                return "".join(out)
            out.append(c)
            i += 1
        raise self._error("unterminated string")

    # -- grammar ----------------------------------------------------------

    def parse(self) -> Node:
        node = self._or()
        self._skip()
        if self.pos != len(self.text):
            raise self._error("unexpected text")
        return node

    def _or(self) -> Node:
        items = [self._and()]
        while self._keyword("or"):
            items.append(self._and())
        return items[0] if len(items) == 1 else Or(tuple(items))

    def _and(self) -> Node:
        items = [self._not()]
        while self._keyword("and"):
            items.append(self._not())
        return items[0] if len(items) == 1 else And(tuple(items))

    def _not(self) -> Node:
        if self._keyword("not"):
            return Not(self._not())
        return self._primary()

    def _primary(self) -> Node:
        if self._peek("("):
            self.pos += 1
            node = self._or()
            self._expect(")")
            return node
        self._skip()
        m = _IDENT.match(self.text, self.pos)
        if not m:
            raise self._error("expected a field, a macro or '('")
        name = m.group(0)
        self.pos = m.end()
        if name in TRANSFORMERS and self._peek("("):
            self.pos += 1
            inner = self._field_ref()
            self._expect(")")
            return self._check(FieldRef(inner.name, inner.arg, name))
        if "." not in name:
            return MacroRef(name)
        return self._check(FieldRef(name, self._bracket()))

    def _bracket(self) -> Optional[str]:
        m = _BRACKET.match(self.text, self.pos)
        if not m:
            return None
        self.pos = m.end()
        return m.group(1)

    def _field_ref(self) -> FieldRef:
        self._skip()
        m = _IDENT.match(self.text, self.pos)
        if not m or "." not in m.group(0):
            raise self._error("expected a field")
        self.pos = m.end()
        return FieldRef(m.group(0), self._bracket())

    def _check(self, field: FieldRef) -> Check:
        self._skip()
        op = None
        for sym in SYMBOLIC_OPS:
            if self.text.startswith(sym, self.pos):
                op = sym
                self.pos += len(sym)
                break
        if op is None:
            m = _WORD.match(self.text, self.pos)
            if not m or m.group(0) not in WORD_OPS:
                raise self._error(f"expected an operator after {field}")
            op = m.group(0)
            self.pos = m.end()
        if op == "==":
            op = "="
        if op == "exists":
            return Check(field, op, None)
        if op in LIST_OPS:
            return Check(field, op, self._list())
        self._skip()
        s = self._string()
        if s is not None:
            return Check(field, op, s)
        if self.text.startswith("val(", self.pos):
            self.pos += 4
            ref = self._field_ref()
            self._expect(")")
            return Check(field, op, ref)
        m = _BARE_VALUE.match(self.text, self.pos)
        if not m:
            raise self._error(f"expected a value after {field} {op}")
        self.pos = m.end()
        return Check(field, op, m.group(0))

    def _list(self) -> Tuple[str, ...]:
        self._skip()
        items = []
        if not self._peek("("):
            # `x in some_list` without parentheses: one bare item
            m = _BARE_ITEM.match(self.text, self.pos)
            if not m:
                raise self._error("expected a list")
            self.pos = m.end()
            return tuple(self._expand(m.group(0)))
        self.pos += 1
        while True:
            self._skip()
            if self._peek(")"):
                self.pos += 1
                return tuple(items)
            s = self._string()
            if s is not None:
                items.append(s)
            else:
                m = _BARE_ITEM.match(self.text, self.pos)
                if not m:
                    raise self._error("expected a list item")
                self.pos = m.end()
                items.extend(self._expand(m.group(0)))
            self._skip()
            if self._peek(","):
                self.pos += 1

    def _expand(self, item: str, depth: int = 0) -> list:
        if item not in self.lists:
            return [item]
        if depth > 32:
            raise ConditionError(f"list {item!r} nests too deeply")
        out = []
        for sub in self.lists[item]:
            sub = str(sub)
            # Falco expands a list as text, so an item written `'"10.0.0.0/8"'`
            # in YAML arrives as a quoted string literal, quotes and all.
            if len(sub) >= 2 and sub[0] == sub[-1] and sub[0] in "\"'":
                out.append(_Parser(sub, {})._string())
            elif sub in self.lists:
                out.extend(self._expand(sub, depth + 1))
            else:
                out.append(sub)
        return out


def parse(text: str, lists: Optional[Dict[str, list]] = None) -> Node:
    return _Parser(text, lists or {}).parse()


# --- static analysis ----------------------------------------------------------

def event_types(node: Node, macros: Dict[str, Node], _depth: int = 0) -> Optional[FrozenSet[str]]:
    """The event types a condition can match, or None for any.

    Falco indexes rules the same way, and warns about a rule with no
    `evt.type` restriction because it runs on every event.
    """
    if _depth > 64:
        raise ConditionError("macros nest too deeply")
    if isinstance(node, Check):
        if node.field.name == "evt.type" and node.field.transformer is None:
            if node.op == "=" and isinstance(node.value, str):
                return frozenset({node.value})
            if node.op == "in" and isinstance(node.value, tuple):
                return frozenset(node.value)
        return None
    if isinstance(node, MacroRef):
        return event_types(macros[node.name], macros, _depth + 1)
    if isinstance(node, Not):
        return None
    if isinstance(node, And):
        result = None
        for item in node.items:
            t = event_types(item, macros, _depth + 1)
            if t is not None:
                result = t if result is None else result & t
        return result
    if isinstance(node, Or):
        result = frozenset()
        for item in node.items:
            t = event_types(item, macros, _depth + 1)
            if t is None:
                return None
            result |= t
        return result
    raise TypeError(node)


def fields_used(node: Node, macros: Dict[str, Node], out: Optional[Set[str]] = None,
                _depth: int = 0) -> Set[str]:
    out = set() if out is None else out
    if _depth > 64:
        raise ConditionError("macros nest too deeply")
    if isinstance(node, Check):
        out.add(node.field.name)
        if isinstance(node.value, FieldRef):
            out.add(node.value.name)
    elif isinstance(node, MacroRef):
        fields_used(macros[node.name], macros, out, _depth + 1)
    elif isinstance(node, Not):
        fields_used(node.item, macros, out, _depth + 1)
    else:
        for item in node.items:
            fields_used(item, macros, out, _depth + 1)
    return out


# --- compilation --------------------------------------------------------------

# extractor(event) -> value | None | UNKNOWN | Multi
Extractor = Callable[[object], object]
# compiled(event, missing) -> True | False | UNKNOWN, adding the names of the
# fields that were unknown to `missing`
Compiled = Callable[[object, Set[str]], object]

# Longest input a `regex` check is run against: the patterns are ours, the
# strings are the sample's.
REGEX_INPUT_LIMIT = 64 * 1024

try:  # pragma: no cover - depends on what is installed
    import re2 as _regex_engine  # type: ignore
except ImportError:  # pragma: no cover
    _regex_engine = re


def _to_int(s: str) -> Optional[int]:
    try:
        return int(s, 10)
    except ValueError:
        try:
            return int(s, 0)
        except ValueError:
            return None


_IP = (ipaddress.IPv4Address, ipaddress.IPv6Address)


def _network(s: str):
    """`10.0.0.0/8` or a single address, as the network an IP field is
    compared against: Falco's `fd.snet = "10.0.0.0/8"` is containment."""
    try:
        return ipaddress.ip_network(s, strict=False)
    except ValueError:
        return None


def _apply_transformer(name: Optional[str], v):
    if name is None or v is None or v is UNKNOWN:
        return v
    if isinstance(v, Multi):
        return Multi((_apply_transformer(name, x) for x in v.values), v.complete)
    s = v if isinstance(v, str) else str(v)
    if name == "tolower":
        return s.lower()
    if name == "toupper":
        return s.upper()
    if name == "basename":
        return s.rsplit("/", 1)[-1]
    if name == "len":
        return len(s)
    if name == "b64":
        import base64
        import binascii
        try:
            return base64.b64decode(s, validate=False).decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            return None
    raise ConditionError(f"unknown transformer {name}")


def _scalar_test(op: str, value) -> Callable[[object], bool]:
    """A predicate on one extracted value, for a constant right-hand side."""
    if op in ("=", "!="):
        r = value
        r_int = _to_int(r)
        r_low = r.lower()
        r_net = _network(r)

        def eq(v) -> bool:
            if isinstance(v, _IP):
                return r_net is not None and v in r_net
            if isinstance(v, bool):
                return r_low in ("true", "false") and v == (r_low == "true")
            if isinstance(v, int):
                return v == r_int if r_int is not None else str(v) == r
            return v == r if isinstance(v, str) else str(v) == r

        return eq if op == "=" else (lambda v: not eq(v))
    if op in ("<", "<=", ">", ">="):
        r_num = _to_int(value)
        if r_num is None:
            try:
                r_num = float(value)
            except ValueError:
                raise ConditionError(f"{op} needs a number, got {value!r}")
        cmp = {"<": lambda a: a < r_num, "<=": lambda a: a <= r_num,
               ">": lambda a: a > r_num, ">=": lambda a: a >= r_num}[op]

        def num(v) -> bool:
            if isinstance(v, bool):
                return False
            if not isinstance(v, (int, float)):
                v = _to_int(str(v))
                if v is None:
                    return False
            return cmp(v)
        return num
    if op == "contains":
        def contains(v) -> bool:
            return value in (v if isinstance(v, str) else str(v))
        contains.op, contains.needle = op, value
        return contains
    if op == "icontains":
        low = value.lower()

        def icontains(v) -> bool:
            return low in (v if isinstance(v, str) else str(v)).lower()
        icontains.op, icontains.needle = op, value
        return icontains
    if op == "startswith":
        return lambda v: (v if isinstance(v, str) else str(v)).startswith(value)
    if op == "endswith":
        return lambda v: (v if isinstance(v, str) else str(v)).endswith(value)
    if op in ("bcontains", "bstartswith"):
        try:
            needle = bytes.fromhex(value)
        except ValueError:
            raise ConditionError(f"{op} needs hex bytes, got {value!r}")

        def as_bytes(v) -> bytes:
            return v if isinstance(v, bytes) else str(v).encode("utf-8", "surrogateescape")
        if op == "bcontains":
            return lambda v: needle in as_bytes(v)
        return lambda v: as_bytes(v).startswith(needle)
    if op in ("glob", "iglob"):
        pattern = re.compile(fnmatch.translate(value.lower() if op == "iglob" else value), re.S)
        if op == "iglob":
            return lambda v: pattern.match(str(v).lower()) is not None
        return lambda v: pattern.match(v if isinstance(v, str) else str(v)) is not None
    if op == "regex":
        try:
            pattern = _regex_engine.compile(value)
        except re.error as exc:
            raise ConditionError(f"bad regex {value!r}: {exc}")
        return lambda v: pattern.search(str(v)[:REGEX_INPUT_LIMIT]) is not None
    if op == "in":
        strs = frozenset(value)
        ints = frozenset(i for i in (_to_int(x) for x in value) if i is not None)
        lows = frozenset(x.lower() for x in value)
        nets = tuple(n for n in (_network(x) for x in value) if n is not None)

        def member(v) -> bool:
            if isinstance(v, _IP):
                return any(v in n for n in nets)
            if isinstance(v, bool):
                return ("true" if v else "false") in lows
            if isinstance(v, int):
                return v in ints or str(v) in strs
            return (v if isinstance(v, str) else str(v)) in strs
        return member
    if op == "pmatch":
        prefixes = tuple(p if p.endswith("/") else p + "/" for p in value)
        exact = frozenset(p.rstrip("/") or "/" for p in value)

        def pmatch(v) -> bool:
            s = v if isinstance(v, str) else str(v)
            return s in exact or s.startswith(prefixes)
        return pmatch
    raise ConditionError(f"operator {op} is not supported")


def _dynamic_test(op: str, rhs_value) -> Optional[Callable[[object], bool]]:
    """A predicate for `field op val(other)`, built per event."""
    if rhs_value is None or rhs_value is UNKNOWN or isinstance(rhs_value, Multi):
        return None
    if op in LIST_OPS:
        return _scalar_test(op, (str(rhs_value),))
    return _scalar_test(op, str(rhs_value))


class Compiler:
    """Compiles parsed conditions against macros and a field resolver."""

    def __init__(self, macros: Dict[str, Node],
                 resolve: Callable[[str, Optional[str]], Extractor]) -> None:
        self.macros = macros
        self.resolve = resolve
        self._macro_cache: Dict[str, Compiled] = {}
        self._in_progress: Set[str] = set()

    def compile(self, node: Node) -> Compiled:
        if isinstance(node, Check):
            return self._check(node)
        if isinstance(node, MacroRef):
            return self._macro(node.name)
        if isinstance(node, Not):
            inner = self.compile(node.item)

            def negate(ev, missing):
                r = inner(ev, missing)
                return r if r is UNKNOWN else not r
            return negate
        if isinstance(node, And):
            parts = tuple(self.compile(i) for i in node.items)

            def conj(ev, missing):
                unknown = False
                for p in parts:
                    r = p(ev, missing)
                    if r is False:
                        return False
                    if r is UNKNOWN:
                        unknown = True
                return UNKNOWN if unknown else True
            return conj
        if isinstance(node, Or):
            parts = tuple(self.compile(i) for i in node.items)

            def disj(ev, missing):
                unknown = False
                for p in parts:
                    r = p(ev, missing)
                    if r is True:
                        return True
                    if r is UNKNOWN:
                        unknown = True
                return UNKNOWN if unknown else False
            return disj
        raise TypeError(node)

    def _macro(self, name: str) -> Compiled:
        if name in self._macro_cache:
            return self._macro_cache[name]
        if name not in self.macros:
            raise ConditionError(f"undefined macro {name!r}")
        if name in self._in_progress:
            raise ConditionError(f"macro {name!r} refers to itself")
        self._in_progress.add(name)
        try:
            fn = self.compile(self.macros[name])
        finally:
            self._in_progress.discard(name)
        self._macro_cache[name] = fn
        return fn

    def _extractor(self, ref: FieldRef) -> Extractor:
        base = self.resolve(ref.name, ref.arg)
        if ref.transformer is None:
            return base
        if ref.transformer not in TRANSFORMERS:
            raise ConditionError(f"unknown transformer {ref.transformer}")
        t = ref.transformer
        return lambda ev: _apply_transformer(t, base(ev))

    def _check(self, node: Check) -> Compiled:
        extract = self._extractor(node.field)
        name = str(node.field)

        if node.op == "exists":
            def exists(ev, missing):
                v = extract(ev)
                if v is UNKNOWN:
                    missing.add(name)
                    return UNKNOWN
                if v is None:
                    return False
                if isinstance(v, Multi):
                    if any(x is not None for x in v.values):
                        return True
                    if v.complete:
                        return False
                    missing.add(name)
                    return UNKNOWN
                return True
            return exists

        if node.op == "intersects":
            wanted = frozenset(node.value)

            def intersects(ev, missing):
                v = extract(ev)
                if v is UNKNOWN:
                    missing.add(name)
                    return UNKNOWN
                if v is None:
                    return False
                if isinstance(v, Multi):
                    have, complete = {str(x) for x in v.values if x is not None}, v.complete
                else:
                    have, complete = set(str(v).split()), True
                if have & wanted:
                    return True
                if complete:
                    return False
                missing.add(name)
                return UNKNOWN
            return intersects

        if isinstance(node.value, FieldRef):
            other = self._extractor(node.value)
            other_name = str(node.value)
            op = node.op

            def against_field(ev, missing):
                v = extract(ev)
                w = other(ev)
                if v is UNKNOWN or w is UNKNOWN:
                    missing.add(name if v is UNKNOWN else other_name)
                    return UNKNOWN
                if v is None or w is None:
                    return False
                test = _dynamic_test(op, w)
                if test is None:
                    return False
                return _test_value(v, test, name, missing)
            return against_field

        test = _scalar_test(node.op, node.value)

        def check(ev, missing):
            v = extract(ev)
            if v is UNKNOWN:
                missing.add(name)
                return UNKNOWN
            if v is None:
                return False
            return _test_value(v, test, name, missing)
        return check


def _test_value(v, test, name: str, missing: Set[str]):
    if isinstance(v, Multi):
        for x in v.values:
            if x is not None and test(x):
                return True
        if v.complete or v.decides(test):
            return False
        missing.add(name)
        return UNKNOWN
    return test(v)