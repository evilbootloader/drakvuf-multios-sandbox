# Licensing research findings

> **This is not legal advice.** It summarizes what license texts say, in
> plain terms, based on research conducted 2026-08-07. Get an actual
> lawyer's read before making commercial/paywall decisions (Milestone M7+
> in `docs/roadmap/project-roadmap.md`). This does not block internal lab
> automation work happening now.

## What DRAKVUF's license text says

This project's own `LICENSE` file (GPLv2 with a custom preamble/exceptions
clause, authored by Tamas K Lengyel) matches the text at
`tklengyel/drakvuf`'s repo root. Key points, near-verbatim:

- It defines "Covered Work"/derivative work broadly, explicitly including
  software that **"is designed specifically to execute Covered Software and
  parse the results"** and software that **"links (statically or
  dynamically) to a library which does any of the above."** This is
  unusually broad — standard GPLv2 doesn't typically reach a mere
  subprocess/"system call" boundary this explicitly; DRAKVUF's authors have
  pre-emptively closed that door in their own text.
- **"Covered Work may not be combined (even as part of a larger work) with
  plain GPL software."** — even a vanilla-GPL orchestration layer combined
  with DRAKVUF is stated to be disallowed under this text without the
  alternative/proprietary license.
- Alternative licenses are explicitly offered "from the author" for anyone
  who needs different terms (contact: tamas.k.lengyel@gmail.com).

## Directly on-point prior art: CERT-Polska's `drakvuf-sandbox`

Its `LICENSE` inherits and reinforces the above: it states the project
**"incorporates DRAKVUF (C) 2014-2023 Tamas K Lengyel which is a separate
project under its own license,"** repeats the "designed specifically to
execute Covered Software and parse the results" language, and adds:
**"If you wish to embed DRAKVUF Sandbox technology into proprietary
software, alternative licenses can be acquired after obtaining the consent
of both authors"** (drakvuf@cert.pl and tamas.k.lengyel@gmail.com).

This is essentially the exact scenario this project's planned web platform
would be in — a service wrapping/orchestrating DRAKVUF — and the people who
built the closest prior art to it explicitly treat that as requiring
separate permission for proprietary/commercial embedding, not something a
loosely-coupled subprocess architecture automatically escapes.

## Plain-terms bottom line (again, not legal advice)

- Static/dynamic linking against DRAKVUF's libraries: squarely "Covered
  Work" per the text — commercial/proprietary use would need a separate
  license from the author.
- Running DRAKVUF as a subprocess and parsing its output (what `dirwatch`
  and this project's automation already do, and what a future web platform
  would do): the license text does **not** carve this out as safe — it
  explicitly names this exact pattern as a derivative work.
- A paywalled/commercial web platform built this way would, per the
  license's own stated interpretation, likely need either (a) to itself be
  released under the same GPLv2+exceptions terms (which would functionally
  prevent keeping it closed-source/paywalled in the conventional sense), or
  (b) a direct commercial license from Tamas K Lengyel (and potentially
  CERT Polska's consent too, if any of their sandbox techniques are
  reused).
- This clause is unusually broad compared to a plain-GPL subprocess
  argument. **Real legal consultation is warranted before committing to a
  commercial architecture** — do not assume a subprocess boundary provides
  the same insulation it might for other GPL projects.

## capa (Mandiant) — no additional friction

Apache License 2.0 — permissive, commercial use allowed, attribution + NOTICE
preservation required. No interaction/incompatibility issue with DRAKVUF's
GPL terms as long as it's run as a genuinely separate process consuming
DRAKVUF's log output (which is how the roadmap's post-processing workstream
plans to use it).

## Gate

This licensing question gates Milestone M7 (web platform) business-model
decisions specifically. It does not gate M0–M6 (internal lab automation,
Ubuntu/Android/Windows pipeline work) — those are not commercial/paywalled
uses.