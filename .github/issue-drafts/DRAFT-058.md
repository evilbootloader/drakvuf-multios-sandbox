# DRAFT-058: Guest locale and keyboard layout as an analysis control

**Status:** Drafted 2026-08-25. Not published.
**Area:** core
**OS:** ALL, most valuable on Windows.
**Milestone:** M5
**Priority:** P2
**Depends on:** the golden images; DRAFT-052 for per-job selection.
**Needs Dom0:** **Yes.**

# Objective

Set the guest's keyboard layout, locale and region — and make the choice
per-run, so behaviour that depends on it becomes visible.

# Context

## Why a keyboard layout is a security control

A large family of malware **refuses to run** on machines that look
post-Soviet. The check is usually one of:

- `GetKeyboardLayoutList` / installed input languages
- `GetUserDefaultLangID`, `GetSystemDefaultUILanguage`
- the region setting, or an installed-locale enumeration

Finding a Russian, Ukrainian, Belarusian or Kazakh layout, the sample exits
cleanly. That is not an obscure trick; it is one of the most widely deployed
behaviours in commodity ransomware and loaders.

**Today our guests have one fixed layout and we have never varied it.** So the
project cannot distinguish "this sample does nothing" from "this sample
declines to run on machines like ours" — and those are opposite findings.

## What varying it turns into evidence

With the layout selectable, the same sample run twice becomes an experiment:

| Run | Layout | Result | Reading |
|---|---|---|---|
| A | es-ES | executes, drops payload | normal |
| B | ru-RU | exits immediately | **CIS-exclusion behaviour confirmed** |

That is a finding no single run produces, and it is exactly the kind of
attribution signal analysts care about. It pairs with `cpuidmon` (DRAFT-050),
which catches hypervisor checks the same way: one records the question, this
records the answer changing the outcome.

## The other direction: looking less like a sandbox

`ideas.md` carries "make VMs more user computer like (anti-evasion)". Locale
is part of that surface, alongside `hidsim`'s synthetic activity (DRAFT-055).
A guest with a default en-US layout, no regional settings, and a clock in UTC
looks like a fresh VM — which is itself a tell.

# Dependencies

- **The golden images.** Some of this is baked at build time; some can be set
  per run.
- **DRAFT-052** — per-job selection.
- **DRAFT-054** — screenshots show a locale change took effect.

# Out of scope

- **Full persona simulation** — browser history, documents, recent files.
  Real anti-evasion work, much larger, and its own issue.
- **Timezone-only tricks.** Related and worth having; keep this focused on
  language, layout and region.
- **Deciding which locale is "right".** The point is that it varies.

# PLAN

1. Choose the locale set — small, and justified per entry.
2. Install it into each golden image as a build step, recorded in the
   checklists.
3. Measure whether a preconfig switch is visible to `GetKeyboardLayoutList`
   and `GetUserDefaultLangID`. **The capability rests on this.**
4. Wire selection through DRAFT-052.

# CREATE

## One image with every locale installed, selected at preconfig

**Not one golden image per locale.** The arithmetic rules it out:
`CLONE_LV_SIZE` is 64G for Ubuntu and 32G for Android, and Windows will want
more — multiplying that by a locale set is disk this lab does not have. It
would also multiply roadmap risk #12, which already records that nothing links
a saved state to the golden image it came from.

Instead: **install the locales once, in the golden image; activate one at
preconfig.** Language data is small next to a disk image — a few hundred
megabytes of Windows language packs against tens of gigabytes per extra
image — so this is two orders of magnitude cheaper for the same capability.

| Guest | Installed at build | Activated at preconfig |
|---|---|---|
| Windows | language packs for the chosen set | add/activate the input layout and set the user locale |
| Ubuntu | `locale-gen` the chosen set | `LANG`/`LC_ALL`, and the X keyboard layout |
| Android | locales are built in | the system locale property |

**Install a chosen set, not all ~200.** The ones that earn their place are the
CIS layouts the exclusion checks look for — `ru-RU`, `uk-UA`, `be-BY`,
`kk-KZ` — plus a plausible baseline and one or two others worth testing
against. Every extra pack is image size for a locale nobody selects.

## The one thing that still needs measuring

Not *which mechanism* — that is settled above — but **whether a runtime switch
is visible to the APIs malware reads.**

The distinction that matters: on Windows the **UI language** generally needs a
sign-out to take full effect, while the **keyboard layout list** and **user
locale** can be changed at runtime. `GetKeyboardLayoutList` and
`GetUserDefaultLangID` are the two most commonly checked, and both are in the
second group — so the preconfig approach should work for the checks that
matter, and that claim needs a fixture rather than confidence.

If some enumeration API turns out to need a restart, the answer is to set it
in the image's *default* profile at build time and still switch the layout per
run — not to build more images.

## Selection

`locale` on the job, from a server-side set. Recorded and shown on the report
— a run's locale is part of what the result means, in exactly the way the
input mode and egress mode are.

# TEST

1. **A preconfig change is visible to the APIs malware uses.** A fixture that
   calls `GetKeyboardLayoutList` and `GetUserDefaultLangID` and reports what
   it sees, run after a preconfig locale switch. **This is the test the
   capability rests on** — if these two do not reflect the switch, the
   exclusion behaviour cannot be provoked.
2. **A known CIS-exclusion sample exits under ru-RU and runs under es-ES**,
   with both traces recorded. The capability's whole justification.
3. **The locale is recorded and rendered**, so two reports of the same sample
   are comparable.
4. **Screenshots confirm it** — the UI language or layout indicator visibly
   changes.
5. **Setting a locale does not break staging.** Non-ASCII paths and different
   input methods must not disturb `writefile` or the guest path rules — the
   filename validator's per-OS rules were written against a fixed locale.
6. **The default is unchanged** from today's behaviour when unspecified.

# DEPLOY

Requires a golden-image rebuild per OS, which is the expensive part and the
reason the locale set should be settled first. Roadmap risk #12 applies: a
rebuild invalidates the saved state and the injection PID, and nothing
currently detects that — so this deploys alongside a template re-save and its
recorded checksums, as issue #7 did for Android.

# Acceptance criteria

- [ ] Locales installed once in each golden image; **no per-locale images**.
- [ ] `GetKeyboardLayoutList` and `GetUserDefaultLangID` demonstrably reflect
      a preconfig switch, or the gap is recorded per API.
- [ ] Locale selectable per job from a server-side set, default unchanged.
- [ ] Recorded on the job and shown on the report.
- [ ] A CIS-exclusion sample demonstrably behaves differently under two
      locales.
- [ ] Staging and filename handling unaffected.

# Evidence required

- The enumeration fixture's output under each mechanism, per guest.
- Two traces of one sample under two locales.
- Screenshots showing the change.

# Security considerations

- **This changes what the sample does, deliberately.** Like `hidsim`, it makes
  runs non-comparable unless recorded — and unlike `hidsim` it is invisible in
  the trace, so the record is the only evidence it was set.
- **Setting a CIS locale to observe exclusion means the sample does not
  run**, which is safe. Setting a *non*-CIS locale to make a sample run that
  would otherwise have exited is the opposite: it is deliberately provoking
  detonation. That is the point, and it belongs in DRAFT-022's position
  alongside DRAFT-057's egress mode.
- **Non-ASCII locales touch the filename path.** `jobs.py`'s per-OS validator
  and `$GUEST_STAGING_DIR` were written against one locale; a Cyrillic or CJK
  layout is where an encoding assumption surfaces.
- **Installing language packs enlarges the golden image**, which is the
  surface every clone inherits. Small against a disk image, but it is more
  software present in a machine whose realism is itself an analysis property —
  a guest with fourteen language packs and no documents is its own kind of
  tell.
- **Per-locale golden images were rejected on disk grounds**, and that
  happens to avoid a second problem: roadmap risk #12 records that nothing
  links a saved state to its golden image, and several images per OS would
  multiply exactly that gap.

# Documentation changes

- **New:** the mechanism chosen, with the measurement that chose it.
- **Updated:** `ideas.md`'s keyboard and anti-evasion lines.
- **Updated:** the per-OS checklists — installing the locale set becomes a
  golden-image build step, and the chosen set is recorded there so a rebuilt
  image can be made to match.

# Recovery / rollback

Do not select a locale; guests behave as today.
