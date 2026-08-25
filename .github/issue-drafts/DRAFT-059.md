# DRAFT-059: Archive submission — password-protected archives and multi-file samples

**Status:** Drafted 2026-08-25. Not published.
**Area:** core/platform
**OS:** ALL
**Milestone:** M4
**Priority:** **P1.** Two of the three ways a sample normally arrives do not
work today.
**Depends on:** #36 (admission), #37 (the object), #38 (the submit form).
Blocked in part on `sandboxd` — see "What this needs from the pipeline".
**Needs Dom0:** **Yes**, for the staging half.

# Objective

Accept an archive as a submission: unwrap a password-protected one, and stage
a multi-file sample as a directory with a chosen entry point.

# Context

## Two separate problems that arrive in the same wrapper

**A password-protected archive is how malware is distributed.** VirusTotal,
MalwareBazaar, abuse.ch and every mailing list ship samples as ZIPs encrypted
with `infected` — precisely so a browser, a mail scanner or an antivirus does
not execute or quarantine them in transit. Today, submitting one analyses *the
ZIP*: `detected_type` says "Zip archive data", the guest runs a file it cannot
execute, and the report describes the wrapper rather than the sample.

**A single file is often not a runnable sample.** A binary that needs its DLLs
beside it, an installer with its data files, a script with its modules — stage
only the executable and it fails on a missing dependency. The trace is real,
the failure is real, and both describe our packaging rather than the malware.
That is a false negative wearing the clothes of a result.

This is the asymmetry #37 already half-solved from the other direction: we
*serve* executable artifacts as `infected`-protected ZIPs. Accepting them is
the same convention run backwards.

## Where unpacking happens — settled by two facts about `injector`

Both read from the recorded help in
`docs/runbooks/verify-user-placeholder.md`, not assumed:

```
writefile - push a file (specified by host path -B) to the VM and store it
            on guest path specified by -e
execproc  - Run any process using vfork and execve ( -e for the program,
            -f for args )
[LINUX]   (execproc -> execve(const char *file, const char *argv[], ...))
```

**`writefile` moves one file per invocation.** There is no multi-file form. A
50-file directory therefore means 50 separate VMI injections, each with its
own setup cost and each an independent failure point. Pushing one archive is a
single injection regardless of how many files it holds.

So the split is:

- **The platform LISTS the archive.** Reading a ZIP central directory is not
  decompressing it — it is cheap, bounded, and does not run the code path
  where bombs live. This is what makes entry-point selection and the per-OS
  filename validation possible *before* anything is staged.
- **The guest EXTRACTS it.** Decompression is the dangerous half, and the
  guest is the disposable machine that exists to absorb dangerous halves. A
  bomb there costs one clone.

An earlier draft of this issue had the platform extract as well as list. That
put a hostile decompressor on the one host holding every credential, to save
an unpacker in the guest — the wrong side of that trade.

**`execproc` takes an argv vector**, which is what makes the entry point and
any user-supplied command safe: each `-f` becomes one `argv` element that
nothing re-parses. `preconfig-android.sh` already relies on this for
`pm install`.

## Staging, in preconfig

```text
push   archive          →  one writefile injection
extract in guest        →  execproc, argv, password as its own element
delete archive          →  before execution, deliberately
execute entry point     →  execproc with the chosen argv
```

**The archive is deleted before the sample runs.** Not tidiness: a sample that
can find its own wrapper can read it, re-extract it, or behave differently
because it is there. The guest should look like a machine the sample arrived
on, not like a machine it was delivered to.

## What this needs from the pipeline

Extraction and multi-file staging both need a step the current callback
contract has no room for: `preconfig-*.sh` performs a fixed sequence and
`drakvuf-*.sh` executes one path built by a fixed rule.

**This lands with `sandboxd` (DRAFT-060), not before.** But the two halves
separate cleanly:

- **A password-protected archive holding ONE file needs no pipeline change at
  all.** The platform lists it, and — this being the only case where the
  platform must decompress — extracts that single member under bound, so what
  reaches the worker is one file exactly as today. This is the common case by
  a wide margin and is buildable now.
- **Multi-file archives wait for `sandboxd`**, which is also where the entry
  point and any run command become argv rather than a string.

Ship the first half. Do not let the second hold it.

# Dependencies

- **#36** — admission, which gains the unwrap step.
- **#37** — the object; the unwrapped sample becomes a second object.
- **#38** — the submit form gains a password field and an entry-point choice.
- **DRAFT-048** — shares the bounded archive reader.
- **DRAFT-060 (`sandboxd`)** — for in-guest extraction, multi-file
  staging, entry points and run commands. The single-file half needs
  none of it.

# Out of scope

- **Nested archives beyond one level.** A ZIP in a ZIP is admitted as a single
  file for a human to decide about. Recursive auto-unwrap is how a submission
  pipeline becomes a decompression bomb with a queue in front of it.
- **Archive formats beyond ZIP, 7z, RAR, tar/gz.** Enough to cover how samples
  actually arrive.
- **Recovering the password.** If it is wrong the submission is refused.
- **Analysing the archive itself as the sample.** If someone genuinely wants
  the ZIP analysed, that is a deliberate choice the form must offer, not the
  default.

# PLAN

1. Bounded unpacker, shared with DRAFT-048.
2. Admission unwraps and re-runs the existing checks on the *contents*.
3. Submit form: password, and entry point when there is more than one file.
4. Directory staging — deferred to `sandboxd`.

# CREATE

## Admission, extended

```text
uploaded object
      ↓
libmagic  →  not an archive  →  today's path, unchanged
      ↓ archive
try password (submitted, else `infected`, else none)
      ↓
list entries, bounded          ← shared with DRAFT-048
      ↓
one file        →  unwrap, admit the CONTENT as the sample
many files      →  admit as a directory sample, entry point required
```

**`infected` is tried automatically.** It is the universal convention and
requiring the operator to type it every time is friction with no benefit — but
it is tried *after* any supplied password, so an archive genuinely protected
with `infected` and one protected with something else both work.

## What the sample becomes

The unwrapped content is written as its own object and the job's
`sha256`/`size_bytes`/`detected_type` describe **the content, not the
wrapper**. The archive is retained as an artifact — it is what was submitted,
and DRAFT-030's reasoning applies to it as much as to a filename.

The submitted filename rules (`jobs.py:_reject_unsafe_filename`) apply to the
**entry name inside the archive**, per target OS. An archive is an excellent
way to smuggle a name a direct submission would refuse: `../../etc/passwd`,
`CON`, `payload.exe:ads`. Same validator, same boundary.

## Password handling

- Never logged, never in a URL, never in the job row.
- Carried in the JSON body of `POST /api/v1/jobs`, over TLS.
- Held only long enough to unwrap. It is not a secret worth storing — it is
  almost always `infected` — but writing it into a database is the kind of
  thing nobody intends and everybody regrets.
- **It must never reach a guest shell.** If directory staging later unpacks
  in-guest, the `sh -c '…' sh "$1"` idiom from `preconfig-android.sh` is the
  minimum, and a password containing `"` or `$` is precisely the case that
  breaks a naive implementation.

## The submit form

A password field, shown only when the picked file looks like an archive — the
browser knows the extension before upload, so this needs no round trip. Then,
if the archive holds more than one file, the entry point is chosen from a
listing after upload, before admission completes.

# TEST

1. **A `infected`-protected ZIP holding one PE is admitted as that PE** —
   `detected_type` is the PE's, not "Zip archive data".
2. **A supplied password is preferred over `infected`**, and a wrong password
   is a clear refusal naming the reason.
3. **A zip bomb is refused**, by depth and by expansion ratio, and the refusal
   is recorded rather than the container falling over.
4. **Path traversal in an entry name is refused** — `../../etc/passwd`,
   absolute paths, and the Windows cases (`CON`, `a:b`) when the target is
   Windows. Same validator as a direct submission.
5. **A symlink entry is refused.** A ZIP can carry one, and unpacking it can
   write outside the destination — the hazard `unzip` has shipped CVEs for.
6. **An archive with two files demands an entry point** rather than guessing.
7. **The archive is retained** as an artifact alongside the extracted sample.
8. **A password is absent from every log line and from the job row**, asserted
   by searching both.
9. **A non-archive submission is completely unaffected** — the existing path
   runs unchanged, proven by the existing tests still passing untouched.

# DEPLOY

Platform-side only for the first half; no Dom0 change, no pipeline change.
Directory staging deploys with `sandboxd`.

# Acceptance criteria

- [ ] A password-protected ZIP from MalwareBazaar or VirusTotal is admitted as
      its contents, end to end.
- [ ] `infected` tried automatically, after any supplied password.
- [ ] Unpacking is bounded in depth, ratio, entry count and total bytes, in a
      separate process, sharing DRAFT-048's reader.
- [ ] Traversal, absolute paths, symlinks and per-OS-illegal names refused —
      by the same validator direct submission uses.
- [ ] The password never reaches a log, a URL or the database.
- [ ] The archive is retained as an artifact; the sample is its content.
- [ ] Multi-file archives require an explicit entry point.
- [ ] Directory staging is deferred and recorded as blocked on `sandboxd`.

# Evidence required

- A real password-protected sample from a public feed, submitted and admitted,
  with the resulting `detected_type`.
- Zip bomb, traversal and symlink refusals as transcripts.
- A log and database search showing no password.
- The existing test suite unchanged and passing.

# Security considerations

- **This adds an attacker-controlled parser to the credential-holding host**,
  which is the same objection DRAFT-048 carries and for the same component.
  They should share the bound as well as the reader.
- **Zip bombs are the cheapest attack in this issue.** 42 KB expanding to
  petabytes, and a submission endpoint is exactly where one gets pointed.
  Depth, ratio, entry count and total bytes all bounded, not just one.
- **Symlink and traversal entries write outside the destination.** `unzip` has
  a CVE history here; using a library does not make it go away, because the
  library will happily create what the archive describes unless told not to.
- **Auto-trying `infected` is a small ergonomic risk.** An archive whose real
  password happens to be `infected` but whose contents the submitter did not
  intend to detonate is unwrapped and run. The form must show what was
  extracted before the job is queued.
- **The password is low-value but high-embarrassment.** It is almost always
  `infected`; the failure mode is not disclosure but an operator later finding
  a real password in a log they shared.
- **Directory staging widens what reaches the guest.** Today one file is
  written to a known path. A directory means many writes and a working
  directory the sample controls the contents of — worth its own review when
  `sandboxd` gets there, not a detail of this issue.

# Documentation changes

- **New:** how archive submission works, the bounds, and the entry-point rule.
- **Updated:** `docs/architecture/platform.md` — the sample object is no
  longer necessarily what was uploaded.
- **Updated:** `docs/architecture/result-schema.md` — the archive as a
  retained artifact.
- **Updated:** #38's submit view.

# Recovery / rollback

Disable the unwrap step: archives are admitted as archives again, which is
today's behaviour. Jobs already unwrapped keep both objects and stay valid.