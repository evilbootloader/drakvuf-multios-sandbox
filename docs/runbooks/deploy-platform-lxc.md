# Runbook — provision the platform LXC on Proxmox (L0)

> **Status: PARTIALLY EXECUTED.** Steps 1–6 ran on 2026-08-22 and steps
> 7–14 on 2026-08-23, after a rollback to `base-install`; both carry real
> output below and are append-only evidence from here on — annotate, never
> rewrite. **Steps 15–22 (the API, issue #36) ran on 2026-08-23**, with steps
> 19a/20a/20b/21b added mid-flight to cover gaps the execution exposed — see
> "Order, and why it is this way".
>
> The worker channel is closed end to end: MinIO serves TLS on the LAN
> address, the API enforces mTLS, and the fake worker registers and claims.
> **Step 20b did not complete** — the browser listener on `8000` never
> started, because the `sed` that derived its unit produced an unparseable
> one. It is rewritten below and has not been re-run.
>
> **Step 23 closes the submission path** — create, upload, admit, claim,
> complete, with the declared-size policy demonstrated as enforced rather
> than recorded.
>
> **Still open after this runbook:** the SSE stream is not yet exercised;
> nothing has been submitted through the tunnel from a browser; abandoned
> jobs in state `created` are never cleaned up (see step 23); and the
> decisions in "What is deliberately not in this runbook".
>
> Container **102** runs Postgres 17 on a **UTF-8** cluster with the #35
> schema applied, reachable only over the Unix socket, holding no password,
> and pulling this repository with a key confirmed read-only.
>
> | Check | Result |
> |---|---|
> | Cluster encoding | **PASS** — `locale "C.UTF-8"` → `encoding ... "UTF8"` |
> | Postgres not on TCP | **PASS** — nothing bound to 5432 |
> | Deploy key is read-only | **PASS** — `the key ... has been marked as read only` |
> | Migrations apply | **PASS** — two `applied` |
> | **Migrations are idempotent** | **PASS** — `up to date` (this failed on 08-22) |
> | The `target_os` enum is closed | **PASS** — `invalid input value for enum target_os` |
> | **Text is `str`, not `bytes`** | **PASS** — `type: str -> 0001_jobs.sql` |
>
> **Findings:**
>
> - **F2 — SQL_ASCII made the migration runner fail silently. CLOSED.** Fixed
>   in the runner, which now refuses such a database (`26803a7`), and in the
>   order of these steps, which create the UTF-8 cluster before any database
>   exists. Both the fix and a regression check are tested.
> - **F1 — the LVM thin pool is oversubscribed 3.5:1 with no protection**, and
>   it is shared with the Xen L1 VM. **OPEN, and not this runbook's to fix.**
>   Tracked on [#37](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/37).
>
> The first attempt's transcripts are preserved in the appendix. Steps 7–14
> above replace them, and the substantive change is one of *order* — the
> cluster is recreated as UTF-8 before any database exists, because a database
> cannot be re-encoded in place and `template1` was SQL_ASCII too.
>
> **Issue:** [#34](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/34)
> (DRAFT-041) decided the shape; [#37](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/37)
> (DRAFT-044) owns MinIO's configuration. This runbook only stands up the
> container they both live in.
>
> **Runs on L0, the Proxmox host.** Not Dom0, not the development container.

---

## What this container is, and what it must never become

It holds Postgres, MinIO and the FastAPI service. **It never executes a
sample** — that asymmetry is the entire reason a container is proportionate
here rather than a VM, and it is why Dom0 dials out to *this* machine and
never the reverse.

Two rules that follow, and both are load-bearing:

- **Unprivileged, always.** An LXC shares L0's kernel, so an escape is a
  Proxmox host compromise rather than a guest one.
- **Nothing here ever runs a downloaded artifact.** Not to "check" a pcap,
  not to test an extracted file. The moment something does, the container's
  security argument is void and it should be a VM.

---

## Inputs needed before step 1

Four values this runbook cannot guess. Fill them in, then the commands below
are copy-paste.

| # | Value | How to find it | Yours |
|---|---|---|---|
| 1 | Proxmox storage pool for the rootfs | `pvesm status` — usually `local-lvm` or `local-zfs` | `________` |
| 2 | Storage pool for the MinIO data volume | Same list. Can be the same pool, but see sizing below | `________` |
| 3 | Bridge and static IP | `ip -br a` on L0; pick an address Dom0 can reach | `vmbr__` / `______/__` |
| 4 | **Measured artifact size per analysis** | On Dom0: `du -sh /malware_finished/*/* \| sort -h \| tail -20` | `________` |

**Input 4 is the one that matters and the one I cannot estimate.** Artifact
volume is dominated by memdumps, and this project has real finished runs to
measure rather than a number to guess at. Run that `du` and the data-volume
sizing below becomes arithmetic instead of a guess.

Also confirm free memory on L0 before choosing `--memory`:

```bash
free -m                  # on L0
               total        used        free      shared  buff/cache   available
Mem:           31924       17395       13557         162        1521       14529
Swap:           8191           0        8191
pct list; qm list        # what is already allocated
      VMID NAME                 STATUS     MEM(MB)    BOOTDISK(GB) PID       
       101 drakvuf              running    20480           1024.00 1996      
       153 phoenix              stopped    1024               9.32 0         
       191 flare-vm             stopped    8192             100.00 0         
       192 remnux               stopped    4096             100.00 0         
       199 builder              stopped    24576            512.00 0 
```

The Xen L1 VM holds the clone pool and is the large consumer. **An LXC's
`--memory` is a cgroup cap, not a reservation** — unlike a VM's, it is not
taken from the host until it is used, so being slightly generous costs
nothing until something actually grows into it.

---

## Sizing, with the reasoning

| Resource | Value | Why |
|---|---|---|
| `--cores` | 2 | Postgres and MinIO are both idle-heavy here. The one CPU-bound operation is SHA-256 over an uploaded sample, which is single-threaded and infrequent |
| `--memory` | 4096 | Postgres shared buffers + MinIO + a Python service. 2048 works; 4096 leaves room for Postgres to cache the jobs table entirely, which it will, because the table is small |
| `--swap` | 512 | Small deliberately — swapping Postgres is worse than failing |
| `--rootfs` | 16G | OS, Postgres data, application. Postgres here stores kilobyte rows, thousands of them, not millions |
| `mp0` (MinIO) | **see below** | The whole storage question |

### The data volume

**Do not put MinIO on the rootfs.** A 16G rootfs and multi-gigabyte memdumps
fill silently, and the failure surfaces as an artifact upload failing at the
*end* of a run that otherwise worked — the most expensive possible place to
fail, because the analysis is already spent.

Size it from input 4:

```
data volume  =  (measured artifact size per run)
             ×  (runs per day)
             ×  (retention days)
             ×  1.3            # headroom; MinIO is not a thin filesystem
```

Retention is still an **open decision** (DRAFT-041, and it interacts with
DRAFT-022's GDPR position — pcaps carry third-party traffic). Until it is
made, size for what you can spare and set a monitoring threshold rather than
picking a retention period by implication.

---

## Step 1 — fetch a container template

Debian 13 recommended over Ubuntu: smaller, and nothing here needs Ubuntu's
packaging.

```bash
# on L0
pveam update
pveam available --section system | grep -E 'debian-13'
pveam download <storage> debian-13-standard_13.x-x_amd64.tar.zst
```

## Step 2 — create the container

Replace the four bracketed values from the inputs table.

```bash
# on L0
pct create 102 local:vztmpl/debian-13-standard_13.x-x_amd64.tar.zst \
    --hostname   platform \
    --unprivileged 1 \
    --features   nesting=1 \
    --cores      2 \
    --memory     4096 \
    --swap       512 \
    --rootfs     local-lvm:16 \
    --mp0        local-lvm:256,mp=/srv/minio \
    --net0       name=eth0,bridge=vmbr0,ip=192.168.1.10/24,gw=192.168.1.1 \
    --onboot     1 \
    --start      1
```

Notes on the choices, since several are deliberate rather than default:

- `--unprivileged 1` — non-negotiable, see the rules at the top. This is the
  boundary that matters: the container's root is not the host's root, and
  everything below is a secondary consideration next to it.
- `--features nesting=1` — enabled, and the reasoning is worth reading
  because an earlier draft of this runbook said `nesting=0` and was wrong on
  both counts.

  It does not only mean "run containers inside". It relaxes the restrictions
  on mounting the API filesystems (`/proc`, `/sys`, the cgroup hierarchy)
  inside a nested user namespace — which **systemd needs in order to manage
  services**. Debian 13 is systemd-based and `systemctl enable --now
  postgresql` in step 3 depends on it, as will the API unit later. Proxmox
  enables it by default on unprivileged containers for exactly this reason.
  So the claim that it "buys nothing" was simply false.

  The cost is real but bounded, and the bound is the unprivileged flag above.
  Nesting widens what the container may mount; it does **not** undo the uid
  mapping, so container-root is still an unprivileged host user. The
  genuinely dangerous combination is nesting on a *privileged* container,
  which this is not, and must never become.

  **If it turns out nothing here needs it**, turning it off costs nothing —
  verify by setting `nesting=0`, restarting, and confirming `systemctl status
  postgresql` still reports active. Left on because it is the working
  configuration and the smaller of the two risks is an unverified feature
  flag, not a service that fails to start after a reboot nobody is watching.
- **Static IP, not DHCP.** Dom0 needs a stable target for the mTLS trust
  anchor and for the Proxmox firewall rule that constrains it. A lease
  change would break both in a way that reads as a network fault.
- `--onboot 1` — the queue should survive an L0 reboot without an operator.

## Step 3 — base packages

```bash
pct exec 102 -- bash -lc '
  apt-get update
  apt-get install -y postgresql postgresql-contrib python3 python3-venv \
                     python3-pip ca-certificates curl gnupg
  systemctl enable --now postgresql
  psql --version
'

psql (PostgreSQL) 17.11 (Debian 17.11-0+deb13u1)
```

Postgres 15+ is required — `FOR UPDATE SKIP LOCKED` is much older than that,
but `gen_random_uuid()` without the `pgcrypto` extension needs 13+, and the
migration in #35 assumes it.

## Step 4 — MinIO, on its own volume

```bash
pct exec 102 -- bash -lc '
  curl -fsSLo /usr/local/bin/minio https://dl.min.io/server/minio/release/linux-amd64/minio
  chmod +x /usr/local/bin/minio
  useradd -r -s /usr/sbin/nologin minio-user || true
  install -d -o minio-user -g minio-user /srv/minio
  df -h /srv/minio          # confirm this is the mp0 volume, NOT the rootfs
'

# We need to change default credentials for minio

Filesystem                        Size  Used Avail Use% Mounted on
/dev/mapper/pve-vm--102--disk--1  251G  2.1M  239G   1% /srv/minio
```

**Check that `df -h /srv/minio` shows the data volume and not the rootfs
before going further.** If `mp0` failed to attach, MinIO will happily write
to the rootfs and the first sign will be a full container.

Bucket, policy, service account and CORS are **not** here — they belong to
[#37](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/37),
which also decides the presigned-URL TTLs and the deliberately absent
`DeleteObject` capability.

## Step 5 — network reachability, both directions

The design requires an asymmetry, and this is where to confirm it rather
than assume it:

```bash
# from Dom0 — must SUCCEED once the API is up
user@personal:~$ curl -sv https://192.168.1.10:9000/healthz
*   Trying 192.168.1.10:9000...
* ALPN: curl offers h2,http/1.1
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
*  CAfile: /etc/ssl/certs/ca-certificates.crt
*  CApath: /etc/ssl/certs
* TLS connect error: error:0A00010B:SSL routines::wrong version number
* closing connection #0

# from the platform container — must FAIL
pct exec 102 -- bash -lc 'curl -m 5 -sv https://<dom0-ip>/ ; echo "exit=$?"'
*   Trying 192.168.1.139:443...
* Connection timed out after 5002 milliseconds
* closing connection #0
exit=28
```

The second is the important one. **Dom0 has no inbound listener and the
platform must never acquire a route to it.** Right now that is true because
nothing listens; it becomes *enforced* when the Proxmox firewall rules land.

Also confirm the platform cannot reach the Proxmox internal management
network — the second of the two prerequisites recorded in
`docs/architecture/platform.md`.

## Step 6 — snapshot before anything else

```bash
pct snapshot 102 base-install --description 'Debian 13 + postgres + minio binary, before any config'
```

Cheap snapshots are most of why this is a container. Take one here, and
another before every subsequent change.

---

# Deploying the database — issue [#35](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/35)

Steps 7–14.

> **Rewritten 2026-08-23.** The first attempt ran on 2026-08-22, created the
> database under the cluster's default `SQL_ASCII` encoding, and the migration
> runner then silently re-applied every migration on every run — see **F2**.
> The container was rolled back to the `base-install` snapshot and these steps
> replace the originals, which are preserved in the appendix.
>
> **The order changed, and that is the substance of the fix.** Encoding is
> fixed *before* any database exists, because a database cannot be re-encoded
> in place and `template1` on this cluster is SQL_ASCII too.

**Nothing here holds a password.** Postgres and the API run in the *same*
container, so the API reaches the database over the Unix socket with peer
authentication as its own OS user. A TCP password connection would mean
storing a credential in a config file for a hop that never leaves the
container — a secret to leak, rotate and forget, buying nothing.

## Step 7 — recreate the Postgres cluster as UTF-8

**Do this first, on a freshly restored `base-install`, before any database
exists.**

The Debian container has no UTF-8 locale, so the `initdb` that ran during
package installation chose `SQL_ASCII` — and every database created on the
cluster inherits it, `template1` included. `SQL_ASCII` is not an encoding; it
is the *absence* of one. Postgres stores and returns raw bytes with no
validation or conversion, and psycopg consequently hands back `bytes` rather
than `str` for every text column. F2 is what that cost.

### 7a — make the inherited locale valid, first

**`pct exec` injects the Proxmox host's `LANG` into the container**, and this
container does not have `en_US.UTF-8` generated. Every command then emits a
wall of perl warnings, which is cosmetic — except for `pg_createcluster`,
which **validates the ambient `LANG` before it looks at `--locale` at all**
and refuses outright:

```
Error: The locale requested by the environment is invalid:
  LANG: en_US.UTF-8
```

Generate it once. This does **not** change what the cluster uses — that still
comes from `--locale` below — it only makes the variable the host keeps
injecting resolvable:

```bash
root@pve1:~# pct exec 102 -- env -u LANG bash -lc '
  sed -i "s/^# *en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/" /etc/locale.gen
  locale-gen
  locale -a | grep -iE "en_US|C\.utf8"
'
Generating locales (this might take a while)...
  en_US.UTF-8... done
Generation complete.
en_US.utf8
```

`env -u LANG` is needed for this one command, because it is the command that
fixes the reason `LANG` is broken. Everything after it runs clean.

### 7b — recreate the cluster

```bash
root@pve1:~# pct exec 102 -- bash -lc 'pg_createcluster 17 main --locale=C.UTF-8 --start'
Creating new PostgreSQL cluster 17/main ...
/usr/lib/postgresql/17/bin/initdb -D /var/lib/postgresql/17/main --auth-local peer --auth-host scram-sha-256 --no-instructions --locale C.UTF-8
The database cluster will be initialized with locale "C.UTF-8".
The default database encoding has accordingly been set to "UTF8".
The default text search configuration will be set to "english".
...
Ver Cluster Port Status Owner    Data directory              Log file
17  main    5432 online postgres /var/lib/postgresql/17/main /var/log/postgresql/postgresql-17-main.log
```

Those two lines — `locale "C.UTF-8"` and `encoding ... set to "UTF8"` — are
the whole point of this step. F2 happened because they previously read
`SQL_ASCII`.

`pg_dropcluster` was **not** run: `pg_lsclusters` printed only its header, so
there was nothing to drop (see the note above).

**If `pg_lsclusters` prints only its header, there is no cluster to drop** and
`pg_dropcluster` will say so. That is fine — skip it and run
`pg_createcluster` alone. Observed after restoring `base-install` on
2026-08-23: the snapshot restored the packages but no cluster, so
`/etc/postgresql/` was empty.

**`pg_dropcluster` destroys every database on the cluster.** That is safe
here and only here: `base-install` predates any database. Running this later
is data loss.

**Why `C.UTF-8` rather than `en_US.UTF-8`:** it is built into glibc, so no
`locale-gen` step and no dependency on which locales the image happens to
carry. It gives UTF-8 encoding with deterministic byte-order collation, which
is what this database wants — it sorts filenames and hex digests, not natural
language — and it sidesteps the collation-version churn that glibc upgrades
inflict on locale-aware indexes.

Verify before continuing; everything downstream assumes it:

```bash
pct exec 102 -- su - postgres -c "psql -tAc \"
  SELECT pg_encoding_to_char(encoding), datcollate FROM pg_database WHERE datname='template1'\""
# expect: UTF8|C.UTF-8   -- NOT SQL_ASCII
```

## Step 8 — confirm Postgres is local-only

```bash
root@pve1:~# pct exec 102 -- bash -lc "
  su - postgres -c \"psql -tAc 'SHOW listen_addresses'\"
  ss -lntp | grep 5432 || echo 'not listening on TCP -- correct'
"

not listening on TCP -- correct
```

**Observed 2026-08-23: already empty on a freshly created cluster**, so this
step was a no-op. `SHOW listen_addresses` returned the blank line above and
nothing was bound. That is not what the paragraph below predicted, and the
discrepancy is recorded rather than reconciled — the setting was verified
correct either way, and chasing why `pg_createcluster` produced it is not
worth a deploy. **Do not skip the check on that basis**: verify, and set it
if the answer differs.

Debian's documented default is `localhost`, which still opens TCP listeners on
`127.0.0.1:5432` and `[::1]:5432` — reachable by anything else running in the
container, including MinIO or a future service nobody has thought about yet.

Set `listen_addresses = ''` in `/etc/postgresql/17/main/postgresql.conf` and
restart. **No TCP listener at all**, Unix socket only, which is what the
peer-authentication design assumes:

```bash
pct exec 102 -- bash -lc "
  sed -i \"s/^#*listen_addresses.*/listen_addresses = ''/\" /etc/postgresql/17/main/postgresql.conf
  systemctl restart postgresql
  ss -lntp | grep 5432 || echo 'not listening on TCP -- correct'
"
```

If a later component genuinely needs TCP, that is a decision to take
deliberately — not something left open because a default was permissive.

## Step 9 — the application role and database

```bash
pct exec 102 -- bash -lc "
  useradd -r -m -s /usr/sbin/nologin platform || true
  su - postgres -c 'createuser platform'
  su - postgres -c 'createdb -O platform -E UTF8 -T template0 sandbox_platform'
  su - platform -s /bin/bash -c 'psql -d sandbox_platform -tAc \"select current_user\"'
"
```

`-E UTF8 -T template0` is belt and braces: step 7 already made the cluster
UTF-8, so `template1` would serve — but stating the encoding explicitly means
this command is correct even on a cluster where step 7 was skipped, and it is
the line whose absence caused F2.

The OS user and the database role share a name deliberately — that is what
makes peer authentication work with no configuration and no password.

**`platform` is not a superuser.** It owns its own database and nothing else,
so a flaw in the API cannot reach the rest of the cluster. The migration
runner needs only `CREATE` inside that database, which ownership grants.

Verify the encoding actually landed:

```bash
root@pve1:~# pct exec 102 -- su - postgres -c "psql -tAc \"
  SELECT pg_encoding_to_char(encoding) FROM pg_database WHERE datname='sandbox_platform'\""
UTF8
```

The runner refuses to run against `SQL_ASCII` as of #35, so a mistake here now
fails loudly rather than silently re-applying migrations — but checking costs
one command and reading the error costs a deploy.

## Step 10 — a read-only deploy key

The container needs to pull this repository, the way Dom0 does. It gets its
**own** key, and that key is **read-only**.

**Why read-only is a containment decision, not tidiness.** Dom0 pulls its
worker scripts from this same repository. A platform key with write access
would mean that compromising the platform lets an attacker push to the
repository Dom0 then pulls and executes — turning a web-tier compromise into
code execution on the machine that runs malware.

**Why its own key, not Dom0's.** Either host can be revoked without breaking
the other, and a key found on the platform proves nothing about Dom0.

If the snapshot restore predates the original key, regenerate it and replace
the deploy key on GitHub; otherwise the existing one still works.

```bash
pct exec 102 -- su - platform -s /bin/bash -c '
  mkdir -p ~/.ssh && chmod 700 ~/.ssh
  ssh-keygen -t ed25519 -N "" -C "platform-lxc-102 (read-only)" -f ~/.ssh/id_ed25519
  ssh-keyscan github.com >> ~/.ssh/known_hosts
  cat ~/.ssh/id_ed25519.pub
'
```

`ssh-keyscan` pins GitHub's host key now rather than reaching for
`StrictHostKeyChecking=no` at clone time — that flag accepts any host that
answers, which on a first connection is exactly when it matters.

Register the printed key at **Settings → Deploy keys → Add deploy key**, or:

```bash
gh repo deploy-key add /path/to/id_ed25519.pub --title "platform-lxc-102 (read-only)"
```

**Leave "Allow write access" unchecked.** That box is the whole of the
decision above.

Verification comes after step 11, because it needs a checkout — and note that
`ssh -T git@github.com` does **not** distinguish read from write: GitHub
returns the same "successfully authenticated" line either way. Only an
attempted push tells you.

## Step 11 — deploy the code

```bash
pct exec 102 -- bash -lc "
  apt-get install -y git
  install -d -o platform -g platform /opt/platform
"
pct exec 102 -- su - platform -s /bin/bash -c '
  git clone git@github.com:evilbootloader/drakvuf-multios-sandbox.git \
      /opt/platform/src \
    || git -C /opt/platform/src pull --ff-only
  cd /opt/platform/src/platform
  python3 -m venv .venv
  .venv/bin/pip install -r requirements.txt
'
```

Now confirm the key cannot write:

```bash
root@pve1:~# pct exec 102 -- su - platform -s /bin/bash -c '
  cd /opt/platform/src && git push --dry-run origin HEAD 2>&1 | tail -5
'
ERROR: The key you are authenticating with has been marked as read only.
fatal: Could not read from remote repository.
```

**PASS, and note how much better this is than `ssh -T`.** GitHub names the
reason explicitly. `ssh -T` returns the same "successfully authenticated" line
for a writable key, which is why it was replaced as the check.

Same rule as Dom0's checkout: **do not edit deployed files in place.** Change
them in the repository, push, pull here. That is the drift issue #2 needed a
whole runbook to diagnose, and a database makes it worse — an edited migration
that has already been applied cannot be un-applied by editing it. `--ff-only`
so a local edit someone made anyway causes a visible refusal rather than a
silent merge.

## Step 12 — apply the migrations

```bash
root@pve1:~# pct exec 102 -- su - platform -s /bin/bash -c '
  cd /opt/platform/src/platform
  export DATABASE_URL="postgresql:///sandbox_platform"
  .venv/bin/python migrations/run.py --status
  .venv/bin/python migrations/run.py
  .venv/bin/python migrations/run.py
'
 pending  0001_jobs.sql
 pending  0002_triggers.sql
applied  0001_jobs.sql
applied  0002_triggers.sql
up to date
```

**`up to date` is F2 closed.** On 2026-08-22 this same third invocation
re-applied `0001` and died on `DuplicateObject`.

Expect, in order: two `pending` lines, two `applied` lines, then **`up to
date`**.

**The third invocation is not redundant — it is the test.** Every future
deploy re-runs this command against an already-migrated database, so if it is
not a no-op then the second deploy is where that gets discovered. This is
exactly what failed on 2026-08-22 (F2), and it failed by re-applying the
schema rather than by erroring.

The empty host in `postgresql:///sandbox_platform` is what selects the Unix
socket. `postgresql://localhost/...` would go over TCP and fail, because step
8 removed the listener.

## Step 13 — verify the schema landed

```bash
pct exec 102 -- su - platform -s /bin/bash -c '
  psql -d sandbox_platform -c "\dt"
  psql -d sandbox_platform -c "\d jobs" | tail -20
  psql -d sandbox_platform -tAc "SELECT filename FROM schema_migrations ORDER BY filename"
'
```

Four tables — `jobs`, `workers`, `worker_pipelines`, `schema_migrations` —
five indexes on `jobs` including the two partial ones, and both triggers
attached.

Two checks by hand, because each is a property the schema *enforces* rather
than documents. Both use a heredoc so the SQL never passes through another
layer of shell quoting — the original used escaped double quotes, which SQL
reads as an **identifier**, so psql never reached the enum and failed with a
misleading "column does not exist".

```bash
# 1. the OS enum is closed (issue #3)
pct exec 102 -- su - platform -s /bin/bash -c "psql -d sandbox_platform <<'SQL'
INSERT INTO jobs (target_os, submitted_filename) VALUES ('linux', 'x');
SQL"
# PASS 2026-08-23:
# ERROR:  invalid input value for enum target_os: "linux"
# LINE 1: ...INTO jobs (target_os, submitted_filename) VALUES ('linux', '...

# 2. text really is text now, not bytes (F2)
pct exec 102 -- su - platform -s /bin/bash -c "cd /opt/platform/src/platform && .venv/bin/python <<'PY'
import psycopg
c = psycopg.connect('postgresql:///sandbox_platform')
row = c.execute('select filename from schema_migrations limit 1').fetchone()
print('type:', type(row[0]).__name__, '->', row[0])
assert isinstance(row[0], str), 'still bytes -- database is not UTF8'
print('OK')
PY"
# PASS 2026-08-23:
# type: str -> 0001_jobs.sql
# OK
```

Check 2 is the one that would have caught F2 on day one. If it prints
`bytes`, stop: the database is still SQL_ASCII and every text column in the
system will behave this way.

## Step 14 — snapshot

```bash
root@pve1:~# pct snapshot 102 schema-applied --description 'UTF-8 cluster, jobs schema at 0002'
snapshot name 'schema-applied' already used
```

**The name collided with the snapshot taken during the first attempt**, which
survived the rollback to `base-install` — restoring an earlier snapshot does
not remove later ones.

**Resolved: the 2026-08-22 snapshot was deleted via the Proxmox GUI and the
name reused.** Worth doing rather than picking a new name, because the old one
captured the *SQL_ASCII* cluster under a label promising the opposite.
Restoring a snapshot called `schema-applied` and silently getting F2 back is
the kind of trap that costs an afternoon and looks like a new bug.

If reproducing this from the command line:

```bash
pct listsnapshot 102
pct delsnapshot 102 schema-applied
pct snapshot 102 schema-applied --description 'UTF-8 cluster, jobs schema at 0002'
```

```
freeze guest filesystem
  WARNING: You have not turned on protection against thin pools running out of space.
  Logical volume "snap_vm-102-disk-0_schema-applied" created.
  WARNING: Sum of all thin volume sizes (<6.35 TiB) exceeds the size of thin pool pve/data
           and the size of whole volume group (<1.82 TiB).
thaw guest filesystem
```

The thin-pool warnings are **not** noise — see F1.

---


---

# Deploying the API — issue [#36](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/36)

Steps 15–22.

> **Read this before starting: the browser routes have no authentication.**
> Anything that can reach the API can read, cancel and stream every job,
> including presigned URLs for every artifact. `owner` and `visibility` exist
> as columns and nothing populates them.
>
> That is a deployment constraint, not a bug to work around:
> **Cloudflare Access must admit only people who may see everything.**
> [#47](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/47)
> closes it.

## Order, and why it is this way

Three things must exist before the API can be configured at all, and two are
produced somewhere other than this container.

| # | What | Produced | Needed by |
|---|---|---|---|
| 15 | MinIO bucket + service account | **on the container** (#37) | Step 18 — there is no `S3_ACCESS_KEY` until this exists |
| 16 | Internal CA + certificates | **on your workstation** (#39) | Step 19 — and the CA key must never come here |
| 17 | Tunnel hostnames | **Cloudflare dashboard** (#39) | Step 18 — `S3_PUBLIC_ENDPOINT` must be the real name |

**The tunnel does not have to be running yet**, only decided. The API *signs*
URLs for the public hostname and never connects to it — signing is local
arithmetic — so `cloudflared` starts at step 20, once there is an origin for
it to reach.

Then, in order:

| # | What | Why here |
|---|---|---|
| 18 | The environment file | Needs the keys from 15 and the hostname from 17 |
| 19 | TLS material onto the container | The API cannot start without its own certificate |
| **19a** | **MinIO on TLS, on the LAN address** | Step 20's tunnel config and step 22's presigned URLs both assume it |
| 20 | The API service (mTLS, `8443`) | Dom0's listener |
| **20a** | **Install `cloudflared`, create the tunnel** | The config file in step 20 is inert without a binary and a unit |
| **20b** | **The browser listener (`8000`)** | `cloudflared` cannot present a client certificate to an mTLS origin |
| 21 | Verify, negatives first | |
| **21b** | **Pre-flight for step 22** | Four things that fail at request time, not at startup |
| 22 | A real job, end to end | |

**Steps 19a, 20a, 20b and 21b were missing** and were added 2026-08-23, after
step 20 was reached and `systemctl enable --now cloudflared` failed with no
such unit. They are lettered rather than renumbered so that the executed
evidence below, which cites step numbers, stays readable.

## Step 15 — the bucket and the API's service account

Full policy, CORS and TTL decisions belong to
[#37](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/37).
This is the minimum that unblocks the API.

```bash
root@pve1:~# pct exec 102 -- bash -lc '
  curl -fsSLo /usr/local/bin/mc https://dl.min.io/client/mc/release/linux-amd64/mc
  chmod +x /usr/local/bin/mc
  set -a; . /etc/minio/minio.env; set +a
  mc alias set local http://127.0.0.1:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD"
  mc mb --ignore-existing local/analysis
  mc ls local
'
Added `local` successfully.
Bucket created successfully `local/analysis`.
[2026-08-23 10:09:24 UTC]     0B analysis/

```

**`MINIO_SITE_REGION` must be `eu-central-1`** and must match `S3_REGION` in
step 18. The region is part of the SigV4 signing scope, so a mismatch fails
every presigned URL with a 403 that talks about the signature and never
mentions regions.

The policy, derived from what the code actually does rather than from what it
might need:

```bash
pct exec 102 -- bash -lc 'cat > /tmp/api-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:PutObject"],
    "Resource": ["arn:aws:s3:::analysis/*"]
  }]
}
EOF
mc admin user svcacct add --policy /tmp/api-policy.json local "$MINIO_ROOT_USER"
rm /tmp/api-policy.json'
```

Record the access key and secret it prints — they go into step 18 and are not
recoverable afterwards.

**Why exactly those two actions.** The API itself makes only `head_object` and
`get_object` calls, during admission; it never uploads. But it *signs*
presigned PUTs for the browser and the worker, **and a presigned URL carries
the signer's permissions** — so without `PutObject` here every upload fails at
use time rather than at signing time, which is a confusing place to find out.

Deliberately absent: **no `ListBucket`**, so a compromised API cannot
enumerate a store holding live malware, and **no `DeleteObject`**, because
nothing in the current design deletes an artifact and the capability should
not exist until retention is designed and grants it.

**Root credentials stop here.** They created the bucket and the service
account; they must not appear in any application config.

## Step 16 — the CA, on your workstation

> **THIS STEP DOES NOT RUN ON L0 OR ON THE CONTAINER**, unlike everything else
> in this runbook. The CA root key is the highest-value key in the system
> precisely because it can mint identities — including a Dom0 client
> certificate — so it lives on a machine that is not part of the platform.
> `issue-cert.sh init` refuses to run somewhere that looks like the container,
> but the rule is yours to keep.

```bash
# on your workstation, in a checkout of this repository
./tls/issue-cert.sh init

./tls/issue-cert.sh server api   192.168.1.10 platform.lan
./tls/issue-cert.sh server minio 192.168.1.10 platform.lan
./tls/issue-cert.sh client dom0-lab
./tls/issue-cert.sh client fake-worker

./tls/issue-cert.sh verify api
```

**`fake-worker` is a separate identity from `dom0-lab` on purpose.** Step 22
runs the fake worker on the container, and `dom0-lab` is the one pair that
must never leave Dom0 (see step 19). Two identities also mean the `workers`
table records which of them did what, and the test one can be revoked without
touching the real worker.

Record the expiry dates somewhere they will be read. With manual issuance and
no monitoring, the failure mode is the platform stopping on a date nobody
wrote down.

Back up `tls/ca/ca.key` somewhere that is **not** the platform and not Dom0.
Losing it means reissuing every certificate and reinstalling the trust anchor.

## Step 17 — tunnel hostnames

Create the tunnel and route two hostnames to it. `cloudflared` is configured
in step 20; this step only fixes the names, because they go into the API's
configuration and the browser's upload URLs are signed against them.

- `sandbox.evilbootloader.com` → the API
- `objects.evilbootloader.com` → MinIO

These names are not cosmetic. `S3_PUBLIC_ENDPOINT` in step 18 must be the
second one **exactly**, because SigV4 signs the Host header — a URL signed for
one name and presented at another fails with a 403 about the signature.

**Put Cloudflare Access on both before the first submission.** Without it they
are public, and the second fronts a store holding live malware.

## Step 18 — the environment file

```bash
pct exec 102 -- bash -lc 'install -d -m 700 -o platform -g platform /etc/sandbox-platform'
pct exec 102 -- bash -lc 'cat > /etc/sandbox-platform/api.env <<EOF
DATABASE_URL=postgresql:///sandbox_platform

# TWO endpoints, and they are not interchangeable. SigV4 signs the Host
# header, so a URL signed for one host is rejected at the other. Dom0 reaches
# MinIO over the LAN; browsers reach it through the tunnel.
S3_INTERNAL_ENDPOINT=https://192.168.1.10:9000
S3_PUBLIC_ENDPOINT=https://objects.evilbootloader.com
S3_BUCKET=analysis
S3_REGION=eu-central-1
S3_ACCESS_KEY=<from step 15>
S3_SECRET_KEY=<from step 15>
S3_CA_BUNDLE=/etc/sandbox-platform/tls/ca.crt

# The only credential Dom0 ever holds. Generate it: openssl rand -hex 32
WORKER_TOKEN=<generated>
EOF
chmod 600 /etc/sandbox-platform/api.env
chown platform:platform /etc/sandbox-platform/api.env'
```

`0600` and owned by `platform`, because this file holds every credential on
the platform in one place. That concentration is deliberate — it is what buys
the narrow blast radius on Dom0 — and it is what makes this file the thing to
protect.

## Step 19 — TLS material onto the container

Copy in the certificates from step 16. **Note which files travel and which do
not.**

```bash
pct push 102 tls/ca/ca.crt   /etc/sandbox-platform/tls/ca.crt
pct push 102 tls/ca/api.crt  /etc/sandbox-platform/tls/api.crt
pct push 102 tls/ca/api.key  /etc/sandbox-platform/tls/api.key
pct exec 102 -- bash -lc '
  chown -R platform:platform /etc/sandbox-platform/tls
  chmod 600 /etc/sandbox-platform/tls/api.key
'
```

`dom0-lab.crt`/`dom0-lab.key` go to Dom0 and nowhere else.
`fake-worker.crt`/`fake-worker.key` go to the container, for step 22:

```bash
pct push 102 tls/ca/fake-worker.crt /etc/sandbox-platform/tls/fake-worker.crt
pct push 102 tls/ca/fake-worker.key /etc/sandbox-platform/tls/fake-worker.key
pct exec 102 -- bash -lc '
  chown platform:platform /etc/sandbox-platform/tls/fake-worker.*
  chmod 600 /etc/sandbox-platform/tls/fake-worker.key
'
```

`minio.crt`/`minio.key` are step 19a.

Then assert the property the whole design rests on:

```bash
pct exec 102 -- bash -lc 'find / -name "ca.key" 2>/dev/null | grep . && echo FAIL || echo "no CA key on the platform -- correct"'
```

## Step 19a — MinIO on TLS, on the LAN address

**This step was missing, and steps 20 and 22 both assume it has run.** Step 4
brings MinIO up on plain HTTP bound to loopback, which is right for step 15's
bucket creation and wrong for everything after it:

- **Dom0 cannot reach loopback.** `S3_INTERNAL_ENDPOINT` is *Dom0's* endpoint —
  the presigned sample URL is signed against it and then fetched from Dom0. A
  URL naming `127.0.0.1` tells Dom0 to fetch from itself.
- **Step 20 points `cloudflared` at `https://127.0.0.1:9000`**, which fails
  against an HTTP listener.

MinIO looks for `public.crt` and `private.key` by those exact names — it does
not take a path to an arbitrary pair:

```bash
pct exec 102 -- bash -lc 'install -d -m 700 -o minio-user -g minio-user /etc/minio/certs'
pct push 102 tls/ca/minio.crt /etc/minio/certs/public.crt
pct push 102 tls/ca/minio.key /etc/minio/certs/private.key
pct exec 102 -- bash -lc '
  chown minio-user:minio-user /etc/minio/certs/public.crt /etc/minio/certs/private.key
  chmod 600 /etc/minio/certs/private.key
'
```

> **`/etc/minio` itself must be traversable by `minio-user`.** This cost three
> rounds of debugging on 2026-08-23. The directory was `root:root`, so
> `minio-user` could not descend into `/etc/minio/certs` no matter what the
> certs' own ownership said — and MinIO **started anyway, on HTTP, without
> logging a reason.**
>
> The symptom is indistinguishable from "the flag was ignored": `--certs-dir`
> is right there in the argv, and the server speaks plain HTTP. Check the
> parent, not just the leaf:
>
> ```bash
> pct exec 102 -- ls -ld /etc/minio /etc/minio/certs
> pct exec 102 -- su -s /bin/sh minio-user -c 'ls -l /etc/minio/certs/'
> # if that second command cannot list, MinIO cannot read them either
> pct exec 102 -- chown root:minio-user /etc/minio && pct exec 102 -- chmod 750 /etc/minio
> ```

Then bind it to the LAN address and pin the region, in `/etc/minio/minio.env`:

```bash
MINIO_VOLUMES="/srv/minio/data"
MINIO_OPTS="--address 192.168.1.10:9000 --console-address 127.0.0.1:9001 --certs-dir /etc/minio/certs"
MINIO_SITE_REGION=eu-central-1
```

**The console stays on loopback.** It is an administrative interface to a store
holding live malware and has no reason to be reachable from the LAN; reach it
over an SSH tunnel when you need it.

`MINIO_SITE_REGION` must equal `S3_REGION` in step 18. The region is part of
the SigV4 signing scope, so a mismatch fails every presigned URL with a 403
that talks about the signature and never mentions regions.

```bash
root@pve1:~# pct exec 102 -- systemctl restart minio
pct exec 102 -- ss -lntp | grep 9000
LISTEN 0      4096       127.0.0.1:9000      0.0.0.0:*    users:(("minio",pid=3047,fd=6))                       
LISTEN 0      4096    192.168.1.10:9000      0.0.0.0:*    users:(("minio",pid=3047,fd=7))                       
LISTEN 0      4096           [::1]:9000         [::]:*    users:(("minio",pid=3047,fd=8))       
```

**Three listeners is correct, and this document said otherwise.** It claimed
to expect `192.168.1.10:9000` *only*, and that a surviving `127.0.0.1:9000`
meant `--address` had not applied. Wrong: MinIO binds loopback alongside the
address it is given, so the extra sockets prove nothing either way.

That mistaken expectation sent the 2026-08-23 debugging down the wrong path
for two rounds. **`ss` cannot tell you whether `MINIO_OPTS` applied — argv
can:**

```bash
pct exec 102 -- bash -lc 'tr "\0" " " < /proc/$(pgrep -x minio)/cmdline; echo'
```

And the protocol question is answered by asking for both, not by reading a
handshake summary:

```bash
pct exec 102 -- bash -lc '
  curl -s  -o /dev/null -w "http:  %{http_code}\n" http://192.168.1.10:9000/minio/health/live
  curl -sk -o /dev/null -w "https: %{http_code}\n" https://192.168.1.10:9000/minio/health/live
'
# TLS is on when https answers 200 and http does not
```

> **Do not use `openssl s_client … | grep 'Verify return'` for this.**
> It prints `Verify return code: 0 (ok)` even when **no certificate was
> received at all**, because an empty chain has nothing to reject. Against a
> plain-HTTP MinIO it reports what looks like success. The absent `subject=`
> and `issuer=` lines are the real signal — so grep for those, or use the
> `curl` pair above.

Re-point `mc` at the new address, since step 15's alias still says `http://`:

```bash
root@pve1:~# pct exec 102 -- bash -lc '
  set -a; . /etc/minio/minio.env; set +a
  mc alias set local https://192.168.1.10:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" \
     --api S3v4
  mc ls local
'
Added `local` successfully.
[2026-08-23 10:09:24 UTC]     0B analysis/
[0001-01-01 00:00:00 UTC]     0B data/

```

If `mc` rejects the certificate, it does not trust the internal CA yet:
`mc --insecure` proves that is the only problem, then install `ca.crt` into
`~/.mc/certs/CAs/` rather than leaving `--insecure` in a command someone will
copy.

## Step 20 — the API service (mTLS, for Dom0)

```bash
pct exec 102 -- bash -lc 'cat > /etc/systemd/system/sandbox-api.service <<EOF
[Unit]
Description=DRAKVUF sandbox platform API
After=network.target postgresql.service
Wants=postgresql.service

[Service]
User=platform
Group=platform
WorkingDirectory=/opt/platform/src/platform
EnvironmentFile=/etc/sandbox-platform/api.env
ExecStart=/opt/platform/src/platform/.venv/bin/python -m uvicorn \\
    sandbox_platform.app:app \\
    --host 192.168.1.10 --port 8443 \\
    --ssl-certfile /etc/sandbox-platform/tls/api.crt \\
    --ssl-keyfile  /etc/sandbox-platform/tls/api.key \\
    --ssl-ca-certs /etc/sandbox-platform/tls/ca.crt \\
    --ssl-cert-reqs 2
Restart=on-failure
RestartSec=5

# The service reads a sample only as a stream and writes none.
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now sandbox-api
systemctl status sandbox-api --no-pager | head -5'
```

`--ssl-cert-reqs 2` is `CERT_REQUIRED`: **a connection without a client
certificate signed by our CA is refused at the TLS layer**, before any handler
runs. That is what makes mTLS real rather than nominal, and it is why step 21
looks for a refused handshake rather than a 401.

## Step 20a — install cloudflared and create the tunnel

**This step was missing too.** The config file below is useless without a
binary, a tunnel, its credentials, and a systemd unit — and `systemctl enable
--now cloudflared` fails with no such unit until one exists.

```bash
pct exec 102 -- bash -lc '
  curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg \
    -o /usr/share/keyrings/cloudflare-main.gpg
  echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" \
    > /etc/apt/sources.list.d/cloudflared.list
  apt-get update && apt-get install -y cloudflared
'
```

Authenticate and create the tunnel. `tunnel login` prints a URL to open in a
browser; it writes `~/.cloudflared/cert.pem`, which authorises *creating*
tunnels and is not what the tunnel runs on:

```bash
pct exec 102 -- cloudflared tunnel login
pct exec 102 -- cloudflared tunnel create sandbox-platform
pct exec 102 -- cloudflared tunnel route dns sandbox-platform sandbox.evilbootloader.com
pct exec 102 -- cloudflared tunnel route dns sandbox-platform objects.evilbootloader.com
```

`tunnel create` prints the UUID and writes `~/.cloudflared/<UUID>.json`. Move
it where the config below expects it:

```bash
pct exec 102 -- bash -lc '
  install -d -m 750 /etc/cloudflared
  mv ~/.cloudflared/<UUID>.json /etc/cloudflared/
  chmod 600 /etc/cloudflared/<UUID>.json
'
```

The service unit. `cloudflared service install` will write one for you, as
root; this is the same thing running as a dedicated account, because the
process binds no privileged port and makes only outbound connections:

```bash
pct exec 102 -- bash -lc '
  useradd --system --no-create-home --shell /usr/sbin/nologin cloudflared || true
  cp /etc/sandbox-platform/tls/ca.crt /etc/cloudflared/ca.crt
  chown -R cloudflared:cloudflared /etc/cloudflared

cat > /etc/systemd/system/cloudflared.service <<EOF
[Unit]
Description=Cloudflare Tunnel (browser-facing ingress)
After=network-online.target sandbox-api.service
Wants=network-online.target

[Service]
Type=notify
User=cloudflared
Group=cloudflared
ExecStart=/usr/bin/cloudflared --no-autoupdate --config /etc/cloudflared/config.yml tunnel run
Restart=on-failure
RestartSec=5
TimeoutStartSec=0

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload'
```

Two details that are not decoration:

- **`--no-autoupdate`.** The default is a self-updating binary that restarts
  itself. Under `ProtectSystem=strict` it cannot write anyway, but the real
  objection is an unannounced binary change on the host fronting a malware
  store.
- **`ca.crt` is copied into `/etc/cloudflared/`** rather than referenced at
  `/etc/sandbox-platform/tls/ca.crt`. That directory is `0700 platform:platform`
  from step 18, so a non-root `cloudflared` cannot read it. The CA certificate
  is public material, so copying costs nothing and avoids loosening a
  directory that holds every credential on the platform.

Now the tunnel config, which reaches both origins over **loopback** so the
browser path never depends on the LAN certificate matching a public name:

```bash
pct exec 102 -- bash -lc 'cat > /etc/cloudflared/config.yml <<EOF
tunnel: 9d7675c5-fd3d-492a-8e7d-625981d8150d
credentials-file: /etc/cloudflared/9d7675c5-fd3d-492a-8e7d-625981d8150d.json
ingress:
  - hostname: sandbox.evilbootloader.com
    service: https://192.168.1.10:8000
    originRequest:
      caPool: /etc/cloudflared/ca.crt
  - hostname: objects.evilbootloader.com
    service: https://192.168.1.10:9000
    originRequest:
      caPool: /etc/cloudflared/ca.crt
  - service: http_status:404
EOF
chown cloudflared:cloudflared /etc/cloudflared/config.yml
cloudflared --config /etc/cloudflared/config.yml tunnel ingress validate
systemctl enable --now cloudflared
systemctl status cloudflared --no-pager | head -5'
```

`ingress validate` parses the rules before you have a service flapping in a
restart loop.

> **The origins are the LAN address, not loopback, and the API one is port
> 8000 rather than 8443.** Both are corrections to what this step said
> originally, and both are consequences of the same thing:
>
> - **uvicorn binds `192.168.1.10` only** (see the `ss` output in step 21), so
>   nothing answers on `127.0.0.1:8443`. Connecting to the container's own LAN
>   address never reaches the wire — the kernel routes it locally — so nothing
>   is lost.
> - **`cloudflared` cannot present a client certificate to an origin.**
>   `originRequest` can *verify* an origin (`caPool`, `originServerName`,
>   `noTLSVerify`) but has no option to send one. The API's mTLS listener
>   answers `--ssl-cert-reqs 2` — `CERT_REQUIRED` — so the browser path cannot
>   traverse it at all. Port **8000** is the second listener added in step 20b.

## Step 20b — the browser listener

The mTLS listener on `8443` is for Dom0. `cloudflared` needs its own origin,
and splitting them buys more than a working tunnel:

| Listener | Reached by | Authenticated by | Mounts |
|---|---|---|---|
| `192.168.1.10:8443` | Dom0 | client certificate **and** worker token | `/api/v1/worker/*` |
| `192.168.1.10:8000` | `cloudflared` | Cloudflare Access, at the edge | `/api/v1/jobs/*` |

**Separating them means a Cloudflare Access bypass still cannot reach the
worker channel, and a leaked Dom0 key cannot enumerate job history.** Neither
holds while one process serves both to everyone who gets past its front door.

> **NOT YET IMPLEMENTED.** `app.py` mounts both routers unconditionally, so
> today the split is by *listener* only and both listeners expose both
> routers. Per-listener mounting needs a code change — tracked with
> [#47](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/47),
> which owns the browser-auth gap generally. Until it lands, the table above
> describes intent and **Cloudflare Access is the only thing keeping the
> browser side closed.**

```bash
root@pve1:~# pct exec 102 -- bash -lc 'sed -e s/8443/8000/ \
    -e "/ssl-cert-reqs/d" \
    -e "s/sandbox platform API/sandbox platform API (browser)/" \
    /etc/systemd/system/sandbox-api.service \
    > /etc/systemd/system/sandbox-api-browser.service
systemctl daemon-reload
systemctl enable --now sandbox-api-browser
ss -lntp | grep -E "8000|8443"'
Created symlink '/etc/systemd/system/multi-user.target.wants/sandbox-api-browser.service' → '/etc/systemd/system/sandbox-api-browser.service'.
LISTEN 0      2048    192.168.1.10:8443       0.0.0.0:*    users:(("python",pid=3701,fd=9))        
```

> **That `sed` produces a unit that cannot start, and the output above is the
> proof: only `8443` is listening.** `enable` succeeded — it only creates a
> symlink — so the failure is silent unless you read the `ss` line.
>
> The cause is the `-e "/ssl-cert-reqs/d"` deletion. `ExecStart` is a
> line-continued block, and `--ssl-cert-reqs 2` is its **last** line, the only
> one without a trailing `\`. Deleting it leaves the previous line ending in a
> backslash with nothing after it, and systemd rejects the unit.
>
> `sed` was the wrong tool: deriving one unit from another by text
> substitution makes the result depend on line breaks in the original.
> Write it out instead:

```bash
pct exec 102 -- bash -lc 'cat > /etc/systemd/system/sandbox-api-browser.service <<EOF
[Unit]
Description=DRAKVUF sandbox platform API (browser origin for cloudflared)
After=network.target postgresql.service
Wants=postgresql.service

[Service]
User=platform
Group=platform
WorkingDirectory=/opt/platform/src/platform
EnvironmentFile=/etc/sandbox-platform/api.env
ExecStart=/opt/platform/src/platform/.venv/bin/python -m uvicorn \\
    sandbox_platform.app:app \\
    --host 192.168.1.10 --port 8000 \\
    --ssl-certfile /etc/sandbox-platform/tls/api.crt \\
    --ssl-keyfile  /etc/sandbox-platform/tls/api.key
Restart=on-failure
RestartSec=5

ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
systemd-analyze verify /etc/systemd/system/sandbox-api-browser.service
systemctl daemon-reload
systemctl enable --now sandbox-api-browser
systemctl is-active sandbox-api-browser
sleep 2
ss -lntp | grep -E "8000|8443"'

active
LISTEN 0      2048    192.168.1.10:8443       0.0.0.0:*    users:(("python",pid=4674,fd=9))                      
LISTEN 0      2048    192.168.1.10:8000       0.0.0.0:*    users:(("python",pid=6269,fd=9))    
```

`systemd-analyze verify` is what would have caught the `sed` breakage before
the service was enabled — it parses the unit and reports syntax errors without
starting anything. **`systemctl is-active` must print `active`, and `ss` must
show both ports.** `enable` alone tells you nothing.

No `--ssl-ca-certs` and no `--ssl-cert-reqs`: TLS stays on, client
certificates become optional, which is what `cloudflared` needs. The listener
is still on the LAN address, so **`192.168.1.10:8000` is reachable from Dom0
and from anything else on that segment without a certificate** — that is the
exposure #47 closes, and it is why Access on the tunnel is load-bearing rather
than convenient.

**The `Host` header must reach MinIO unchanged.** Presigned URLs are signed
for `objects.evilbootloader.com`, and MinIO recomputes the signature from the Host it
receives — so if `cloudflared` rewrites it, every browser upload fails with a
403 about the signature. If that happens, check this first.

## Step 21 — verify, negatives first

The positive cases prove it runs. **These prove it is doing anything.**

```bash
user@personal:~/QubesIncoming/vault/tls/ca$ openssl s_client -connect 192.168.1.10:8443 </dev/null 2>&1 | tail -3
Verify return code: 19 (self-signed certificate in certificate chain)
---
DONE
user@personal:~/QubesIncoming/vault/tls/ca$ curl --cacert ca.crt --cert dom0-lab.crt --key dom0-lab.key \
     https://192.168.1.10:8443/healthz
{"status":"ok"}user@personal:~/QubesIncomingopenssl s_client -connect 192.168.1.10:8443 -tls1_1 </dev/null 2>&1 | tail -2 2>&1 | tail -2
Verify return code: 0 (ok)
---
user@personal:~/QubesIncoming/vault/tls/ca$ curl --cacert ca.crt --cert dom0-lab.crt --key dom0-lab.key \
     -X POST https://192.168.1.10:8443/api/v1/worker/claim \
     -H 'Content-Type: application/json' \
     -d '{"worker_id":"x","free_mib":1,"free_vlans":1,"free_slots":1}'
{"detail":"worker token required"}

# 5. the tunnel opened no inbound port
root@pve1:~# pct exec 102 -- ss -lntp | grep -v 127.0.0.1
State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess                                                
LISTEN 0      4096    192.168.1.10:9000       0.0.0.0:*    users:(("minio",pid=3473,fd=12))                      
LISTEN 0      2048    192.168.1.10:8443       0.0.0.0:*    users:(("python",pid=4123,fd=9))                      
LISTEN 0      4096               *:22               *:*    users:(("sshd",pid=118,fd=3),("systemd",pid=1,fd=117))
LISTEN 0      100            [::1]:25            [::]:*    users:(("master",pid=269,fd=14))                      
LISTEN 0      4096           [::1]:9000          [::]:*    users:(("minio",pid=3473,fd=13))           
```

### Checks 1 and 3 above do not prove what they claim

Both were mine and both are unsound. Keeping the transcript as evidence of
what was run, and replacing the checks.

**Check 1 — `Verify return code: 19` does not demonstrate mTLS.** Code 19 is
*"this CA is not in my trust store"*, which is just `openssl` being run without
`-CAfile`. It says the server sent a certificate the client could not verify.
It says nothing about whether the server demanded one in return — and a server
with `--ssl-cert-reqs 0` produces the identical line.

**Check 3 — `Verify return code: 0 (ok)` does not demonstrate TLS 1.1 was
refused.** Same trap as the MinIO check above: with no certificate received
there is nothing to reject, so verification passes vacuously. The output of a
*refused* connection and a *successful* one are one line apart, and `tail -2`
crops the part that distinguishes them.

**Why these are ambiguous rather than merely sloppy: under TLS 1.3 the server
completes its side of the handshake before it validates the client
certificate.** A missing client certificate is therefore not a handshake
failure the client sees at connect time — it arrives later, as a closed
connection while waiting for a response. This is exactly what cost an hour on
2026-08-23 when the fake worker returned `UNEXPECTED_EOF_WHILE_READING` with
no matching line in uvicorn's log.

Use `curl` and read the exit status, which is unambiguous:

```bash
# 1. no client certificate -> the connection must FAIL, not return 401
curl --cacert ca.crt https://192.168.1.10:8443/healthz
echo "exit=$?"
# expect: non-zero, and a message naming a certificate.
#   curl 8.x: "OpenSSL/3.x error ... tlsv13 alert certificate required"
# A 401 or a 200 here means mTLS is NOT being enforced.

# 3. TLS 1.2 and below refused
curl --cacert ca.crt --cert dom0-lab.crt --key dom0-lab.key \
     --tls-max 1.2 https://192.168.1.10:8443/healthz
echo "exit=$?"
# expect: non-zero. exit=0 means an obsolete version is still accepted.
```

## Step 21b — before step 22

Four things step 22 needs that earlier steps do not produce. Check each rather
than assuming, because three of them fail at *request* time rather than at
startup and the symptom is a traceback in the middle of an otherwise working
run.

**1. The code on the container is current.** The checkout is the deployment
mechanism, so a code change reaches the container by pull and nothing else:

```bash
pct exec 102 -- su - platform -s /bin/bash -c '
  cd /opt/platform/src && git pull --ff-only && git log -1 --oneline
  cd platform && .venv/bin/pip install -r requirements.txt
  set -a; . /etc/sandbox-platform/api.env; set +a
  .venv/bin/python migrations/run.py
'
pct exec 102 -- systemctl restart sandbox-api
```

> **If `git pull` refuses** with *"local changes would be overwritten"* or
> *"untracked working tree files would be overwritten"*, the container has a
> build that did not come from git — the drift CLAUDE.md warns about. Confirm
> the working tree matches the pushed commit before discarding anything:
>
> ```bash
> pct exec 102 -- su - platform -s /bin/bash -c '
>   cd /opt/platform/src && git fetch origin
>   git add -A && git diff --cached --stat origin/master; git reset -q'
> ```
>
> Empty output means only the bookkeeping is behind, and
> `git reset --hard origin/master && git clean -fd` is safe — but run
> `git clean -fdn` first and check `.venv` is not in the list.
>
> **Encountered 2026-08-23.** The container held the whole of #36 as untracked
> files while `origin/master` had none of it, because the commits existed only
> on the workstation. `git pull` reported *"Already up to date"*, which was
> true and useless. The `--ff-only` refusal is the guard working.

**2. The migration state is what you think.** `run.py` printing `up to date`
proves it applied nothing, not that everything is applied:

```bash
root@pve1:~# pct exec 102 -- su - platform -s /bin/bash -c "psql -d sandbox_platform <<'SQL'
SELECT filename, applied_at FROM schema_migrations ORDER BY filename;
SQL"
       filename       |          applied_at           
----------------------+-------------------------------
 0001_jobs.sql        | 2026-08-23 04:15:18.243017+00
 0002_triggers.sql    | 2026-08-23 04:15:18.243017+00
 0003_sample_etag.sql | 2026-08-23 11:56:02.878385+00
(3 rows)


# expect three rows, including 0003_sample_etag.sql
```

**3. The API's S3 block is present and correct.** Every S3 setting in
`config.py` has a default — *including empty credentials* — so a missing block
starts cleanly and fails on the first request that touches MinIO:

```bash
root@pve1:~# pct exec 102 -- grep -cE '^S3_(ACCESS|SECRET)_KEY=.' /etc/sandbox-platform/api.env
2
# expect: 2

root@pve1:~# pct exec 102 -- grep -E '^S3_(INTERNAL|PUBLIC)_ENDPOINT|^S3_REGION' /etc/sandbox-platform/api.env
S3_INTERNAL_ENDPOINT=https://192.168.1.10:9000
S3_PUBLIC_ENDPOINT=https://objects.evilbootloader.com
S3_REGION=eu-central-1
```

`S3_INTERNAL_ENDPOINT` must be the address **Dom0** can reach
(`https://192.168.1.10:9000` after step 19a), not loopback. `S3_REGION` must
equal MinIO's `MINIO_SITE_REGION`.

*The fake worker runs on the container, so a loopback `S3_INTERNAL_ENDPOINT`
will still pass step 22 and then fail against real Dom0. Fix it here rather
than discovering it once `sandboxd` exists.*

**4. The fake worker has a certificate.** Issued at step 16, pushed at step
19. Confirm both halves arrived:

```bash
root@pve1:~# pct exec 102 -- ls -l /etc/sandbox-platform/tls/fake-worker.crt /etc/sandbox-platform/tls/fake-worker.key
-rw-r--r-- 1 platform platform 1533 Aug 23 13:06 /etc/sandbox-platform/tls/fake-worker.crt
-rw------- 1 platform platform 1704 Aug 23 13:06 /etc/sandbox-platform/tls/fake-worker.key
```

## Step 22 — a real job, end to end

`fake_worker.py` is in the repository for exactly this. It analyses nothing:
no clone, no VLAN, no execution. It proves the platform works before Dom0 is
involved, and afterwards it is what tells a platform fault from a Dom0 one.

```bash
root@pve1:~# pct exec 102 -- su - platform -s /bin/bash -c '
  cd /opt/platform/src/platform
  set -a; . /etc/sandbox-platform/api.env; set +a
  .venv/bin/python fake_worker.py \
      --api https://192.168.1.10:8443 \
      --cacert /etc/sandbox-platform/tls/ca.crt \
      --cert   /etc/sandbox-platform/tls/fake-worker.crt \
      --key    /etc/sandbox-platform/tls/fake-worker.key \
      --token "$WORKER_TOKEN" --once
'
registered as fake-worker, offering 12082 MiB
nothing to do
```

> **PASS 2026-08-23.** The worker channel closes end to end: mTLS, the bearer
> token, `register`, `reconcile` and `claim`. `nothing to do` is the correct
> answer on an empty queue.
>
> **This needed a code fix first (`d1640b8`), and the failure is worth
> knowing.** The first attempt died with
> `httpx.ReadError: [SSL: UNEXPECTED_EOF_WHILE_READING]` and **no
> corresponding request in uvicorn's log** — `/healthz` over the same
> certificates returned 200 from `curl` at the same moment.
>
> The cause was in `fake_worker.py`, not on the container. httpx 0.28's
> `create_ssl_context` returns early when `verify` is a path string:
>
> ```python
> elif isinstance(verify, str):
>     return ssl.create_default_context(cafile=verify)   # returns here
> ...
> if cert:                                              # never reached
>     ctx.load_cert_chain(*cert)
> ```
>
> Passing both as strings silently discarded the client certificate, so the
> worker connected anonymously while `--help` still listed `--cert`/`--key`.
> The fix builds the `SSLContext` directly.
>
> **Two things to carry forward.** A rejected client certificate under TLS 1.3
> looks like an EOF and an empty server log, not like an authentication error —
> if `sandboxd` ever shows that, suspect its certificate first. And a client
> library can accept a security parameter and drop it, so the property worth
> asserting is *the server saw the identity*, not *the flag was passed*.

**`192.168.1.10:8443`, not `127.0.0.1`** — uvicorn binds the LAN address only.
The three TLS flags are not optional against the deployed listener: it
requires a client certificate at the handshake, so without them the worker
fails before it sends a request.

Expect `registered as fake-worker, offering 12082 MiB`, then `nothing to do`.
That alone exercises mTLS, the bearer token, registration, reconcile and the
claim path.

**If a job is rejected `no_workers`, that is correct**, not a fault —
admission refuses before any worker has registered, and on a fresh platform
that is the honest answer. Register first, then submit.

## Step 23 — a submission, end to end

Step 22 proves the worker channel. This proves everything the worker channel
does not touch: the jobs router, the presigned upload, admission, and artifact
publication.

`submit.py` is the browser's half of the protocol as `fake_worker.py` is
Dom0's. Together they close the loop with neither a UI (#38) nor a Xen host.

**Test against the LAN before the tunnel.** The presigned POST is signed for
`S3_PUBLIC_ENDPOINT`, so going through Cloudflare mixes the platform and the
tunnel into one result. Set it to `https://192.168.1.10:9000` temporarily,
restart both listeners, and put it back afterwards.

```bash
root@pve1:~# pct exec 102 -- su - platform -s /bin/bash -c '
  cd /opt/platform/src/platform
  echo "harmless test file" > /tmp/hello.txt
  .venv/bin/python submit.py \
      --api https://192.168.1.10:8443 \
      --cacert /etc/sandbox-platform/tls/ca.crt \
      --cert   /etc/sandbox-platform/tls/fake-worker.crt \
      --key    /etc/sandbox-platform/tls/fake-worker.key \
      --target-os ubuntu --file /tmp/hello.txt
'
created 62f31c64-70a2-4979-a875-a21bd28aad71 for hello.txt (19 bytes)
uploaded to https://192.168.1.10:9000/analysis
admitted: state=queued sha256=af9c4ea0d7be30203e00346c79d1bdf645568614ab6ced2610fa3dbef406e890 type='ASCII text'

root@pve1:~# pct exec 102 -- su - platform -s /bin/bash -c '
  cd /opt/platform/src/platform
  set -a; . /etc/sandbox-platform/api.env; set +a
  .venv/bin/python fake_worker.py \
      --api https://192.168.1.10:8443 \
      --cacert /etc/sandbox-platform/tls/ca.crt \
      --cert   /etc/sandbox-platform/tls/fake-worker.crt \
      --key    /etc/sandbox-platform/tls/fake-worker.key \
      --token "$WORKER_TOKEN" --once
'
registered as fake-worker, offering 12082 MiB
leased 62f31c64-70a2-4979-a875-a21bd28aad71 (ubuntu) 'hello.txt' attempt 1
  fetched 19 bytes
  -> preparing
  -> executing
  -> collecting
  -> cleaning
  uploaded 3 artifacts
  -> completed
```

> **PASS 2026-08-23.** Admission computed the digest and the type from the
> stored object rather than from anything the client declared, the worker
> fetched the sample with a presigned GET and no credential, and publication
> was atomic — the artifacts were in the store before the row said so.

### The declared size is enforced, not recorded

The check worth keeping, because it is the one an attacker would try. A client
declaring a small size and uploading a large file is refused **by the object
store**, not by the API:

```bash
root@pve1:~# … submit.py --target-os ubuntu --declare-size 10 --file /tmp/hello.txt
created b7a83f7b-dfc6-4f60-8848-43931a782210 for hello.txt (19 bytes)
upload rejected: 400
<Error><Code>EntityTooLarge</Code><Message>Your proposed upload exceeds the
maximum allowed object size.</Message>…
```

`create_job` signs the policy with `min(declared, MAX_SAMPLE_BYTES)`, so
`content-length-range` is built from the declaration. **Under-declaring
shrinks the submitter's own allowance; it cannot raise it**, and the refusal
happens at MinIO before a byte is stored. Editing the size in a proxy after
signing invalidates the signature instead.

> **FINDING — abandoned jobs are never cleaned up.** `b7a83f7b…` above is
> still in state `created` and always will be. `reap()` covers **lapsed
> leases** only; nothing touches the state between `POST /api/v1/jobs` and
> `/uploaded`. Every rejected or abandoned upload leaves a row.
>
> That matters because the browser routes have **no authentication and no
> rate limit** — anyone who can reach the API can grow that table at no cost.
> Not urgent while Access fronts the only public path, and not this runbook's
> to fix: tracked on
> [#47](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/47).

### Still to run

- **The SSE stream.** `--watch` was not exercised above. It blocks on the
  event stream, so start it *before* the worker, in a second terminal:
  `submit.py … --watch --wait 120`, then `fake_worker.py … --once`. Expect one
  `->` line per state, ending at `completed`.
- **The tunnel half.** Restore `S3_PUBLIC_ENDPOINT` to
  `https://objects.evilbootloader.com`, restart, and submit from a browser.
  Read the Access note in step 17 first — Access on the object-store hostname
  breaks the cross-origin upload.

Then snapshot:

```bash
pct snapshot 102 api-deployed --description 'API on 8443 with mTLS, tunnel up'
```


## F2 — the database was created SQL_ASCII, and the runner failed silently

> **CLOSED 2026-08-23.** The cluster was recreated as UTF-8 before any
> database existed, and the runner now refuses a SQL_ASCII database rather
> than misbehaving against one (`26803a7`). Verified on the container: the
> third `run.py` invocation prints `up to date`, and
> `type(row[0]).__name__` is `str`. The account below is kept because the
> failure mode is the part worth remembering.

**Symptom.** Step 11's idempotence re-run did not print `up to date`. It tried
to apply `0001_jobs.sql` a second time and died on
`DuplicateObject: type "target_os" already exists` — while `psql` showed both
migrations correctly recorded in `schema_migrations`, with the right digests,
in the right database, as the right user.

**Cause.** Every database on this cluster is `SQL_ASCII`, visible in step 12's
`psql -l` and easy to read past. SQL_ASCII is not an encoding; it is the
absence of one, and Postgres stores and returns raw bytes with no validation
or conversion. psycopg therefore hands back `bytes` rather than `str` for
every text column:

```
db/user  : (b'sandbox_platform', b'platform')
rows     : [(b'0001_jobs.sql',), (b'0002_triggers.sql',)]
```

`applied()` built a dict keyed by `b'0001_jobs.sql'`. `path.name` is a `str`.
The membership test never matched, so **every migration looked pending,
forever**. Reproduced in the development container against a deliberately
SQL_ASCII database; the development container is UTF8, which is why the test
suite never saw it.

**Why the cluster is SQL_ASCII.** The Debian container was created without a
UTF-8 locale, so `initdb` chose SQL_ASCII and `template1` inherited it. Step
8's `createdb` did not override it. Corrected in place above.

**Two fixes, and the second is the one that matters.**

1. *This database* is recreated as UTF8 — free right now because it holds
   only the schema, a dump-and-restore once it holds analyses.
2. *The runner refuses to run against SQL_ASCII at all*, rather than coping
   with bytes. Coping would have hidden a misconfiguration that #36's API and
   #38's web UI would each hit independently — and this database stores
   attacker-controlled filenames that will contain UTF-8, text the project
   has to compare, index and render rather than merely echo. The guard
   decodes defensively, because under SQL_ASCII even
   `SHOW server_encoding` returns bytes and a naive comparison passes.

**What this says about the failure mode, which is the real lesson.** The
runner did not error; it silently did the most destructive thing available —
re-run every migration against a live schema. On a database holding analyses
that is a corruption path, not an inconvenience. The guard is now a test
(`tests/test_migrations.py`), as is the plpgsql-`BEGIN` false positive from
earlier the same day.

---

## F1 — the LVM thin pool is oversubscribed 3.5:1 with no protection

Surfaced by the snapshot in step 12, in warnings easy to scroll past:

```
WARNING: You have not turned on protection against thin pools running out of space.
WARNING: Set activation/thin_pool_autoextend_threshold below 100 to trigger
         automatic extension of thin pools before they get full.
WARNING: Sum of all thin volume sizes (<6.35 TiB) exceeds the size of thin pool
         pve/data and the size of whole volume group (<1.82 TiB).
```

**6.35 TiB provisioned against 1.82 TiB of real storage.** Thin provisioning
is doing its job — nothing is wrong *yet*, because almost none of it is
written. What is missing is the guard for when that stops being true.

**Why this is not just a Proxmox housekeeping note.** The MinIO volume is
256 G thin, currently 2.1 M used, and this project is about to start writing
multi-gigabyte memdumps into it — one per analysis, with retention still an
open decision. If the *pool* fills, every thin volume on it is affected, not
only the one that filled it. That includes **VM 101, the Xen L1 host** whose
disks hold the golden images and the clone pool.

So the failure mode is: collecting artifacts fills the pool, and the analysis
lab stops working. A component whose entire security argument is that it is
isolated from Dom0 turns out to share a storage failure domain with it.

DRAFT-044's test 9 ("a full volume fails loudly") assumed the *volume* was the
constraint. It is not; the pool is, and the pool is shared.

**Not fixed here.** Three things to decide, none of them this runbook's:

1. `thin_pool_autoextend_threshold` and `autoextend_percent` in
   `/etc/lvm/lvm.conf` — the protection the warning names. Only helps while
   the VG has free extents.
2. Monitoring on pool usage, with a threshold that fires before the pool is
   full rather than when it is.
3. Whether the MinIO volume belongs on this pool at all, or on separate
   storage that cannot take Dom0's VM down with it. That is the real fix and
   it is an infrastructure decision.

Recorded against #37 (MinIO) and `docs/architecture/platform.md`, whose trust
boundary table describes isolation between the platform and Dom0 that the
storage layer does not currently provide.

---

## Rolling the database back

Not `DROP DATABASE` once real analyses exist. While #35 is the only thing
deployed the database holds nothing, so dropping and re-migrating is free —
and that stops being true the moment the API accepts its first submission.
After that, a schema change is a new numbered migration, never an edit and
never a reset.

---

## What is deliberately not in this runbook

- **Bucket creation, policy, service account, CORS** — #37.
- **TLS certificates and the mTLS trust anchor** — #36, which is where the
  worker token and the client certificate are defined together.
- **Backups.** Real work, and separate. Losing `/srv/minio` loses collected
  artifacts, which are reproducible only by re-running analyses.
- **Proxmox firewall rules.** Named as a prerequisite in `platform.md` and
  parked by the maintainer on 2026-08-21. Step 5 *observes* the posture; it
  does not enforce it.

## Rollback

```bash
pct stop 102 && pct destroy 102     # destroys the rootfs
```

`mp0` is a separate volume; check whether `pct destroy` removed it before
assuming the data is gone, and before assuming it is not. Nothing on Dom0 is
affected by any step here — the `dirwatch` pipeline runs throughout, which
is the property that makes the whole platform buildable without a flag day.



---

## Appendix — first attempt at the database, 2026-08-22 (rolled back)

Preserved because it is where **F2** was found, and because deleting a
transcript because its state was discarded is how a project forgets what
it already learned. Superseded by steps 7–14 above; the container was
restored to `base-install` on 2026-08-23 and these commands re-run in
corrected form.

Three things this pass established that survive the rollback: the deploy
key is read-only (a push was refused), the `target_os` enum is closed,
and the migration runner cannot be trusted against a SQL_ASCII database.

<details>
<summary>Original steps 7–12 and their output</summary>

# Deploying the database — issue [#35](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/35)

Steps 7–11. The schema and the migration runner are built and tested; this is
what puts them on the container.

**Nothing here holds a password.** Postgres and the API run in the *same*
container, so the API reaches the database over the Unix socket with peer
authentication as its own OS user. A TCP password connection would mean
storing a credential in a config file for a hop that never leaves the
container — a secret to leak, rotate and forget, buying nothing. Postgres
therefore also keeps Debian's default of not listening on the network at all.

## Step 7 — confirm Postgres is local-only

```bash
root@pve1:~# pct exec 102 -- bash -lc "
  su - postgres -c \"psql -tAc 'SHOW listen_addresses'\"
  ss -lntp | grep 5432 || echo 'not listening on TCP -- correct'
"
localhost
LISTEN 0      200        127.0.0.1:5432      0.0.0.0:*    users:(("postgres",pid=4671,fd=7))                   
LISTEN 0      200            [::1]:5432         [::]:*    users:(("postgres",pid=4671,fd=6))   

# Edited /etc/postgresql/17/main/postgresql.conf
listen_addresses = ''

root@pve1:~# pct exec 102 -- bash -lc "
  su - postgres -c \"psql -tAc 'SHOW listen_addresses'\"
  ss -lntp | grep 5432 || echo 'not listening on TCP -- correct'
"

not listening on TCP -- correct
```

**Corrected 2026-08-22 from the run above.** The instruction here said "expect
`localhost`", which was too weak. Debian's default *is* `localhost`, and that
still opens TCP listeners on `127.0.0.1:5432` and `[::1]:5432` — reachable by
anything running inside the container, including a compromised MinIO or a
future service nobody has thought about yet.

`listen_addresses = ''` was set instead, and that is the correct setting:
**no TCP listener at all**, Unix socket only. It matches what the design
actually assumes, since the API is co-located and connects over the socket
with peer authentication. Expect the second `ss` to print nothing.

If a later component genuinely needs TCP, that is a decision to take
deliberately — not something to leave open because a default was permissive.

## Step 8 — the application role and database

```bash
root@pve1:~# pct exec 102 -- bash -lc "
  useradd -r -m -s /usr/sbin/nologin platform || true
  su - postgres -c \"createuser platform\"
  su - postgres -c \"createdb -O platform sandbox_platform\"
  su - platform -s /bin/bash -c \"psql -d sandbox_platform -tAc 'select current_user'\"
"
platform
```

The OS user and the database role share a name deliberately — that is what
makes peer authentication work without configuration.

**`platform` is not a superuser.** It owns its own database and nothing else,
so a flaw in the API cannot reach the rest of the cluster. The migration
runner needs only `CREATE` inside that database, which ownership already
grants.

> **CORRECTED 2026-08-22 — `createdb` above is missing `-E UTF8`, and that
> caused F2 below.** The container has no UTF-8 locale, so this cluster's
> `initdb` defaulted to `SQL_ASCII` and every database inherits it. Use:
>
> ```bash
> su - postgres -c "createdb -O platform -E UTF8 -T template0 sandbox_platform"
> ```
>
> `-T template0` is required: `template1` is itself SQL_ASCII on this cluster
> and a new database cannot have an encoding its template lacks. Verified on a
> C-locale cluster — the result is `UTF8` with `C.UTF-8` collation, and the
> migrations apply and re-apply cleanly against it.
>
> Confirm before continuing:
>
> ```bash
> psql -d postgres -tAc \
>   "SELECT pg_encoding_to_char(encoding) FROM pg_database WHERE datname='sandbox_platform'"
> # expect: UTF8   -- NOT SQL_ASCII
> ```

## Step 9 — a read-only deploy key

The container needs to pull this repository, the way Dom0 already does. It
gets its **own** key, and that key is **read-only**.

**Why read-only is a containment decision, not tidiness.** Dom0 pulls its
worker scripts from this same repository. A platform key with write access
would mean that compromising the platform lets an attacker push to the
repository Dom0 then pulls and executes — turning a web-tier compromise into
code execution on the machine that runs malware. Read-only cuts that edge
entirely.

**Why its own key, not Dom0's.** Either host can then be revoked without
breaking the other, and a key found on the platform proves nothing about
Dom0.

Generate it in the container, as the `platform` user, so the private half is
created where it will live and never travels:

```bash
pct exec 102 -- su - platform -s /bin/bash -c '
  mkdir -p ~/.ssh && chmod 700 ~/.ssh
  ssh-keygen -t ed25519 -N "" -C "platform-lxc-102 (read-only)" -f ~/.ssh/id_ed25519
  ssh-keyscan github.com >> ~/.ssh/known_hosts
  cat ~/.ssh/id_ed25519.pub
'
```

`ssh-keyscan` pins GitHub's host key now rather than reaching for
`StrictHostKeyChecking=no` at clone time — that flag would accept any host
that answers, which on a first connection is exactly when it matters.

Register the printed public key as a deploy key. Either from a machine with
`gh` authenticated:

```bash
gh repo deploy-key add /path/to/id_ed25519.pub \
    --title "platform-lxc-102 (read-only)"
```

or in the web UI at **Settings → Deploy keys → Add deploy key**. Paste the
key, title it so it is identifiable, and **leave "Allow write access"
unchecked** — that box is the whole of the decision above.

Confirm it works and confirm it cannot write:

```bash
root@pve1:~# pct exec 102 -- su - platform -s /bin/bash -c '
  ssh -T git@github.com 2>&1 | head -2
'
Hi evilbootloader/drakvuf-multios-sandbox! You've successfully authenticated, but GitHub does not provide shell access.

```

**Corrected 2026-08-22: that output does NOT prove the key is read-only.**
GitHub returns the same `Hi <repo>! You've successfully authenticated` line
for a deploy key with write access. It confirms the key is bound to this
repository and nothing more.

The only check that distinguishes them is attempting a write:

```bash
pct exec 102 -- su - platform -s /bin/bash -c '
  cd /opt/platform/src && git push --dry-run origin HEAD 2>&1 | tail -3
'
# expect: ERROR: Write access to repository not granted.
```

**Still owed** — run it after step 10, when a checkout exists. Until then the
read-only property rests on the checkbox having been left unticked, which is
the intent but not evidence.

## Step 10 — deploy the code

```bash
pct exec 102 -- bash -lc "
  apt-get install -y git
  install -d -o platform -g platform /opt/platform
"
pct exec 102 -- su - platform -s /bin/bash -c '
  git clone git@github.com:evilbootloader/drakvuf-multios-sandbox.git \
      /opt/platform/src \
    || git -C /opt/platform/src pull --ff-only
  cd /opt/platform/src/platform
  python3 -m venv .venv
  .venv/bin/pip install -r requirements.txt
'
```

Same rule as Dom0's checkout: **do not edit deployed files in place.** Change
them in the repository, push, pull here. That is the drift issue #2 needed a
whole runbook to diagnose, and a database makes it worse — an edited migration
that has already been applied cannot be un-applied by editing it.

`--ff-only` on the pull so a local edit that someone made anyway causes a
visible refusal rather than a silent merge.

## Step 11 — apply the migrations

```bash
root@pve1:~# pct exec 102 -- su - platform -s /bin/bash -c '
  cd /opt/platform/src/platform
  export DATABASE_URL="postgresql:///sandbox_platform"
  .venv/bin/python migrations/run.py --status
  .venv/bin/python migrations/run.py
'
 pending  0001_jobs.sql
 pending  0002_triggers.sql
applied  0001_jobs.sql
applied  0002_triggers.sql

```

Expect `--status` to list both files as `pending`, then two `applied` lines.
Both appeared, and step 12 confirms the schema landed.

**Still owed: the second run.** It must print `up to date` and change nothing,
and the transcript above stops after the first. Idempotence is the property
the whole mechanism rests on — every future deploy re-runs this command
against a database that is already migrated, and if that is not a no-op then
the second deploy is where it will be discovered.

```bash
pct exec 102 -- su - platform -s /bin/bash -c '
  cd /opt/platform/src/platform
  DATABASE_URL="postgresql:///sandbox_platform" .venv/bin/python migrations/run.py
'
# expect exactly: up to date
```

The empty `DATABASE_URL` host (`postgresql:///name`) is what selects the Unix
socket. A `postgresql://localhost/name` would go over TCP and fail, because
step 7 confirmed nothing is listening.

## Step 12 — verify the schema landed

```bash
root@pve1:~# pct exec 102 -- su - platform -s /bin/bash -c '
  psql -d sandbox_platform -c "\dt"
  psql -d sandbox_platform -c "\d jobs" | tail -20
  psql -d sandbox_platform -tAc "SELECT filename FROM schema_migrations ORDER BY filename"
'
               List of relations
 Schema |       Name        | Type  |  Owner   
--------+-------------------+-------+----------
 public | jobs              | table | platform
 public | schema_migrations | table | platform
 public | worker_pipelines  | table | platform
 public | workers           | table | platform
(4 rows)

 cleanup_status     | text                     |           |          | 
 attempt            | integer                  |           | not null | 0
 cancel_requested   | boolean                  |           | not null | false
 lease_owner        | text                     |           |          | 
 lease_expires_at   | timestamp with time zone |           |          | 
 clone_domain       | text                     |           |          | 
 vlan               | integer                  |           |          | 
 manifest           | jsonb                    |           |          | 
Indexes:
    "jobs_pkey" PRIMARY KEY, btree (id)
    "jobs_created" btree (created_at DESC)
    "jobs_lease" btree (lease_expires_at) WHERE lease_expires_at IS NOT NULL
    "jobs_queue" btree (queue_seq) WHERE state = 'queued'::text
    "jobs_sha256" btree (sha256)
Check constraints:
    "jobs_state_check" CHECK (state = ANY (ARRAY['received'::text, 'admitted'::text, 'queued'::text, 'cloning'::text, 'preparing'::text, 'executing'::text, 'collecting'::text, 'cleaning'::text, 'completed'::text, 'rejected'::text, 'cancelled'::text, 'failed'::text, 'interrupted'::text]))
Triggers:
    jobs_notify AFTER INSERT OR UPDATE ON jobs FOR EACH ROW EXECUTE FUNCTION jobs_notify_state()
    jobs_touch BEFORE UPDATE ON jobs FOR EACH ROW EXECUTE FUNCTION jobs_touch_updated_at()

0001_jobs.sql
0002_triggers.sql
```

Four tables — `jobs`, `workers`, `worker_pipelines`, `schema_migrations` —
five indexes on `jobs` including the two partial ones, and both triggers
attached.

One check worth doing by hand, because it is the security property the schema
enforces rather than documents:

```bash
root@pve1:~# pct exec 102 -- su - platform -s /bin/bash -c '
  psql -d sandbox_platform -c "INSERT INTO jobs (target_os, submitted_filename) VALUES (\"linux\", \"x\")"
'
ERROR:  column "linux" does not exist
LINE 1: ...INTO jobs (target_os, submitted_filename) VALUES ("linux", "...
                   
# expect: ERROR: invalid input value for enum target_os: "linux"
```

**That is the wrong error, and the check did not actually run.** `column
"linux" does not exist` means psql never reached the enum: the quoting was
mangled through `pct exec` → `su` → `psql`, and by the time psql saw it,
`"linux"` was **double-quoted**, which in SQL is an *identifier* — a column
name — not a string literal. String literals take single quotes.

The command in this runbook could not have worked, and the failure it produced
looks enough like success to be worse than no check at all.

Reproduced and fixed in the development container 2026-08-22. Use a heredoc so
the SQL never passes through another layer of shell quoting:

```bash
pct exec 102 -- su - platform -s /bin/bash -c "psql -d sandbox_platform <<'SQL'
INSERT INTO jobs (target_os, submitted_filename) VALUES ('linux', 'x');
SQL"
# expect: ERROR:  invalid input value for enum target_os: "linux"
```

**Still owed.** That failure is issue #3's closed-set decision being enforced
by the database rather than merely documented. If the insert *succeeds*, the
column was created as text somewhere and the guarantee is gone — so this is
worth running properly rather than leaving on the assumption that the
migration did what it says.

Then snapshot again:

```bash
root@pve1:~# pct snapshot 102 schema-applied --description 'jobs schema at 0002' 
freeze guest filesystem
  WARNING: You have not turned on protection against thin pools running out of space.
  WARNING: Set activation/thin_pool_autoextend_threshold below 100 to trigger automatic extension of thin pools before they get full.
  Logical volume "snap_vm-102-disk-0_schema-applied" created.
  WARNING: Sum of all thin volume sizes (<6.10 TiB) exceeds the size of thin pool pve/data and the size of whole volume group (<1.82 TiB).
  WARNING: You have not turned on protection against thin pools running out of space.
  WARNING: Set activation/thin_pool_autoextend_threshold below 100 to trigger automatic extension of thin pools before they get full.
  Logical volume "snap_vm-102-disk-1_schema-applied" created.
  WARNING: Sum of all thin volume sizes (<6.35 TiB) exceeds the size of thin pool pve/data and the size of whole volume group (<1.82 TiB).
thaw guest filesystem
```


</details>
