# Runbook — provision the platform LXC on Proxmox (L0)

> **Status: EXECUTED on L0.** Steps 1–6 on 2026-08-22; steps 7–14 on
> 2026-08-23, after a rollback to `base-install`. Append-only evidence from
> here on: annotate, never rewrite.
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
