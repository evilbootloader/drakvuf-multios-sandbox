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
> **Steps 22–24 close #36.** The worker channel, the submission path, the SSE
> stream and the tunnel path are all evidenced. Three gaps found while closing
> it were fixed rather than recorded: `jobs.reap` had never been called, so
> the lease TTL did not run; submissions whose upload never completed were
> never expired; and the browser routes had no identity at all.
>
> **Still open after this runbook**, all on
> [#40](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/40):
> no rate limit or quota on job creation; every reader sees every submitter's
> jobs, because `visibility` is still a column nothing populates; and
> `reserved_ahead` reports plain queue position rather than the reservation
> its name promises. Also the decisions in "What is deliberately not in this
> runbook".
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

> **2026-08-24 (#37): that is now step 25**, and it also adds a quota and a
> 30-day lifecycle rule. Size the volume with those in mind.
>
> **Two paths, both correct.** `/srv/minio` here is the `mp0` **mount point**;
> `MINIO_VOLUMES` in step 19a is `/srv/minio/data`, a directory **inside** it.
> `df -h /srv/minio` therefore still reports the mp0 volume, which is what the
> check below is for. Step 4 does not create the `data` subdirectory — step
> 19a's MinIO does, on first start.

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
> [#40](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/40)
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

## Step 17 — Cloudflare: hostnames, Zero Trust, and the AUD

**This step is entirely in the Cloudflare dashboard.** It produces three
values the rest of the runbook needs, and it is worth doing in one sitting
because two of them are easy to look for in the wrong place later:

| Produces | Needed by |
|---|---|
| The two tunnel hostnames | Step 18 (`S3_PUBLIC_ENDPOINT`), step 20a (ingress) |
| `ACCESS_TEAM_DOMAIN` | Step 24 |
| `ACCESS_AUD` | Step 24 |

### 17a — the hostnames

`cloudflared` is configured in step 20a; this only fixes the names, because
they go into the API's configuration and the browser's upload URLs are signed
against them.

- `sandbox.evilbootloader.com` → the API
- `objects.evilbootloader.com` → MinIO

These names are not cosmetic. `S3_PUBLIC_ENDPOINT` in step 18 must be the
second one **exactly**, because SigV4 signs the Host header — a URL signed for
one name and presented at another fails with a 403 about the signature.

### 17b — the Zero Trust team domain

**Zero Trust → Settings → Custom Pages** (also under **Settings → General**).
It is your organisation name, and it makes `<team-name>.cloudflareaccess.com`.
On a first visit, the onboarding asks you to choose it.

**Pick it once.** Changing it later invalidates every Access session and every
`ACCESS_TEAM_DOMAIN` configured against it.

Verify it from the container rather than from the dashboard, because this is
the exact URL the API will fetch signing keys from:

```bash
pct exec 102 -- curl -s https://<team-name>.cloudflareaccess.com/cdn-cgi/access/certs | head -c 200
# expect JSON with a "keys" array. HTML or a 404 means the name is wrong.
```

`ACCESS_TEAM_DOMAIN` is that URL **with `https://` and no trailing slash** —
it is used both to fetch keys and as the expected `iss` claim, so a mismatch
fails every token.

### 17c — a login method

**Zero Trust → Settings → Authentication → Login methods → Add new.**

**One-time PIN has to be added as an identity provider; it is not there by
default.** Earlier drafts of this step said it was built in and always
present — on this account (2026-08-24) the list was empty until it was
created, and there is nothing to select in step 17d until one exists. It
needs no configuration beyond adding it, and emails a code.

GitHub or Google OAuth is a better long-term answer, because OTP proves only
that someone can read a mailbox. It adds a setup step you do not need to get
this working.

### 17d — the Access application

**Zero Trust → Access → Applications → Add an application → Self-hosted.**

- **Public hostname**: `sandbox.evilbootloader.com` — **and only that one.**
  Not `objects.*`; see the next section for why that breaks every upload.
- **Session duration**: 24h is reasonable.
- **Authentication → Accept all available identity providers**: **off.**
  Select One-time PIN explicitly. Identical today, since it is the only
  provider — the difference appears when a provider is added later for
  something unrelated and silently extends *this* application, the one
  fronting a malware store. An explicit list has to be edited on purpose.
- **Apply instant authentication**: on. Convenience only; it skips a chooser
  screen with one option.
- **Authenticate with Cloudflare One Client**: off. That is WARP device auth,
  which is a second way to satisfy authentication for no benefit here.

Then the **policy**, which is the part that actually gates:

- **Action**: Allow
- **Include** → **Emails** → your address

**The authentication section does not decide who gets in; the policy does.**
One-time PIN with `Include: Everyone` means anyone on the internet, because
OTP will happily mail a code to whatever address is typed. Use an explicit
email list, and prefer it over **Emails ending in** unless you genuinely want
everyone at that domain.

Prove it rather than assume it, because this is the only gate in front of the
control plane. In a private window, open `https://sandbox.evilbootloader.com`
and enter an address that is **not** in the policy.

> **Tested 2026-08-24: no email is sent at all.** Access evaluates the policy
> *before* issuing a code, rather than authenticating first and refusing
> after. Stronger than expected — this step originally predicted the code
> would arrive and the refusal would come later.
>
> It also means the OTP mailbox is never touched for an address that could
> not have been admitted, so the login page is not usable as a way to send
> mail to arbitrary recipients.

**If a code does arrive for an address you did not list, stop and fix the
policy.** OTP authenticates anyone who can read the mailbox they named; the
policy is the only thing turning that into a refusal.

### 17e — the AUD

Save the application, reopen it, and read **Application Audience (AUD) Tag**
from the **Overview** tab. That is `ACCESS_AUD` in step 24.

It is what stops a valid token issued for any *other* Access application in
the account from authenticating here. The API refuses to start the check at
all when it is unset, rather than skipping it — `test_access_jwt.py` covers
both the wrong-application token and the misconfiguration.

### Access goes on one hostname, not both

This said "put Access on both" until 2026-08-23. **That is wrong, and it would
have broken every upload** in a way that looks like a signing bug.

| Hostname | Cloudflare Access | Instead |
|---|---|---|
| `sandbox.evilbootloader.com` | **Yes** | — |
| `objects.evilbootloader.com` | **No** | Path-restricted ingress, step 20a |

**Why Access cannot go on the object store.** The browser uploads by POSTing a
presigned form **cross-origin**, from a page on `sandbox.*` to `objects.*`.
Access issues its authorisation cookie **per hostname**, so a user who
authenticated to `sandbox.*` has none for `objects.*`. Access answers that
POST with a 302 to its login page, and a cross-origin redirect to an HTML
login fails CORS. The browser reports a CORS error that never mentions Access.

**What leaving it off does and does not expose.** It does **not** make the
store readable: every object request needs a valid SigV4 signature, MinIO has
no anonymous bucket policy, and forging one means forging HMAC-SHA256. What it
exposes is MinIO's *other* surface — `/minio/admin/v3/*` reachable from the
internet, `/minio/health/*` unauthenticated by design, and version
fingerprinting from response headers. On a container holding live malware,
Postgres and the API's credentials, that is the part worth removing, and the
path rule in step 20a removes it without touching the upload path.

It also means **a leaked presigned URL is sufficient on its own**, with no
second factor. Containment is the TTL — 300s for artifacts, 900s for uploads —
and it matters because Cloudflare logs the full URL including the query
string, as does every other intermediary.

**Access on `sandbox.*` is what makes that acceptable.** Without a way to reach
`POST /api/v1/jobs`, an attacker cannot mint upload policies or list jobs to
discover artifact URLs in the first place. The API has **no application-layer
authentication of its own** ([#40](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/40)),
so Access there is not defence in depth — it is the only gate.

### Sharing the Access JWT with the object store — deferred, not rejected

Raised 2026-08-24: can the `sandbox.*` session be reused against `objects.*`,
so Access protects both without breaking the upload?

**Yes, and it would close the leaked-URL gap** — but only with four things
lined up, and each fails as a CORS error that names none of them:

1. **One Access application spanning both hostnames**, or a wildcard. Access
   scopes `CF_Authorization` to the application and puts that application's AUD
   in the JWT's `aud` claim; two applications means two cookies, and
   `sandbox.*`'s is not valid for `objects.*`. *Verify the cookie's actual
   domain in the dashboard rather than assuming the wildcard behaviour.*
2. **The preflight must bypass Access.** A cross-origin `fetch` carrying any
   custom header triggers an `OPTIONS` preflight, and **preflights never carry
   credentials** — so Access sees it unauthenticated and 302s it, killing the
   upload before the POST is sent. Access has a per-application CORS section
   for this. A presigned POST needs no custom header, so the preflight can be
   avoided entirely; that is easy to lose later.
3. **The client must opt in**: `fetch(url, {credentials: 'include'})`. The
   default omits the cookie cross-origin.
4. **MinIO's own CORS** must allow the `sandbox.*` origin with credentials.

**Deferred to [#38](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/38)**,
because three of the four live in the web page that does not exist yet, and
testing them without one means hand-rolling the exact request a browser would
send. The path rule below is the part that can be done now, has no client-side
dependency, and removes the surface that actually worries me.

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

> **Three credentials live in `/etc/cloudflared/` and they are not
> interchangeable.** Confusing them is easy because two are called
> "certificates":
>
> | File | What it is | Used by |
> |---|---|---|
> | `cert.pem` | Your **Cloudflare account** credential, from `tunnel login` | `tunnel create`, `route dns`, `tunnel delete` — management only |
> | `<UUID>.json` | The **tunnel's own** credential | `tunnel run`, at runtime |
> | `ca.crt` | **Our internal CA** | Verifying the origin's certificate |
>
> `originRequest.caPool` answers *"who signed the certificate that
> `192.168.1.10:9000` presents?"* — our CA, so `ca.crt`. Pointing it at
> `cert.pem` makes `cloudflared` reject the origin: that file is a credential
> *for* Cloudflare, not a trust anchor for anything here.
>
> `cert.pem` is not needed at runtime. Once the tunnel exists and its
> hostnames are routed, it can be removed and the tunnel keeps running —
> it is only required again to change the tunnel's registration.

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

Only the bucket is published. Everything else MinIO serves --
/minio/admin/v3/*, /minio/health/* -- stops existing from the internet's
point of view. See step 17: Access cannot go on this hostname without
breaking the cross-origin upload, so this rule is what replaces it.

(/|$) rather than a bare /analysis/ because the presigned POST targets
/analysis exactly, with no trailing slash -- and because ^/analysis alone
would also match a bucket named "analysis-something".

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
    path: ^/analysis(/|$)
    service: https://192.168.1.10:9000
    originRequest:
      caPool: /etc/cloudflared/ca.crt
  - hostname: objects.evilbootloader.com
    service: http_status:404

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
> [#40](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/40),
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
exposure #40 closes, and it is why Access on the tunnel is load-bearing rather
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
> [#40](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/40).

### The SSE stream

`--watch` follows the job over `LISTEN`/`NOTIFY` instead of polling. It blocks
on the stream, so start it *before* the worker, in a second terminal.

```bash
root@pve1:~# … submit.py … --target-os ubuntu --file /tmp/hello.txt --watch --wait 120
created 1e4991a2-cb4a-49d4-905c-1506b322e7ed for hello.txt (19 bytes)
admitted: state=queued sha256=af9c4ea0d7be30203e00346c79d1bdf645568614ab6ced2610fa3dbef406e890 type='ASCII text'
  -> cloning
  -> preparing
  -> executing
  -> collecting
  -> cleaning
  -> completed
```

> **PASS 2026-08-23.** Note `cloning`: the polled run in the previous section
> never saw that state, because it came and went between two one-second polls.
> That difference is the argument for the stream over polling, and it is why
> `X-Accel-Buffering: no` matters — a buffering proxy turns this into six
> lines arriving at once when the job finishes, which looks identical to a
> stalled analysis.

## Step 24 — the tunnel path, with Access

Steps 22 and 23 prove the platform over the LAN. This proves the path a
browser actually takes: Cloudflare, Access, JWT verification, and a presigned
upload signed for the **public** hostname.

Set `S3_PUBLIC_ENDPOINT=https://objects.evilbootloader.com` in `api.env` and
restart both listeners. Then configure Access per step 17 and wire it into the
**browser listener only** — a drop-in rather than `api.env`, because the two
listeners have different front doors:

```bash
pct exec 102 -- bash -lc '
  mkdir -p /etc/systemd/system/sandbox-api-browser.service.d
  cat > /etc/systemd/system/sandbox-api-browser.service.d/access.conf <<EOF
[Service]
Environment=REQUIRE_ACCESS_JWT=1
Environment=ACCESS_TEAM_DOMAIN=https://<team-name>.cloudflareaccess.com
Environment=ACCESS_AUD=<Application Audience tag>
EOF
  systemctl daemon-reload
  systemctl restart sandbox-api-browser'
```

> **`daemon-reload` is not enough — the unit must be restarted.** A drop-in
> reaches a *running* process only on restart, and the symptom is the check
> below returning 200 with everything looking correctly configured. Cost a
> round on 2026-08-24.

Verify the drop-in landed, and that it did **not** land on the mTLS unit:

```bash
root@pve1:~# pct exec 102 -- systemctl show sandbox-api-browser -p Environment --no-pager
Environment=REQUIRE_ACCESS_JWT=1 ACCESS_TEAM_DOMAIN=https://REDACTED.cloudflareaccess.com ACCESS_AUD=REDACTED
root@pve1:~# pct exec 102 -- systemctl show sandbox-api -p Environment --no-pager
Environment=
```

**The second one must be empty.** If `REQUIRE_ACCESS_JWT` leaks onto `8443`,
Dom0 and every command-line tool are locked out — they hold certificates, not
browser sessions.

### The check that matters

```bash
root@pve1:~# curl -s -o /dev/null -w "%{http_code}\n" https://sandbox.evilbootloader.com/api/v1/jobs
302
root@pve1:~# curl -s -H 'Cf-Access-Jwt-Assertion: garbage' \
     -o /dev/null -w "%{http_code}\n" https://192.168.1.10:8000/api/v1/jobs --insecure
401
```

The 302 only proves **Cloudflare** is doing its job. It says nothing about the
API, which is reachable on the LAN at `:8000` without traversing Cloudflare at
all — so the forged-header check on the second line is the one that proves the
signature is verified rather than the header believed.

### A submission through the tunnel

```bash
root@pve1:~# pct exec 102 -- su - platform -s /bin/bash -c 'cloudflared access login https://sandbox.evilbootloader.com'
Successfully fetched your token

root@pve1:~# pct exec 102 -- su - platform -s /bin/bash -c '
  cd /opt/platform/src/platform
  .venv/bin/python submit.py \
      --api https://sandbox.evilbootloader.com \
      --target-os ubuntu --file /tmp/hello.txt \
      --access-token "$(cloudflared access token -app=https://sandbox.evilbootloader.com)"
'
created ea349f49-dd9e-4ed4-9f61-b154b782e822 for hello.txt (19 bytes)
uploaded to https://objects.evilbootloader.com/analysis
admitted: state=queued sha256=af9c4ea0d7be30203e00346c79d1bdf645568614ab6ced2610fa3dbef406e890 type='ASCII text'
```

> **PASS 2026-08-24.** Three things this establishes that nothing on the LAN
> path could:
>
> 1. **`uploaded to https://objects.evilbootloader.com/analysis`** — the
>    presigned POST was signed for the public host and accepted there. SigV4
>    signs the Host header, so this is the check every earlier step warned
>    about and none of them ran.
> 2. **The `^/analysis(/|$)` path rule passes live traffic.** `tunnel ingress
>    rule` only evaluates the matcher offline.
> 3. **The Access JWT verifies and its identity is recorded.**

**No `--cacert` on this path.** Both hostnames present public Cloudflare
certificates, and `--cacert` **replaces** system trust rather than adding to
it — so passing the internal CA fails with `CERTIFICATE_VERIFY_FAILED` and an
error that names nothing useful. The LAN path still needs it, and that
asymmetry is the point of the two-endpoint design.

### The identity reaches the record

```bash
root@pve1:~# pct exec 102 -- su - platform -s /bin/bash -c "psql -d sandbox_platform <<'SQL'
SELECT substr(id::text,1,8) AS id, state, owner FROM jobs ORDER BY created_at;
SQL"
    id    |   state   |          owner
----------+-----------+--------------------------
 62f31c64 | completed |
 b7a83f7b | rejected  |
 1e4991a2 | completed |
 8e8c8ae4 | completed |
 08cc90bd | queued    |
 ea349f49 | queued    | evilbootloader@proton.me
(6 rows)
```

Only the job submitted through the tunnel has an owner. **The empty ones are
correct, not a defect**: those went over mTLS on `8443`, where a client
certificate identifies a *machine*. `owner` is for a person, and there isn't
one on that path.

`b7a83f7b` as `rejected` is the maintenance sweep — it sat in `received`
after its upload was refused by the size policy, and nothing expired it until
`maintenance.py` existed.

Then snapshot:

```bash
root@pve1:~# pct snapshot 102 api-deployed --description 'API on 8443 mTLS + 8000 behind Access, tunnel up'
freeze guest filesystem
  WARNING: You have not turned on protection against thin pools running out of space.
  WARNING: Set activation/thin_pool_autoextend_threshold below 100 to trigger automatic extension of thin pools before they get full.
  Logical volume "snap_vm-102-disk-0_api-deployed" created.
  WARNING: Sum of all thin volume sizes (6.36 TiB) exceeds the size of thin pool pve/data and the size of whole volume group (<1.82 TiB).
  WARNING: You have not turned on protection against thin pools running out of space.
  WARNING: Set activation/thin_pool_autoextend_threshold below 100 to trigger automatic extension of thin pools before they get full.
  Logical volume "snap_vm-102-disk-1_api-deployed" created.
  WARNING: Sum of all thin volume sizes (6.61 TiB) exceeds the size of thin pool pve/data and the size of whole volume group (<1.82 TiB).
thaw guest filesystem
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

- ~~**Bucket creation, policy, service account, CORS** — #37.~~ Now steps
  25–26, along with the quota, retention and the origin collapse.
- **TLS certificates and the mTLS trust anchor** — #36, which is where the
  worker token and the client certificate are defined together.
- **Backups.** Real work, and separate. Losing `/srv/minio` loses collected
  artifacts, which are reproducible only by re-running analyses.
- **Proxmox firewall rules.** Named as a prerequisite in `platform.md` and
  parked by the maintainer on 2026-08-21. Step 5 *observes* the posture; it
  does not enforce it.

# The object store — issue [#37](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/37)

> **EXECUTED on the deployment, 2026-08-24.** This section was written as a
> CANDIDATE — every command exercised first against a local MinIO
> (`RELEASE.2025-09-07`) and the platform test suite — and the transcripts
> below are the real run, all commands included. It is evidence now, on the
> same footing as steps 1–24.
>
> **Two of those checks pass by producing nothing**: the `objects` DNS
> negative and the CORS negative. They were run and they passed, but silence
> is a weak record — a reader later cannot tell an empty result from a command
> that was skipped. Both now carry an `exit=` echo so a re-run says so out
> loud. The empty transcripts below are the original, correct output.

Steps 4 and 15 stood up the minimum object store that unblocked the API and
said so, deferring policy, CORS and TTLs here. They are dated evidence of what
ran on 2026-08-23 and are **not** edited — this section supersedes them.

## Step 25 — provision the object store deliberately

The bucket, the policy, the service account, CORS, the quota and retention now
come from a script in the repository rather than from `mc` commands pasted out
of this document. That is the point: a policy that exists only as a heredoc in
a runbook has no copy a test can load and no way to be re-applied after a
rebuild. See `platform/minio/README.md` for the reasoning behind each grant.

Migration first — the per-job result budget needs its column:

```bash
root@pve1:~# pct exec 102 -- bash -lc '
  su - platform -s /bin/bash -c "cd /opt/platform/src/ && git pull --ff-only"
  su - platform -s /bin/bash -c "cd /opt/platform/src/platform && \
      DATABASE_URL=postgresql:///sandbox_platform .venv/bin/python migrations/run.py"                                                                           '
remote: Enumerating objects: 98, done.
remote: Counting objects: 100% (98/98), done.
remote: Compressing objects: 100% (26/26), done.
remote: Total 71 (delta 52), reused 64 (delta 45), pack-reused 0 (from 0)
Unpacking objects: 100% (71/71), 59.58 KiB | 635.00 KiB/s, done.
From github.com:evilbootloader/drakvuf-multios-sandbox
   fde4eff..1a1f027  master     -> origin/master
Updating fde4eff..1a1f027
Fast-forward
 .github/issue-drafts/DRAFT-044.md           | 109 +++++-
 .github/issue-drafts/DRAFT-047.md           |   4 +-
 .github/issue-drafts/issue-index.md         |  24 +-
 docs/architecture/platform.md               |  45 ++-
 docs/architecture/result-schema.md          |  15 +
 docs/runbooks/deploy-platform-lxc.md        | 584 ++++++++++++++++++++++++++--
 platform/fake_worker.py                     |  22 +-
 platform/migrations/0004_results_bytes.sql  |  45 +++
 platform/minio/README.md                    | 120 ++++++
 platform/minio/api-policy.json              |  15 +
 platform/minio/provision.sh                 | 228 +++++++++++
 platform/sandbox_platform/config.py         |  75 ++++
 platform/sandbox_platform/objects.py        |  76 ++--
 platform/sandbox_platform/routers/jobs.py   | 156 +++++++-
 platform/sandbox_platform/routers/worker.py | 157 +++++++-
 platform/submit.py                          |  32 +-
 platform/tests/conftest.py                  |  38 ++
 platform/tests/test_access_jwt.py           |  44 ++-
 platform/tests/test_jobs_api.py             | 198 +++++++++-
 platform/tests/test_objects.py              | 302 ++++++++++++++
 platform/tests/test_worker_api.py           | 252 +++++++++++-
 21 files changed, 2431 insertions(+), 110 deletions(-)
 create mode 100644 platform/migrations/0004_results_bytes.sql
 create mode 100644 platform/minio/README.md
 create mode 100644 platform/minio/api-policy.json
 create mode 100755 platform/minio/provision.sh
 create mode 100644 platform/tests/test_objects.py
applied  0004_results_bytes.sql

```

`mc` needs to be present; step 15 installed it. Then:

```bash
root@pve1:~# pct exec 102 -- bash -lc '
  set -a; . /etc/minio/minio.env; set +a
  BROWSER_ORIGIN=https://sandbox.evilbootloader.com \
  BUCKET_QUOTA=200GiB \
  RETENTION_DAYS=30 \
    /opt/platform/src/platform/minio/provision.sh
'

== alias -> https://127.0.0.1:9000
ok

== bucket analysis
Bucket created successfully `local/analysis`.

== anonymous access
Access permission for `local/analysis` is `private`

== versioning
local/analysis is un-versioned

== object lock
not enabled

== quota 200GiB
Bucket `analysis` has hard quota of 200 GiB

== retention: expire after 30 days
Lifecycle configuration imported successfully to `local/analysis`.
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│ Expiration for latest version (Expiration)                                                  │
├────────────────────────────┬─────────┬────────┬──────┬────────────────┬─────────────────────┤
│ ID                         │ STATUS  │ PREFIX │ TAGS │ DAYS TO EXPIRE │ EXPIRE DELETEMARKER │
├────────────────────────────┼─────────┼────────┼──────┼────────────────┼─────────────────────┤
│ sandbox-platform-retention │ Enabled │ -      │ -    │             30 │ false               │
└────────────────────────────┴─────────┴────────┴──────┴────────────────┴─────────────────────┘

RETENTION_DAYS must match RETENTION_DAYS in api.env, or the job
detail view will offer download links for objects MinIO has removed.

== CORS -> https://sandbox.evilbootloader.com
cors_allow_origin=https://sandbox.evilbootloader.com

== service account sandbox-platform-api
created. These go into /etc/sandbox-platform/api.env and are NOT
recoverable afterwards:

  S3_ACCESS_KEY=sandbox-platform-api
  S3_SECRET_KEY=REDACTED

== region
MINIO_SITE_REGION=eu-central-1

== done. S3_REGION in api.env must match the region above.
```

**Size `BUCKET_QUOTA` below the data volume**, so the store refuses writes
before the filesystem does — a full filesystem surfaces as a truncated
artifact at the end of an analysis that has already been paid for. `df -h
/srv/minio` from step 4 showed 251G (that is the `mp0` mount point; MinIO's
data directory is `/srv/minio/data` inside it, per step 19a). 200GiB leaves
headroom for the quota's own lag — see below.

The script is idempotent: re-running it after a partial failure is the
recovery path, not a hazard. It prints the service-account credentials **once**
and they are not recoverable — put them into `api.env` and add the two new
settings:

```bash
pct exec 102 -- bash -lc '
  cat >> /etc/sandbox-platform/api.env <<EOF

# Must match RETENTION_DAYS in step 25. The API does no deleting -- it uses
# this to know when NOT to offer a download link, because a job row is
# permanent and its objects are not.
RETENTION_DAYS=30

# Total result bytes one job may be issued upload tickets for.
MAX_JOB_RESULT_BYTES=4294967296
EOF
  # replace the step-15 service account with the one provision.sh minted
  sed -i "s|^S3_ACCESS_KEY=.*|S3_ACCESS_KEY=sandbox-platform-api|" \
      /etc/sandbox-platform/api.env
  # S3_SECRET_KEY: paste by hand. It contains + and / from base64.
  systemctl restart sandbox-api sandbox-api-browser
'
```

### Why the bucket quota is not the guard it looks like

Measured 2026-08-24 against a local MinIO: **3 MiB was written into a 1 MiB
quota and every write was accepted.** The same bucket refused ~45s later with
`XMinioAdminBucketQuotaExceeded`.

MinIO enforces quotas against usage statistics its background scanner
refreshes, not at write time. So the quota stops accumulation over days —
which is the real failure mode, results piling up — and permits an overshoot
bounded by write rate times scanner interval, which is not a documented
contract.

`MAX_JOB_RESULT_BYTES` is the prompt guard. It is checked when an upload
*ticket* is minted, before any bytes travel, because the API is not in the
upload path at all — the worker POSTs straight to MinIO. Keep the arithmetic
in view: **(jobs expected inside the retention window) × MAX_JOB_RESULT_BYTES
should stay under BUCKET_QUOTA**, or the store fills before retention reclaims
anything.

### Retention is lifecycle expiry, not object lock

The two are opposites sharing a word. **Object lock prevents deletion** for a
period and is asserted *off* by the script, because it would make retention
undecidable later — you cannot delete what is locked. **Lifecycle expiry
deletes** after one, and is what `RETENTION_DAYS` installs.

One rule over the whole bucket, not a shorter period for `samples/` and a
longer one for `results/`. That split is tempting and does not work:
`results/<job_id>/extracted/` is malware too, S3 lifecycle prefixes are
literal rather than globs, so `results/*/extracted/` cannot be expressed, and a
longer results period would keep dropped executables longer than the sample
they came from.

**The API is still delete-less.** MinIO does the expiring on its own schedule,
so retention costs the service account no destructive capability —
`DeleteObject` stays absent from `api-policy.json`.

### Verify

```bash
# the policy denies what it should. As the SERVICE ACCOUNT, not root.
root@pve1:~# pct exec 102 -- bash -lc '
  mc alias set svc https://192.168.1.10:9000 sandbox-platform-api "REDACTED"
  mc ls svc/analysis         ; echo "list  exit=$?  (expect NON-zero)"
  mc cp /etc/hostname svc/analysis/samples/probe/x
  echo "write exit=$?  (expect 0)"
  mc rm svc/analysis/samples/probe/x ; echo "del   exit=$?  (expect NON-zero)"
  mc alias rm svc
'
Added `svc` successfully.
mc: <ERROR> Unable to list folder. Access Denied.
list  exit=1  (expect NON-zero)
/etc/hostname: 9 B / 9 B ┃▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓┃ 911 B/s 0swrite exit=0  (expect 0)
mc: <ERROR> Failed to remove `svc/analysis/samples/probe/x`. Access Denied.
del   exit=1  (expect NON-zero)
Removed `svc` successfully.


# retention and quota are installed
root@pve1:~# pct exec 102 -- bash -lc 'mc ilm rule ls local/analysis; mc quota info local/analysis'
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│ Expiration for latest version (Expiration)                                                  │
├────────────────────────────┬─────────┬────────┬──────┬────────────────┬─────────────────────┤
│ ID                         │ STATUS  │ PREFIX │ TAGS │ DAYS TO EXPIRE │ EXPIRE DELETEMARKER │
├────────────────────────────┼─────────┼────────┼──────┼────────────────┼─────────────────────┤
│ sandbox-platform-retention │ Enabled │ -      │ -    │             30 │ false               │
└────────────────────────────┴─────────┴────────┴──────┴────────────────┴─────────────────────┘
Bucket `analysis` has hard quota of 200 GiB

# the region probe that actually works. `mc admin config get local region`
# reports EMPTY for an env-set value and is NOT a probe -- that is what made
# MINIO_SITE_REGION look unset through two investigations.
root@pve1:~# pct exec 102 -- bash -lc 'mc admin config get local site'
# MINIO_SITE_REGION=eu-central-1
site name= region= 
# expect a commented line: # MINIO_SITE_REGION=eu-central-1
```

## Step 26 — one origin: retire `objects.evilbootloader.com`

Step 17a gave MinIO its own hostname and step 20a routed it. That is dated
evidence and stays. This replaces it, and the reason is CORS.

**CORS keys on origin — scheme + hostname + port — not on host.** MinIO, the
API and the web UI all live on `192.168.1.10`, but a browser seeing
`sandbox.evilbootloader.com` and `objects.evilbootloader.com` has no idea they
are one container. Two names, two origins, and the browser upload becomes a
cross-origin request whose failure mode is nasty: it is CORS-safelisted, so
there is no preflight, so a wrong origin does not *prevent* the upload — MinIO
stores the object and answers 204 and the browser then refuses to expose the
response. The page reports a network error for an upload that succeeded.

MinIO uses **path-style** addressing, so every object URL already begins
`/analysis/`. Routing that path on the API's own hostname makes the whole flow
same-origin and deletes the problem rather than configuring around it:

```yaml
# /etc/cloudflared/config.yml
ingress:
  # bucket FIRST -- cloudflared matches in order
  - hostname: sandbox.evilbootloader.com
    path: ^/analysis(/|$)
    service: https://192.168.1.10:9000
    originRequest:
      caPool: /etc/cloudflared/ca.crt
  - hostname: sandbox.evilbootloader.com
    service: https://192.168.1.10:8000
    originRequest:
      caPool: /etc/cloudflared/ca.crt
  - service: http_status:404
```

`(/|$)` rather than a bare `/analysis/`, because the presigned POST targets
`/analysis` exactly — path-style POST carries the key in a form field, not the
path — and because `^/analysis` alone would also match a bucket named
`analysis-something`. Step 20a already reasoned this out; it carries over.

```bash
root@pve1:~# pct exec 102 -- bash -lc '
  cloudflared --config /etc/cloudflared/config.yml tunnel ingress validate
  sed -i "s|^S3_PUBLIC_ENDPOINT=.*|S3_PUBLIC_ENDPOINT=https://sandbox.evilbootloader.com|" \
      /etc/sandbox-platform/api.env
  systemctl restart cloudflared sandbox-api sandbox-api-browser
'
Validating rules from /etc/cloudflared/config.yml
OK
```

Then remove the `objects` public hostname from the tunnel and its DNS record
in the Cloudflare dashboard. **Do that last**, after the checks below pass.

### What this buys beyond deleting the CORS problem

**The store moves behind Access.** `objects.evilbootloader.com` was
internet-reachable, gated only by the path rule. Under one hostname the store
inherits the existing Access application — same app, same policy, **same
AUD**, nothing new to configure — so a presigned URL leaked outside the policy
is no longer usable through the tunnel at all.

Access was deliberately kept *off* the objects hostname in step 17 because a
cross-origin preflight would have received a 302 to the login page. Same-origin,
that objection disappears, which is why these two changes go together.

**The cost is a shared namespace.** No API or UI route may ever begin
`/analysis`, or cloudflared routes it to MinIO and the route silently stops
existing — in deployment only, surfacing as a 403 from MinIO about a
signature. `tests/test_objects.py::test_no_api_route_claims_the_bucket_prefix`
asserts this so #38 cannot introduce one.

### Verify

```bash
root@platform:/etc/sandbox-platform# TOKEN=$(cloudflared access token -app=https://sandbox.evilbootloader.com)
root@platform:/etc/sandbox-platform# curl -sI https://objects.evilbootloader.com/analysis; echo "exit=$?  (expect 6)"
exit=6  (expect 6)

root@platform:/etc/sandbox-platform# curl -so /dev/null -w '%{http_code}\n' \
     https://sandbox.evilbootloader.com/analysis       # expect: 302 to login
302
root@platform:/etc/sandbox-platform# curl -so /dev/null -w '%{http_code}\n' -H "cf-access-token: $TOKEN" \
     https://sandbox.evilbootloader.com/analysis       # expect: 403 from MinIO
403

```

**403 is the PASS on the third.** It means Access let the request through and
MinIO refused it unsigned, which is exactly right. A 302 there means the path
rule is not matching and the request reached the API instead.

```bash
root@platform:/etc/sandbox-platform# # CORS is scoped, not reflected. Defence in depth now rather than the fix:
# same-origin needs no CORS, but MinIO's default reflects ANY origin with
# Allow-Credentials: true, which would let a page at attacker.example holding
# a LEAKED presigned URL read the response.
curl -si -X OPTIONS https://sandbox.evilbootloader.com/analysis \
     -H "cf-access-token: $TOKEN" -H "Origin: https://evil.example" \
     -H "Access-Control-Request-Method: POST" \
  | grep -i access-control-allow-origin        # expect: NOTHING

```

### That check proved less than it looked like, and the follow-up found why

Run with the **allowed** origin instead of `evil.example`, the tunnel returns
nothing either:

```bash
root@platform:/opt/platform/src/platform# curl -si -X OPTIONS https://sandbox.evilbootloader.com/analysis \
     -H "cf-access-token: $TOKEN" \
     -H "Origin: https://sandbox.evilbootloader.com" \
     -H "Access-Control-Request-Method: POST" \
  | grep -i access-control-allow-origin
root@platform:/opt/platform/src/platform#
```

So the negative above was never evidence that `cors_allow_origin` was set —
**a typo in it would have passed identically.** Asking MinIO directly, on the
LAN, settles it:

```bash
root@platform:/opt/platform/src/platform# curl -si -X OPTIONS https://192.168.1.10:9000/analysis \
     --cacert /etc/sandbox-platform/tls/ca.crt \
     -H "Origin: https://sandbox.evilbootloader.com" \
     -H "Access-Control-Request-Method: POST" \
  | grep -i 'HTTP/\|access-control'
HTTP/1.1 204 No Content
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: POST
Access-Control-Allow-Origin: https://sandbox.evilbootloader.com
Vary: Origin, Access-Control-Request-Method, Access-Control-Request-Headers
```

**`cors_allow_origin` is correctly set and working at the origin.** What is
happening is that **Cloudflare Access answers the `OPTIONS` preflight itself**
— it must, or a preflight would receive a login redirect — and its reply does
not carry the origin's CORS headers. They never reach the browser.

Three consequences, and none of them is a problem today:

- **The effective posture through the tunnel is stricter than origin-scoped.**
  No `Access-Control-Allow-Origin` for *any* origin means a browser refuses
  every cross-origin read of the store.
- **Nothing in the current design depends on it.** #37 made the flow
  same-origin, so the browser sends no preflight and consults no CORS headers.
- **`cors_allow_origin` still earns its place**, but at the origin rather than
  through the tunnel: anything reaching `192.168.1.10:9000` directly — a
  browser on the LAN — gets the scoped header instead of MinIO's reflect-any
  default.

> **Carry this into [#38](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/38):
> CORS headers do not survive this tunnel.** If the web UI is ever served from
> a different hostname than the store, it will not work, and the failure will
> look like a network error rather than a configuration one. Keep it
> same-origin.

It does **not** stop `curl` with a leaked presigned URL. Nothing does, until
the TTL expires — CORS is a control on which *pages* may read a response, not
on who may make the request.

### The whole path, end to end

```bash
# submission. --access-token now covers the upload leg too, because the store
# is behind Access. This is also true of a LAN submission: presigned_upload
# always signs for the browser audience, so an mTLS submission's upload still
# leaves the LAN and returns through Cloudflare.
root@platform:/opt/platform/src/platform# .venv/bin/python submit.py --api https://sandbox.evilbootloader.com --target-os ubuntu     --file /tmp/hello.txt --watch --wait 300 --access-token "$TOKEN"
created 8b1d9e23-9798-44a8-97bd-35a53c33ab0e for hello.txt (19 bytes)
uploaded to https://sandbox.evilbootloader.com/analysis
admitted: state=queued sha256=af9c4ea0d7be30203e00346c79d1bdf645568614ab6ced2610fa3dbef406e890 type='ASCII text'
  -> cloning
  -> preparing
  -> executing
  -> collecting
  -> cleaning
  -> completed
{
  "id": "8b1d9e23-9798-44a8-97bd-35a53c33ab0e",
  "created_at": "2026-08-24T19:48:01.824406Z",
  "target_os": "ubuntu",
  "submitted_filename": "hello.txt",
  "state": "completed",
  "sha256": "af9c4ea0d7be30203e00346c79d1bdf645568614ab6ced2610fa3dbef406e890",
  "size_bytes": 19,
  "owner": "evilbootloader@proton.me",
  "updated_at": "2026-08-24T19:48:02.674731Z",
  "detected_type": "ASCII text",
  "queue_reason": null,
  "failure_stage": null,
  "failure_reason": null,
  "attempt": 1,
  "cancel_requested": false,
  "manifest": {
    "artifacts": [
      "trace.log",
      "capture.pcap",
      "manifest.json"
    ]
  },
  "artifacts": {
    "trace.log": "https://sandbox.evilbootloader.com/analysis/results/8b1d9e23-9798-44a8-97bd-35a53c33ab0e/trace.log?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=sandbox-platform-api%2F20260824%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20260824T194802Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=4269f7d40651260753f524999901216b0c448342c8c85d1862877086b375ada4",
    "capture.pcap": "https://sandbox.evilbootloader.com/analysis/results/8b1d9e23-9798-44a8-97bd-35a53c33ab0e/capture.pcap?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=sandbox-platform-api%2F20260824%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20260824T194802Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=bf5cc46c703dab40a0c9628c956cfdfa69a0344952c2291edc8ad38654428eaf",
    "manifest.json": "https://sandbox.evilbootloader.com/analysis/results/8b1d9e23-9798-44a8-97bd-35a53c33ab0e/manifest.json?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=sandbox-platform-api%2F20260824%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20260824T194802Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=8c625990b97e633da767cbd81b887e662c1704ebf45c9666802da2c9a12e11e6"
  },
  "artifacts_expired": false,
  "reserved_ahead": false
}



root@platform:/etc/sandbox-platform# . api.env; /opt/platform/src/platform/.venv/bin/python /opt/platform/src/platform/fake_worker.py --api https://192.168.1.10:8443 --token "$WORKER_TOKEN"     --cacert tls/ca.crt --cert tls/fake-worker.crt --key tls/fake-worker.key --once
registered as fake-worker, offering 12082 MiB
leased 8b1d9e23-9798-44a8-97bd-35a53c33ab0e (ubuntu) 'hello.txt' attempt 1
  fetched 19 bytes
  -> preparing
  -> executing
  -> collecting
  -> cleaning
  uploaded 3 artifacts
  -> completed

```

Confirm `capture.pcap` lands at **0 bytes**. An empty capture is a real result
— it means the clone generated no traffic — and the artifact upload policy
starts its size range at 0 for exactly that reason, where the sample policy
starts at 1.

### Run the worker WITHOUT `--once` when you are testing a submission

`--once` claims the **head of the queue** by `queue_seq`, not the job you just
submitted. With anything queued from an earlier session, each run drains a
backlog entry while the new submission waits behind it — which on 2026-08-24
looked exactly like a broken `--watch` and cost an evening. Two submissions
timed out at 300s and completed normally once the backlog cleared.

Drop `--once` and the worker long-polls, taking each job as it arrives:

```bash
. api.env; /opt/platform/src/platform/.venv/bin/python \
  /opt/platform/src/platform/fake_worker.py --api https://192.168.1.10:8443 \
  --token "$WORKER_TOKEN" --cacert tls/ca.crt \
  --cert tls/fake-worker.crt --key tls/fake-worker.key
```

**Five consecutive submissions with `--watch --wait 300` completed cleanly
against that**, 2026-08-24, after the SSE snapshot fix in `a0ddb21`.

`submit.py` now says which of the two is happening rather than printing a bare
`timed out after 300.0s`: it names the state, and distinguishes "another job
is reserved ahead of this one" from "nothing is ahead and no worker claimed
it". The queue was never the bug; the silence was.

# The web UI — issue [#38](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/38)

> **EXECUTED on the deployment, 2026-08-25.** Written as a candidate and run
> the same day; the transcripts below are the real output. One instruction in
> it was wrong and has been replaced with the reason not to follow it — see
> "Do not run the test suite here".

## Step 27 — deploy the UI shell

#38 adds the operator-facing UI: submit, history, and a per-job report with a
tab framework. It is served by the **same** API process under `/ui`, so there
is no new service, no second port and no reverse proxy.

### Nothing changes on the Cloudflare side, and that is worth checking rather than assuming

Step 26's ingress sends `^/analysis(/|$)` to MinIO and **everything else** to
the API on 8000. `/ui` is "everything else", so it is already routed and
already behind the Access application covering the hostname. No tunnel change,
no DNS change, no new Access app.

The one thing to keep in mind: `/analysis` is matched **first**. Any future UI
route beginning `/analysis` would silently go to MinIO instead — which is why
`platform/tests/test_objects.py::test_no_api_route_claims_the_bucket_prefix`
exists and fails if one appears.

### Pull and install

```bash
root@pve1:~# pct exec 102 -- su - platform -s /bin/bash -c '
  cd /opt/platform/src && git pull --ff-only
  cd /opt/platform/src/platform && .venv/bin/pip install -r requirements.txt
'
Updating a0ddb21..232740b
Fast-forward
 platform/sandbox_platform/catalogue.py             | 202 ++++++++++
 platform/sandbox_platform/ui/__init__.py           | 237 +++++++++++
 platform/sandbox_platform/ui/static/app.css        | 307 ++++++++++++++
 platform/sandbox_platform/ui/static/htmx.min.js    |   1 +
 platform/sandbox_platform/ui/static/submit.js      | 138 +++++++
 ...
 41 files changed, 6340 insertions(+), 38 deletions(-)

Downloading playwright-1.62.0-py3-none-manylinux1_x86_64.whl (47.7 MB)
Successfully installed MarkupSafe-3.0.3 charset_normalizer-3.5.1 greenlet-3.5.5
  jinja2-3.1.6 playwright-1.62.0 pyee-13.0.1 pytest-base-url-2.1.0
  pytest-playwright-0.9.0 python-slugify-8.0.4 requests-2.34.2 text-unidecode-1.3
```

> **47.7 MB of Playwright landed on the deployment, and that is worth
> revisiting.** `pytest` was already in `requirements.txt`, so test tooling
> here is an existing decision — but that decision looks different at 47 MB
> than it did at a few hundred kilobytes, on a container whose security
> argument is that it holds every credential and therefore stays small.
> **Splitting `requirements.txt` into runtime and dev would fix it**, and
> would make the rule below structural instead of advisory. Not done here;
> recorded so it is a decision rather than an accumulation.

> **The container runs Python 3.13; the development container runs 3.14.**
> Nothing here is version-sensitive and both are supported, so this is not a
> fault. It is recorded because it means the development container is not
> quite reproducing the deployment, which is the sort of gap that eventually
> explains a mystery.

`jinja2` is the only new **runtime** dependency — the UI is server-rendered so
that autoescaping is structural rather than remembered.

**`pytest-playwright` is also in `requirements.txt` and that is deliberate**,
consistent with `pytest` already being there: the suite runs against the real
Postgres and MinIO, which is the whole reason those tests are worth having.
What must **not** be run here is:

```bash
# DO NOT run on the deployment
.venv/bin/playwright install chromium
```

That downloads a 115 MB browser. The browser tests belong in development;
`pytest.importorskip` makes them skip loudly here rather than fail.

### Restart both listeners

```bash
root@pve1:~# pct exec 102 -- systemctl restart sandbox-api sandbox-api-browser
root@pve1:~# pct exec 102 -- systemctl is-active sandbox-api sandbox-api-browser
active
active
```

**Both, not one.** `sandbox-api` is the mTLS listener Dom0 uses and
`sandbox-api-browser` is the one behind the tunnel; they are separate
processes of the same application, and restarting only the browser listener
leaves Dom0 running yesterday's code.

> **Python changes need a restart; templates do not.** Jinja reloads templates
> from disk per request, so a running server picks up template edits and keeps
> serving stale Python. That combination produced a page rendering new markup
> against old context data during development, with no error — every tab
> marked empty because the variable that says otherwise did not exist yet.
> If a change looks half-applied, restart before investigating anything else.

### Verify

```bash
TOKEN=$(cloudflared access token -app=https://sandbox.evilbootloader.com)

# the views, and the static assets the app serves itself
for p in /ui/submit /ui/jobs /ui /ui/static/app.css /ui/static/htmx.min.js; do
  printf '%-26s ' "$p"
  curl -so /dev/null -w '%{http_code}\n' -H "cf-access-token: $TOKEN" \
       "https://sandbox.evilbootloader.com$p"
done
/ui/submit                 200
/ui/jobs                   200
/ui                        200
/ui/static/app.css         200
/ui/static/htmx.min.js     200

# still behind Access, with no token
curl -so /dev/null -w 'no token   %{http_code}  (expect 302)\n' \
     https://sandbox.evilbootloader.com/ui/jobs
no token   302  (expect 302)

# the object store still wins the /analysis prefix
curl -so /dev/null -w '/analysis  %{http_code}  (expect 403 from MinIO)\n' \
     -H "cf-access-token: $TOKEN" https://sandbox.evilbootloader.com/analysis
/analysis  403  (expect 403 from MinIO)
```

**403 on the last one is the PASS**, for the same reason as step 26: Access
let the request through and MinIO refused it unsigned. A 302 there would mean
the path rule stopped matching and the UI had swallowed the prefix.

### The bare hostname

`/` was a 404 when this step was first run — cloudflared routes everything
except `/analysis*` to the API, and the API had no root of its own, so typing
the hostname produced an error page from a service that was working perfectly.
It now redirects:

```bash
curl -so /dev/null -w '/ -> %{redirect_url}  (%{http_code})\n' \
     -H "cf-access-token: $TOKEN" https://sandbox.evilbootloader.com/
# expect: https://sandbox.evilbootloader.com/ui  (302)
```

**302 rather than 308**, deliberately. A permanent redirect is cached hard by
browsers and would make `/` awkward to reclaim later — for a landing page, or
a public report index (DRAFT-053). One redirect per visit, decision
reversible.

Confirm the vendored htmx is the file that was reviewed:

```bash
root@pve1:~# pct exec 102 -- sha256sum \
    /opt/platform/src/platform/sandbox_platform/ui/static/htmx.min.js
e209dda5c8235479f3166defc7750e1dbcd5a5c1808b7792fc2e6733768fb447  /opt/platform/src/platform/sandbox_platform/ui/static/htmx.min.js
```

Matches `ui/static/VENDOR.md`.

It is the only third-party front-end code in the project;
`ui/static/VENDOR.md` records why one was accepted at all.

### Then look at it

Open `https://sandbox.evilbootloader.com/ui/jobs` in a browser. The jobs from
step 26 should be listed. Two things worth confirming by eye rather than by
`curl`:

- **A hostile filename renders as text.** Submit one — `<script>alert(1)` is
  admitted deliberately, because the name must reach the guest byte-exact.
  Nothing should execute, and the name should appear intact.
- **A Ubuntu job has no Registry tab, and a Windows job does.** The tab list
  is computed from the guest's plugin support; `regmon` is Windows-only, so a
  Registry tab on Ubuntu could never be filled.

### Do not run the test suite here

The candidate version of this step said to run `pytest` on the container and
expect the browser tests to skip. **That was wrong, and running it produced
312 errors** — every test failing at setup, because the session fixture
migrates a database called `sandbox_platform_test` which does not exist here:

```bash
root@pve1:~# pct exec 102 -- su - platform -s /bin/bash -c '
  cd /opt/platform/src/platform && .venv/bin/python -m pytest -q 2>&1 | head -40
'
EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE [ 23%]
...
    @pytest.fixture(scope="session", autouse=True)
    def migrated() -> None:
>       subprocess.run(
            [sys.executable, str(PLATFORM_DIR / "migrations" / "run.py")],
            env={**os.environ, "DATABASE_URL": DSN},
            check=True,
            capture_output=True,
        )
312 errors in 3.36s
```

**The obvious fix is to create that database. Do not.** Look at what the
`conn` fixture does before every single test:

```python
c.execute("TRUNCATE jobs, worker_pipelines, workers RESTART IDENTITY CASCADE")
```

The default DSN is the test database, so it is safe as written — but one
mistyped `TEST_DATABASE_URL` on this container and the entire job history is
gone, with no recovery. That risk buys nothing: the suite already runs against
a real Postgres and a real MinIO in the development container, and running it
here adds only "the same code on the same OS", which the checks above already
established.

**What verifies this deployment is the curl output and the browser**, not
pytest.

> **A defect this exposed, since fixed.** `conftest.py` used
> `check=True, capture_output=True`, which raises a `CalledProcessError` whose
> message names the command and *discards the runner's stderr* — so every test
> errored with no reason given, and finding the cause took a second run with
> `head -40`. It now fails with the DSN it tried, the command to create it,
> and the runner's actual output.

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
