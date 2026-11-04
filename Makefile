SHELL	:= /bin/bash
.ONESHELL:

# Host-specific values -- the analysis user and its password, the operator's
# SSH key, the addresses -- belong in an UNTRACKED `Makefile.local` beside
# this file (2026-11-03). It is read first, and every default below yields to
# it (`?=`). Until then Dom0 carried its own values as a local commit on this
# file, which blocked every `git pull --ff-only` and put a password and a key
# into a tracked file; `scripts/check-secrets.sh` does not read a Makefile.
-include Makefile.local

VM      ?= platform
CFG     ?= misc/xen-vms/platform.cfg
VMADDR	?= 192.168.1.12/24
VMIP := $(firstword $(subst /, ,$(VMADDR)))
VMROUTE	?= 192.168.1.1
RSA_KEY	?=
SANDBOX_WEB ?= sandbox.evilbootloader.com
GARAGE_V ?= v2.4.1
# Garage publishes no checksum file (migrate-object-store-to-garage.md probed
# for one on 2026-10-02). This is the sha256 of the v2.4.1 musl binary as
# downloaded on 2026-10-02 and again on 2026-11-03, on two machines, and it is
# what the platform runs. Bumping GARAGE_V means downloading, hashing and
# recording the new one here first; until 2026-11-03 the hash was only printed
# (review M-1).
GARAGE_SHA256 ?= ae49f8de4aaee6b5ca305f7cbdccc8cd8a29b2804aac074649f18bfb83d0a2b6
S3_QUOTA ?= 400
S3_RETENTION ?= 30
SANDBOXDIP ?= 192.168.1.6
ANALYSIS_VM_PASS ?= malware
ANALYSIS_VM_USER ?= user
REPO_ROOT := $(shell pwd)
# Xen boot line, see docs/CURRENT-STATE.md §1.2
XEN_CMDLINE := dom0_mem=8192M,max:8192M dom0_max_vcpus=6 dom0_vcpus_pin=1 force-ept=1 ept=ad=0 hap_1gb=0 hap_2mb=0 altp2m=1 hpet=legacy-replacement smt=0 sched=credit rdtsc-poc=1
# Parallel vm_event processing deadlocks dom0 without it:
# https://lists.xenproject.org/archives/html/xen-devel/2026-10/msg01125.html
XEN_PATCH := $(REPO_ROOT)/automation/xen-altp2m-pause-vcpu.patch
# RDTSC compensation for the analysis guests (rdtsc-poc=1 above, and the 'd' key
# xen-rdtsc-poc.service presses at boot): docs/architecture/rdtsc-poc.md
XEN_RDTSC_PATCH := $(REPO_ROOT)/automation/xen-rdtsc-poc.patch
# SMBIOS hardware from smbios_firmware, no hypervisor leaves without the hypervisor bit;
# scripts/xen-identity.py then writes this deployment's identity over Xen's own strings,
# and its firmware files and lines into the guests' configs: docs/architecture/guest-identity.md
XEN_IDENTITY_PATCH := $(REPO_ROOT)/automation/xen-guest-identity.patch
# QEMU's CD-ROM answers INQUIRY with its ide-cd.model instead of "QEMU QEMU DVD-ROM";
# applied to the qemu-xen tree the Xen build clones
QEMU_CDROM_PATCH := $(REPO_ROOT)/automation/qemu-xen-cdrom-inquiry.patch
XEN_IDENTITY := $(REPO_ROOT)/scripts/xen-identity.py
# The guests' firmware files, from the identity (not tracked, like the identity)
GUEST_FIRMWARE := $(REPO_ROOT)/state/firmware
# OVMF is built from tianocore's edk2 instead of the xenbits mirror Config.mk names
OVMF_URL := https://github.com/tianocore/edk2.git
OVMF_REVISION := 4dfdca63a93497203f197ec98ba20e2327e4afe4
# volatility3 PR #650 (pdbconv with C++ types) is unmerged and its head is a
# personal fork's branch, so it is fetched by commit: a push there installs nothing
VOLATILITY3_PR650 := 7fe200e5f4611a676299dd67fd435a8dd9bec6e7
# Microsoft only serves the current Windows 11, so 23H2 comes from a mirror.
# Microsoft's SHA-256 for 23H2 English International x64, as reproduced at
# release by ginjfo.com and iguru.gr; Dom0's copy matched it 2026-10-24
WIN_ISO_URL := https://archive.org/download/win-11-23-h-2-english-international-x-64/Win11_23H2_EnglishInternational_x64.iso
WIN_ISO_SHA256 := 0eea13c537e39cd1631b1758cd98847cf0d88bd0c32a8d69d9a02723ae79a612
UBUNTU_ISO_URL := https://releases.ubuntu.com/jammy/ubuntu-22.04.5-live-server-amd64.iso
# From releases.ubuntu.com/jammy/SHA256SUMS, whose SHA256SUMS.gpg verified on
# 2026-11-03 against the Ubuntu CD Image Automatic Signing Key (2012),
# 8439 38DF 228D 22F7 B374 2BC0 D94A A3F0 EFE2 1092. Checked before every use,
# not only after a download (review M-1).
UBUNTU_ISO_SHA256 := 9bc6028870aef3f74f4e16b900008179e78b130e6b0b9a140635434a46aa98b0
# FakeNet-NG: the commit tag v3.5 named on 2026-11-03. A tag can be moved, a
# commit cannot, so the install names the commit (review M-1).
FAKENET_COMMIT := 82c01b00f8da2f29fc4ae77c6f5546bb26dd8904
# What the platform DomU checks out: this checkout's HEAD. It must be pushed,
# since the DomU fetches it from GitHub, and web_sandbox fails at the checkout
# when it is not. Until 2026-11-03 the DomU got whatever the default branch's
# tip was at the time, reviewed or not (review M-1).
PLATFORM_SHA ?= $(shell git -C $(REPO_ROOT) rev-parse HEAD)
# The installers vendored into the modified ISO: automation/win-installers.list
# names each file, its SHA-256 and where it comes from.
WIN_INSTALLERS := $(REPO_ROOT)/misc/iso/win-installers
WIN_INSTALLERS_LIST := $(REPO_ROOT)/automation/win-installers.list
# The installers' mirror (2026-11-04): a static directory the platform's nginx
# serves to Dom0 over the internal CA, automation/win-installers-mirror.conf.
# `win_installers` fetches each file from here first and from the vendor's URL
# only when the mirror has no such file or is not there yet; the hash check is
# the same either way. `win_installers_mirror` publishes Dom0's verified cache
# to it. Why: Chrome's URL is an unversioned redirect, and the first Dom0 run
# refused the build one day after the pin because Google had shipped a release
# in between (docs/TROUBLESHOOTING.md, "make win_installers refuses the
# build"). With the mirror, what the image gets is what this lab verified
# once, not what a vendor serves today. Empty disables it.
INSTALLERS_MIRROR ?= https://$(VMIP):9100/win-installers
INSTALLERS_MIRROR_CA ?= /etc/sandboxd/tls/ca.crt
INSTALLERS_MIRROR_DIR := /srv/vendor/win-installers
INSTALLERS_MIRROR_CONF := $(REPO_ROOT)/automation/win-installers-mirror.conf

.PHONY: xen web_vm web_sandbox sandboxd win_installers win_installers_mirror

xen:
	@echo "Building and installing Xen with the altp2m deadlock fix and RDTSC compensation, then reboot into it"
	set -e; \
	# Build Xen as from a shell, not as a sub-make of this one: a sub-make prints its \
	# directories, docs/Makefile reads the Xen version from a nested make's output, and \
	# pod2man then fails on --release=make[2]: Entering directory ... \
	unset MAKEFLAGS MFLAGS MAKELEVEL; \
	sudo apt-get install -y wget git bcc bin86 gawk bridge-utils iproute2 libcurl4-openssl-dev bzip2 libpci-dev build-essential make gcc clang libc6-dev linux-libc-dev zlib1g-dev libncurses5-dev patch libvncserver-dev libssl-dev libsdl-dev iasl libbz2-dev e2fslibs-dev git-core uuid-dev ocaml libx11-dev bison flex ocaml-findlib xz-utils gettext libyajl-dev libpixman-1-dev libaio-dev libfdt-dev cabextract libglib2.0-dev autoconf automake libtool libjson-c-dev libfuse-dev liblzma-dev autoconf-archive kpartx python3-dev python3-pip golang libsystemd-dev nasm ninja-build llvm lld; \
	sudo apt-get install -y python3-pefile python3-construct; \
	cd $(REPO_ROOT); \
	git submodule update --init drakvuf; \
	cd drakvuf; \
	git submodule update --init xen; \
	cd xen; \
	# From the pinned commit every time: the identity rewrites strings the patches leave \
	git checkout -- .; \
	git apply $(XEN_PATCH); \
	git apply $(XEN_RDTSC_PATCH); \
	git apply $(XEN_IDENTITY_PATCH); \
	python3 $(XEN_IDENTITY) patch-xen .; \
	sed -i -e 's|^OVMF_UPSTREAM_URL ?= .*|OVMF_UPSTREAM_URL ?= $(OVMF_URL)|' \
		-e 's|^OVMF_UPSTREAM_REVISION ?= .*|OVMF_UPSTREAM_REVISION ?= $(OVMF_REVISION)|' Config.mk; \
	grep -qx 'OVMF_UPSTREAM_REVISION ?= $(OVMF_REVISION)' Config.mk; \
	./configure --enable-githttp --enable-systemd --enable-ovmf --disable-pvshim; \
	# qemu-xen is cloned by the build, at its pin, so clone it now and patch it, \
	# from the pinned commit every time as the Xen tree is \
	make -C tools qemu-xen-dir-find; \
	git -C tools/qemu-xen-dir-remote checkout -- .; \
	git -C tools/qemu-xen-dir-remote apply $(QEMU_CDROM_PATCH); \
	make -j$$(nproc) dist-xen; \
	make -j$$(nproc) dist-tools; \
	make -j$$(nproc) debball; \
	# Anchored (2026-11-03). An argument that names no package and contains \
	# '*' is a POSIX regex to apt, matched as a SUBSTRING of every package \
	# name: 'xen*' is "xe, then any number of n", which selects libxext6, \
	# exempi and whatever else has "xe" in its name, with -y, and the \
	# || true hid the outcome. '^xen-' and '^libxen' select the distro's Xen \
	# packages and nothing else; the || true stays because a host with no \
	# such packages makes apt exit non-zero, and that is not a failure here. \
	sudo apt-get remove -y '^xen-' '^libxen' || true; \
	sudo apt install -y ./dist/xen*.deb; \
	# The boot line and Xen as the default entry, in the file grub-mkconfig reads last \
	sudo install -d /etc/default/grub.d; \
	sed 's|@XEN_CMDLINE@|$(XEN_CMDLINE)|' $(REPO_ROOT)/automation/xen-grub.cfg | sudo tee /etc/default/grub.d/xen.cfg >/dev/null; \
	sudo sed -i '/^GRUB_CMDLINE_XEN_DEFAULT=/d' /etc/default/grub; \
	echo "/usr/local/lib" | sudo tee /etc/ld.so.conf.d/xen.conf >/dev/null; \
	sudo ldconfig; \
	grep -qxF "none /proc/xen xenfs defaults,nofail 0 0" /etc/fstab || \
		echo "none /proc/xen xenfs defaults,nofail 0 0" | sudo tee -a /etc/fstab >/dev/null; \
	for m in xen-evtchn xen-privcmd xen-gntdev; do \
		grep -qx "$$m" /etc/modules || echo "$$m" | sudo tee -a /etc/modules >/dev/null; \
	done; \
	# xenstored.service, not xencommons.service (2026-11-03). The tree ships \
	# no xencommons unit: that name is the init script systemd's generator \
	# wraps, which repeats what the units already did and fails on every \
	# boot -- automation/xen-rdtsc-poc.service has carried that note since it \
	# was written, and the poc unit itself Requires xenstored.service. \
	sudo systemctl enable xenstored.service; \
	sudo systemctl enable xen-qemu-dom0-disk-backend.service; \
	sudo systemctl enable xen-init-dom0.service; \
	sudo systemctl enable xenconsoled.service; \
	# rdtsc-poc=1 makes the guests' RDTSCs exit; the 'd' key, once per boot, compensates them \
	sudo install -m 0644 $(REPO_ROOT)/automation/xen-rdtsc-poc.service /etc/systemd/system/xen-rdtsc-poc.service; \
	sudo systemctl daemon-reload; \
	sudo systemctl enable xen-rdtsc-poc.service; \
	sudo update-grub2; \
	sudo grep -q "multiboot2.*altp2m=1" /boot/grub/grub.cfg || { echo "update-grub2 wrote no Xen entry"; exit 1; }; \
	sudo grep -q "multiboot2.*rdtsc-poc=1" /boot/grub/grub.cfg || { echo "the Xen entry has no rdtsc-poc=1"; exit 1; }; \
	echo "Xen installed, reboot to start it"

web_vm:
	@echo "Installing $(VM)..."
	# One shell for the whole recipe (.ONESHELL) and no && between its steps:
	# until 2026-11-03 a failed lvcreate was ignored and mkfs ran on the
	# volumes that already existed. The first failure now ends the run.
	set -e

	# The operator's public key, from Makefile.local. Refused here, before any
	# volume is touched: without it `make web_sandbox` has no way into the DomU.
	test -n '$(RSA_KEY)' || { echo "RSA_KEY is empty: put the operator's public key in Makefile.local, e.g. RSA_KEY := ssh-ed25519 AAAA... root@dom0" >&2; exit 1; }

	sudo apt install -y lvm2 debootstrap

	# The thin pool every guest volume lives in, created once, here, before
	# the first volume that needs it. Until 2026-11-03 it was created at the
	# END of `make sandboxd`, which failed on every re-run of that target.
	sudo lvs vg-root/thinpool >/dev/null 2>&1 || sudo lvcreate --type thin-pool -l 90%FREE --poolmetadatasize 16G -n thinpool vg-root

	# This target builds a NEW platform. A second run must never reach mkfs:
	# it would format the platform's root and the 512 G object store, which
	# the kernel refuses only while the DomU holds them open. Removing the
	# volumes is a deliberate act done by hand, never a side effect of make.
	for lv in $(VM) $(VM)_data; do if sudo lvs vg-root/$$lv >/dev/null 2>&1; then echo "vg-root/$$lv exists: refusing to build over a platform. To rebuild from nothing: xl destroy $(VM); lvremove vg-root/$(VM) vg-root/$(VM)_data -- by hand, on purpose." >&2; exit 1; fi; done

	sudo lvcreate -V 20G  --thin -n $(VM) vg-root/thinpool
	sudo lvcreate -V 512G --thin -n $(VM)_data vg-root/thinpool

	sudo mkfs.ext4 -L $(VM)-root /dev/vg-root/$(VM)
	sudo mkfs.ext4 -T largefile -L $(VM)-data /dev/vg-root/$(VM)_data

	sudo mkdir -p /mnt/$(VM)
	sudo mount /dev/vg-root/$(VM) /mnt/$(VM)

	sudo debootstrap \
		--arch=amd64 \
		trixie \
		/mnt/$(VM) \
		http://deb.debian.org/debian/

	for d in dev dev/pts proc sys; do
		sudo mount --bind /$$d /mnt/$(VM)/$$d
	done


	sudo chroot /mnt/$(VM) /bin/bash -c '\
		set -e; \
		echo "$(VM)" > /etc/hostname; \
		echo "Input root password:"; \
		passwd root; \
		apt update; \
		apt install -y \
			linux-image-amd64 \
			systemd-sysv \
			ifupdown2 \
			openssh-server \
			ca-certificates \
			locales \
			sudo; \
		mkdir -p /srv/garagehq; \
		printf "%s\n" \
			"LABEL=$(VM)-root / ext4 errors=remount-ro 0 1" \
			"LABEL=$(VM)-data /srv/garagehq ext4 defaults 0 2" \
			> /etc/fstab; \
                mkdir -p /srv/garagehq; \
		printf "%s\n" \
			"auto lo" \
			"iface lo inet loopback" \
			"" \
			"auto eth0" \
			"iface eth0 inet static" \
			"    address $(VMADDR)" \
			"    gateway $(VMROUTE)" \
			> /etc/network/interfaces; \
		printf "%s\n" \
			"nameserver 1.1.1.1" \
			"nameserver 8.8.8.8" \
			> /etc/resolv.conf; \
		printf "%s\n" \
			"127.0.0.1 localhost" \
			"127.0.1.1 $(VM)" \
			"::1 localhost ip6-localhost ip6-loopback" \
			> /etc/hosts; \
	'

	# The key goes in from OUTSIDE the chroot (2026-11-03). Until then it was
	# spliced into the single-quoted `bash -c` script above as '$(RSA_KEY)':
	# the key's own quotes ended that string, its words became arguments of
	# bash instead of text of the script, and authorized_keys was never
	# written -- the DomU never got the key. Here no shell re-parses it: one
	# quoted word to printf, piped into install, which also sets the modes.
	sudo install -d -m 700 -o root -g root /mnt/$(VM)/root/.ssh
	printf '%s\n' '$(RSA_KEY)' | sudo install -m 600 -o root -g root /dev/stdin /mnt/$(VM)/root/.ssh/authorized_keys

	sudo mkdir -p /var/lib/xen/$(VM)

	sudo cp /mnt/$(VM)/boot/vmlinuz-* \
		/var/lib/xen/$(VM)/vmlinuz

	sudo cp /mnt/$(VM)/boot/initrd.img-* \
		/var/lib/xen/$(VM)/initrd.img

	for d in sys proc dev/pts dev; do
		sudo umount /mnt/$(VM)/$$d
	done

	sudo umount /mnt/$(VM)

	sudo xl create $(CFG)

web_sandbox:
	# No `bash -c`: ssh joins its arguments, so it would run only `apt`.
	#
	# Safe to run again since 2026-11-03. Until then a second run dropped the
	# Postgres cluster -- every job row and manifest -- cloned over an
	# existing checkout, rewrote /etc/garage.toml with new secrets over the
	# live store, appended a second JWT key to api.env and moved a new CA
	# inside the old one. Now the remote script stops at its first failure
	# (set -e), and each thing it would create is kept when it already exists.
	ssh root@$(VMIP) 'set -e; apt update; \
	apt install -y postgresql postgresql-contrib python3 python3-venv python3-pip ca-certificates curl gnupg git libmagic1t64; \
	systemctl enable --now postgresql; \
	useradd -r -m -s /usr/sbin/nologin platform || true; \
	if su - postgres -c "psql -lqt" | grep -qw sandbox_platform; then echo "sandbox_platform exists: keeping the cluster and the database"; else \
	pg_dropcluster --stop 17 main; \
	pg_createcluster 17 main --locale=C.UTF-8 --start; \
	systemctl restart postgresql; \
	su - postgres -c "createuser platform"; \
	su - postgres -c "createdb -O platform -E UTF8 -T template0 sandbox_platform"; \
	fi; \
	su - platform -s /bin/bash -c "psql -d sandbox_platform -tAc \"select current_user\""; \
	apt-get install -y git; \
	install -d -o platform -g platform /opt/platform; \
	if [ ! -d /opt/platform/src/.git ]; then su - platform -s /bin/bash -c "git clone --no-checkout https://github.com/evilbootloader/drakvuf-multios-sandbox.git /opt/platform/src"; fi; \
	su - platform -s /bin/bash -c "git -C /opt/platform/src fetch --quiet origin && git -C /opt/platform/src checkout --quiet --detach $(PLATFORM_SHA) && git -C /opt/platform/src log -1 --format=\"platform at %h %s\""; \
	su - platform -s /bin/bash -c "set -e; cd /opt/platform/src/platform; \
	python3 -m venv .venv; \
	.venv/bin/pip install --require-hashes -r requirements.txt; \
	export DATABASE_URL=\"postgresql:///sandbox_platform\"; \
	.venv/bin/python migrations/run.py --status; \
	.venv/bin/python migrations/run.py; \
	"; \
	curl -fsSLo /usr/local/bin/garage.new "https://garagehq.deuxfleurs.fr/_releases/$(GARAGE_V)/x86_64-unknown-linux-musl/garage"; \
	echo "$(GARAGE_SHA256)  /usr/local/bin/garage.new" | sha256sum -c -; \
	install -m 755 -o root -g root /usr/local/bin/garage.new /usr/local/bin/garage; \
	rm /usr/local/bin/garage.new; \
	id garage >/dev/null 2>&1 || adduser --system --group --no-create-home --home /nonexistent garage; \
	if [ -f /etc/garage.toml ]; then echo "/etc/garage.toml exists: keeping the store, its secrets and its layout"; FIRST=0; else FIRST=1; \
	RPC_SECRET=$$(openssl rand -hex 32); \
	ADMIN_TOKEN=$$(openssl rand -base64 32); \
	mkdir -p /srv/garagehq/meta /srv/garagehq/data; \
	chown -R garage:garage /srv/garagehq; \
	printf "%s\n" \
	"metadata_dir = \"/srv/garagehq/meta\"" \
	"data_dir     = \"/srv/garagehq/data\"" \
	"db_engine    = \"lmdb\"" \
	"" \
	"# One node. The lab has one." \
	"replication_factor = 1" \
	"" \
	"rpc_bind_addr   = \"127.0.0.1:3901\"" \
	"rpc_public_addr = \"127.0.0.1:3901\"" \
	"rpc_secret      = \"$$RPC_SECRET\"" \
	"" \
	"compression_level = 1" \
	"" \
	"[s3_api]" \
	"# MUST equal S3_REGION in /etc/sandbox_platform/api.env. The region is part of" \
	"# the SigV4 signing scope, so a mismatch fails every presigned URL with a 403" \
	"# that discusses signatures and never mentions regions." \
	"s3_region     = \"eu-central-1\"" \
	"api_bind_addr = \"127.0.0.1:3900\"" \
	"# root_domain is deliberately UNSET. Every client here uses path-style" \
	"# addressing \(objects.py pins addressing_style=\"path\"\), and with no root_domain" \
	"# a Host header can never be read as a bucket name." \
	"" \
	"[admin]" \
	"api_bind_addr = \"127.0.0.1:3903\"" \
	"admin_token   = \"$$ADMIN_TOKEN\"" > /etc/garage.toml ; \
	chown root:garage /etc/garage.toml && chmod 640 /etc/garage.toml; fi; \
	printf "%s\n" \
	"[Unit]" \
	"Description=Garage object store (analysis bucket)" \
	"After=network-online.target" \
	"Wants=network-online.target" \
	"" \
	"[Service]" \
	"Environment=RUST_LOG=garage=info" \
	"ExecStart=/usr/local/bin/garage server" \
	"User=garage" \
	"Group=garage" \
	"Restart=always" \
	"RestartSec=5" \
	"LimitNOFILE=65536" \
	"NoNewPrivileges=true" \
	"ProtectSystem=strict" \
	"ProtectHome=true" \
	"PrivateTmp=true" \
	"ReadWritePaths=/srv/garagehq" \
	"" \
	"[Install]" \
	"WantedBy=multi-user.target " > /etc/systemd/system/garage.service; \
        systemctl daemon-reload && systemctl stop garage && sleep 3 && systemctl enable garage && systemctl start garage && sleep 3; \
	G="garage -c /etc/garage.toml"; \
	$$G status; \
	if [ "$$FIRST" = 1 ]; then NODE=$$($$G node id -q | cut -d@ -f1) ; \
	$$G layout assign -z lab -c $(S3_QUOTA)G "$$NODE"; \
	$$G layout apply --version 1; fi; \
	$$G layout show; \
	$$G status; \
	mkdir -p /etc/sandbox_platform ; \
	chown platform:platform /etc/sandbox_platform ; \
	chmod 750 /etc/sandbox_platform ; \
	BROWSER_ORIGIN=https://$(SANDBOX_WEB) BUCKET_QUOTA=$(S3_QUOTA)GiB RETENTION_DAYS=$(S3_RETENTION) /opt/platform/src/platform/garage/provision.sh; \
	'
	sed -e 's|@VMIP@|$(VMIP)|g' -e 's|@SANDBOX_WEB@|$(SANDBOX_WEB)|g' \
	    -e 's|@RETENTION_DAYS@|$(S3_RETENTION)|g' \
	    -e 's|@ANALYSIS_USERNAME@|$(ANALYSIS_VM_USER)|g' \
	    -e "s|@JWT_SIGNING_KEY@|$$(openssl rand -hex 32)|" \
	    $(REPO_ROOT)/automation/api.env.example \
	  | ssh root@$(VMIP) 'if grep -q "^JWT_SIGNING_KEY=" /etc/sandbox_platform/api.env 2>/dev/null; then echo "api.env already rendered: keeping it"; cat >/dev/null; else umask 077; cat >> /etc/sandbox_platform/api.env; fi'
	# Appended, not written: provision.sh put the S3 keys in that file first.
	# A placeholder left unrendered is a failure, not a line in the output.
	#
	# The CA (2026-11-03). This target has no workstation to make the CA on,
	# so it makes it on the DomU, which tls/README.md forbids for the root
	# key, and until now it LEFT it there, owned by the user the API runs as:
	# code execution in the API could mint certificates Dom0 trusts. Now the
	# three leaf certificates are issued and ca.key is destroyed in the same
	# breath, so on a Makefile-built platform the root key exists nowhere.
	# The cost: a renewal (leaves last 825 days) is a new CA and a new trust
	# anchor on Dom0, which `make sandboxd` installs. A ca.key found on the
	# platform at any later run stops the run and says how to remove it.
	ssh root@$(VMIP) 'set -e; ! grep -n "@[A-Z_]*@" /etc/sandbox_platform/api.env || { echo "api.env: unrendered placeholder" >&2; exit 1; }; \
	chmod 600 /etc/sandbox_platform/api.env; \
	chown platform:platform /etc/sandbox_platform/api.env; \
	if [ -d /etc/sandbox_platform/tls ]; then echo "/etc/sandbox_platform/tls exists: keeping the certificates"; else \
	su - platform -s /bin/bash -c "export CA_ALLOW_HERE=1; /opt/platform/src/tls/issue-cert.sh init; /opt/platform/src/tls/issue-cert.sh server sandbox_web 127.0.0.1 $(SANDBOX_WEB) $(VMIP); /opt/platform/src/tls/issue-cert.sh server s3bucket_web 127.0.0.1 $(SANDBOX_WEB) $(VMIP); /opt/platform/src/tls/issue-cert.sh server dom0-lab 127.0.0.1 $(SANDBOXDIP)"; \
	mv /opt/platform/src/tls/ca/ /etc/sandbox_platform/tls; \
	openssl x509 -in /etc/sandbox_platform/tls/ca.crt -noout -fingerprint -sha256 -enddate; \
	shred -u /etc/sandbox_platform/tls/ca.key /etc/sandbox_platform/tls/ca.srl 2>/dev/null || rm -f /etc/sandbox_platform/tls/ca.key /etc/sandbox_platform/tls/ca.srl; \
	echo "ca.key destroyed on this host; the three leaf certificates are issued for 825 days. A renewal is a new CA: rm -r /etc/sandbox_platform/tls; make web_sandbox; make sandboxd (installs the new ca.crt on Dom0)."; \
	fi; \
	test ! -f /etc/sandbox_platform/tls/ca.key || { echo "/etc/sandbox_platform/tls/ca.key exists on the platform. The CA root key must not live here (tls/README.md, Custody): shred -u /etc/sandbox_platform/tls/ca.key /etc/sandbox_platform/tls/ca.srl, then run this again." >&2; exit 1; }; \
	chown -R platform:platform /etc/sandbox_platform/; \
	printf "%s\n" \
	"[Unit]" \
	"Description=DRAKVUF sandbox platform API" \
	"After=network.target postgresql.service" \
	"Wants=postgresql.service" \
	"[Service]" \
	"User=platform" \
	"Group=platform" \
	"WorkingDirectory=/opt/platform/src/platform" \
	"EnvironmentFile=/etc/sandbox_platform/api.env" \
	"ExecStart=/opt/platform/src/platform/.venv/bin/python -m uvicorn \\" \
	"    sandbox_platform.app:app \\" \
	"    --host $(VMIP) --port 8000 \\" \
	"    --ssl-certfile /etc/sandbox_platform/tls/sandbox_web.crt \\" \
	"    --ssl-keyfile  /etc/sandbox_platform/tls/sandbox_web.key \\" \
	"    --ssl-ca-certs /etc/sandbox_platform/tls/ca.crt" \
	"Restart=on-failure" \
	"RestartSec=5" \
	"" \
	"# The service reads a sample only as a stream and writes none." \
	"ProtectSystem=strict" \
	"ProtectHome=true" \
	"PrivateTmp=true" \
	"NoNewPrivileges=true" \
	"" \
	"[Install]" \
	"WantedBy=multi-user.target" > /etc/systemd/system/sandbox-api.service
	systemctl daemon-reload; \
	systemctl enable --now sandbox-api; \
	systemctl status sandbox-api --no-pager | head -5; \
	apt-get install -y nginx; \
	rm -f /etc/nginx/sites-enabled/default; \
	install -d -m 700 -o root -g root /etc/nginx/tls; \
	install -m 600 -o root -g root /etc/sandbox_platform/tls/s3bucket_web.crt  /etc/nginx/tls/objects.crt; \
	install -m 600 -o root -g root /etc/sandbox_platform/tls/s3bucket_web.key /etc/nginx/tls/objects.key; \
	install -m 644 -o root -g root \
	/opt/platform/src/platform/garage/objects.conf \
	/etc/nginx/conf.d/objects.conf; \
	sed -i "s/192.168.1.10/$(VMIP)/g" /etc/nginx/conf.d/objects.conf ; \
	systemctl reload nginx && systemctl restart nginx; \
	set -a; . /etc/sandbox_platform/api.env; set +a; \
	/opt/platform/src/platform/.venv/bin/python \
	  /opt/platform/src/platform/garage/conformance.py \
	    --front  https://$(VMIP):9000 \
	    --direct http://127.0.0.1:3900 \
	    --origin https://$(SANDBOX_WEB) \
	    --ca /etc/sandbox_platform/tls/ca.crt; \
	cd /opt/platform/src/platform; \
	sudo -u platform DATABASE_URL=postgresql:///sandbox_platform \
	 .venv/bin/python create_worker.py dom0-1 || echo "worker dom0-1 exists already; make sandboxd rotates its token"; \
	'

sandboxd:
	@echo "Installing libvmi, drakvuf and sandboxd orquestrator"
	set -e; \
	xl domid $(VM) || xl create $(CFG) || echo "Run make web_vm and make web_sandbox"; \
	cd $(REPO_ROOT); \
	git submodule sync; \
	git submodule update --init; \
	cd drakvuf; \
	# libvmi moved to the evilbootloader fork, sync brings an existing checkout along \
	git submodule sync; \
	git submodule update --init; \
	cd libvmi; \
	autoreconf -vif; \
	./configure --enable-page-cache=8192 --disable-kvm --disable-bareflank --disable-file; \
	make; \
	make install; \
	if [ -n "$$LD_LIBRARY_PATH" ]; then \
		echo 'export LD_LIBRARY_PATH=$$LD_LIBRARY_PATH:/usr/local/lib' >> ~/.bashrc; \
	else \
		echo 'export LD_LIBRARY_PATH=/usr/local/lib' >> ~/.bashrc; \
	fi; \
	cd $(REPO_ROOT)/drakvuf/volatility3; \
	git fetch origin $(VOLATILITY3_PR650); \
	git switch -C pr-650 $(VOLATILITY3_PR650); \
	# Not installed (review L-7, 2026-11-04): scripts/windows-symbol-profiles.py \
	# runs pdbconv.py out of this checkout with PYTHONPATH set to it, and a \
	# system-wide install of a pull-request branch was what it had to work \
	# around. pdbconv's own imports come from the distribution instead. \
	sudo apt-get install -y python3-pefile python3-construct; \
	cd $(REPO_ROOT)/drakvuf; \
	# threadsafety: required by --parallel-events. On a build/ that exists, \
	# plain `meson setup` is a no-op that keeps the old options and the old \
	# `git describe` banner (review L-8): reconfigure it. \
	if [ -f build/build.ninja ]; then meson setup --reconfigure build --native-file llvm.ini -Dthreadsafety=true; \
	else meson setup build --native-file llvm.ini -Dthreadsafety=true; fi; \
	ninja -C build; \
	ninja -C build install; \
	# Egress responders: tor for `tor`, FakeNet-NG for `simulated`, docs/runbooks/13-verify-egress-modes.md \
	apt-get install -y tor python3-pip python3-venv; \
	install -m 0644 $(REPO_ROOT)/automation/torrc /etc/tor/torrc; \
	python3 -m venv /opt/fakenet-ng; \
	/opt/fakenet-ng/bin/pip install --require-hashes -r $(REPO_ROOT)/automation/fakenet-requirements.txt; \
	# Reinstalled before patching, every time: patch --forward skips a file it finds partly patched \
	/opt/fakenet-ng/bin/pip install --no-deps --force-reinstall 'git+https://github.com/mandiant/flare-fakenet-ng@$(FAKENET_COMMIT)'; \
	install -m 0644 $(REPO_ROOT)/automation/fakenet.ini /etc/fakenet.ini; \
	mkdir -p /var/lib/fakenet/root; \
	SP="$$(/opt/fakenet-ng/bin/python -c 'import fakenet, os; print(os.path.dirname(os.path.dirname(fakenet.__file__)))')"; \
	patch -p1 --forward -d "$$SP" < $(REPO_ROOT)/automation/fakenet-divert-no.patch; \
	# The patch can fail silently, each count below is one of its changes \
	test "$$(grep -c "conn.setblocking(0)" "$$SP/fakenet/listeners/ProxyListener.py")" -eq 1; \
	test "$$(grep -c "fn_addr = '0.0.0.0'" "$$SP/fakenet/fakenet.py")" -eq 2; \
	test "$$(grep -c "self.__diverter is None" "$$SP/fakenet/diverters/diverterbase.py")" -eq 3; \
	test "$$(grep -c "Inadmissible SNI" "$$SP/fakenet/listeners/ssl_utils/__init__.py")" -eq 1; \
	test "$$(grep -c "if diverter is not None else None" "$$SP/fakenet/listeners/ProxyListener.py")" -eq 1; \
	test "$$(grep -c "except ssl.SSLError" "$$SP/fakenet/listeners/ProxyListener.py")" -eq 1; \
	install -m 0644 $(REPO_ROOT)/automation/fakenet.service /etc/systemd/system/; \
	install -m 0644 $(REPO_ROOT)/automation/drakvuf-egress.target /etc/systemd/system/; \
	systemctl daemon-reload; \
	systemctl enable --now drakvuf-egress.target; \
	systemctl restart tor fakenet; \
	systemctl is-active tor fakenet; \
	mkdir /etc/sandboxd/tls -p; \
	scp $(VMIP):/etc/sandbox_platform/tls/ca.crt /etc/sandboxd/tls/; \
	scp $(VMIP):/etc/sandbox_platform/tls/dom0-lab.crt /etc/sandboxd/tls/; \
	scp $(VMIP):/etc/sandbox_platform/tls/dom0-lab.key /etc/sandboxd/tls/; \
	cd $(REPO_ROOT); \
	python3 -m venv .venv-sandboxd; \
	.venv-sandboxd/bin/pip install --require-hashes -r sandboxd/requirements.txt; \
	# Dom0's lvm2 must never parse a clone volume: automation/lvmlocal.conf, \
	# appended once (its first line is the marker) and validated. \
	grep -q 'DRAKVUF clone volumes' /etc/lvm/lvmlocal.conf 2>/dev/null || sudo tee -a /etc/lvm/lvmlocal.conf < $(REPO_ROOT)/automation/lvmlocal.conf >/dev/null; \
	sudo lvmconfig --validate; \
	sudo lvmconfig devices/global_filter; \
	# sandboxd's environment, from automation/sandboxd.env.example. REPLACED, not
	# appended to: `>>` added a second copy of every line on each re-run. The
	# token is this host's own, rotated on the platform; written under umask 077
	# so it is never readable by anyone else, even for a moment.
	TOKEN=$$(ssh $(VMIP) 'sudo -u platform DATABASE_URL=postgresql:///sandbox_platform /opt/platform/src/platform/.venv/bin/python /opt/platform/src/platform/create_worker.py dom0-1 --rotate;' | grep -Eo 'WORKER_TOKEN=.*' | cut -d= -f2-); \
	test -n "$$TOKEN"; \
	# From the totals, not from free_memory at this moment (review L-6): \
	# the host's RAM less Dom0's fixed allocation (dom0_mem=...,max:), less \
	# the platform's (its cfg), less 2000 MiB for Xen's own use. The free \
	# figure counted whatever happened to be running and was wrong in both \
	# directions; this one is the same on every run. \
	TOTAL_MIB=$$(( $$(xl info | awk '/^total_memory/ { print $$3 }') \
		- $$(xl list Domain-0 | awk 'NR == 2 { print $$3 }') \
		- $$(sed -n 's/^memory *= *\([0-9]*\).*/\1/p' $(CFG)) - 2000 )); \
	test "$$TOTAL_MIB" -gt 0; \
	(umask 077; sed -e 's|@VMIP@|$(VMIP)|g' -e "s|@TOTAL_MIB@|$$TOTAL_MIB|" -e "s|@WORKER_TOKEN@|$$TOKEN|" \
		-e 's|@REPO_ROOT@|$(REPO_ROOT)|g' -e 's|@ANALYSIS_VM_USER@|$(ANALYSIS_VM_USER)|g' \
		$(REPO_ROOT)/automation/sandboxd.env.example > /etc/sandboxd/sandboxd.env.new); \
	# The injection PIDs survive a re-run: setup_hooks_* wrote them, and a \
	# daemon without them injects into PID 1 on Windows, which does not exist. \
	grep -E '^SANDBOXD_INJECTION_PID_' /etc/sandboxd/sandboxd.env >> /etc/sandboxd/sandboxd.env.new 2>/dev/null || true; \
	if grep -n '@[A-Z_]*@' /etc/sandboxd/sandboxd.env.new; then \
		echo 'sandboxd.env: unrendered placeholder' >&2; exit 1; \
	fi; \
	install -m 600 /etc/sandboxd/sandboxd.env.new /etc/sandboxd/sandboxd.env; \
	rm -f /etc/sandboxd/sandboxd.env.new; \
	# Nothing is sed-edited into sandboxd/config.py any more (2026-11-03): the
	# checkout path and the analysis user travel in sandboxd.env above, which
	# config.py reads. The two seds that used to be here dirtied Dom0's
	# checkout on every deploy and stopped `git pull --ff-only` on the one file
	# the CPU partition is generated from.
	# The thin pool is no longer created here (Dom0's change, merged
	# 2026-11-03): it exists from the first `make web_vm`, and creating it at
	# the end of this target failed every re-run.



ubuntu_analysis_vm:
	@echo "Installing ubuntu analysis VM"; \
	set -e; \
	HASH=$$(openssl passwd -6 -salt "$$(openssl rand -hex 8)" '$(ANALYSIS_VM_PASS)'); \
	apt install cloud-image-utils wget -y;\
	mkdir -p $(REPO_ROOT)/misc/iso/cidata; \
	cd $(REPO_ROOT)/misc/iso/cidata; \
	\
	printf "%s\n" \
	"#cloud-config" \
	"autoinstall:" \
	"  version: 1" \
	"  identity:" \
	"    hostname: ubuntu" \
	"    password: \"$$HASH\"" \
	"    username: $(ANALYSIS_VM_USER)" \
	"  ssh:" \
	"    install-server: true" \
	"    authorized-keys:" \
	"      - $(RSA_KEY)" \
	"    allow-pw: false" \
	"  codecs:" \
	"    install: true" \
	"  packages:" \
	"    - ubuntu-desktop" \
	"    - git" \
	"    - curl" \
	"    - python3" \
	"  timezone: \"Europe/Madrid\"" \
	"  updates: all" \
	"  shutdown: poweroff" \
	"  late-commands:" \
	"    - curtin in-target --target=/target -- apt-get install -y ubuntu-dbgsym-keyring" \
	"    - curtin in-target --target=/target -- sh -c 'printf \"Types\072 deb\nURIs\072 http://ddebs.ubuntu.com/\nSuites\072 \$$(lsb_release -cs) \$$(lsb_release -cs)-updates \$$(lsb_release -cs)-proposed\nComponents\072 main restricted universe multiverse\nSigned-By\072 /usr/share/keyrings/ubuntu-dbgsym-keyring.gpg\n\" | tee /etc/apt/sources.list.d/ddebs.sources'" \
	"    - curtin in-target --target=/target -- apt-get update" \
	"    - curtin in-target --target=/target -- bash -c 'KVER=\$$(ls /boot/vmlinuz-* | sed \"s|/boot/vmlinuz-||\" | sort -V | tail -1); apt-get install -y linux-image-\$${KVER}-dbgsym'" \
	"    - curtin in-target --target=/target -- mkdir -p /etc/gdm3" \
	"    - curtin in-target --target=/target -- sh -c 'printf \"[daemon]\nAutomaticLoginEnable=true\nAutomaticLogin=$(ANALYSIS_VM_USER)\n\" > /etc/gdm3/custom.conf'" \
	"    - curtin in-target --target=/target -- sed -i 's/^GRUB_CMDLINE_LINUX=\"/&net.ifnames=0 /' /etc/default/grub" \
	"    - curtin in-target --target=/target -- update-grub" \
	"  keyboard:" \
	"    layout: \"es\"" > user-data; \
	touch meta-data; \
	cloud-localds \
		"$(REPO_ROOT)/misc/iso/seed.iso" \
		"$(REPO_ROOT)/misc/iso/cidata/user-data" \
		"$(REPO_ROOT)/misc/iso/cidata/meta-data"; \
	\
	# Downloaded once: 6 GB per run otherwise, and `wget -O` truncates the \
	# file before fetching, so a failed download used to leave nothing; the \
	# download lands in .part and is renamed whole. The checksum is checked \
	# on every run, download or not, against the signed list's value. The \
	# kernel and initrd come from the SAME server ISO the installer boots; \
	# until 2026-11-03 this mounted a desktop ISO nothing had downloaded. \
	test -f $(REPO_ROOT)/misc/iso/ubuntu-22.04.5-live-server-amd64.iso || { wget "$(UBUNTU_ISO_URL)" -O $(REPO_ROOT)/misc/iso/ubuntu-22.04.5-live-server-amd64.iso.part && mv $(REPO_ROOT)/misc/iso/ubuntu-22.04.5-live-server-amd64.iso.part $(REPO_ROOT)/misc/iso/ubuntu-22.04.5-live-server-amd64.iso; }; \
	echo "$(UBUNTU_ISO_SHA256)  $(REPO_ROOT)/misc/iso/ubuntu-22.04.5-live-server-amd64.iso" | sha256sum -c -; \
	mount $(REPO_ROOT)/misc/iso/ubuntu-22.04.5-live-server-amd64.iso  /mnt; \
	cp /mnt/casper/initrd /mnt/casper/vmlinuz $(REPO_ROOT)/misc/iso/; \
	umount /mnt; \
	# The guest's hardware identity: docs/architecture/guest-identity.md \
	python3 $(XEN_IDENTITY) guest-files $(GUEST_FIRMWARE); \
	MAC=$$(python3 $(XEN_IDENTITY) mac ubuntu); \
	printf "%s\n" \
	"arch = 'x86_64'" \
	"name = 'ubuntu_analysis'" \
	"maxmem = 8192" \
	"memory = 8192" \
	"vcpus = 4" \
	"maxvcpus = 4" \
	"builder = 'hvm'" \
	"boot = 'cd'" \
	"hap = 1" \
	"on_poweroff = 'destroy'" \
	"on_reboot = 'restart'" \
	"on_crash = 'destroy'" \
	"vnc = 1" \
	"vnclisten = '127.0.0.1'" \
	"vga = 'stdvga'" \
	"usb = 1" \
	"usbdevice = 'tablet'" \
	"audio = 1" \
	"viridian = 0" \
	"cpuid = 'host,hypervisor=0'" \
	"altp2m = 2" \
	"shadow_memory = 128" \
	"vif = [ 'type=ioemu,model=e1000,mac=$$MAC,bridge=xenbr0' ]" \
	"disk = ['phy:/dev/vg-root/ubuntu,hda,w','file:$(REPO_ROOT)/misc/iso/seed.iso,hdb:cdrom,r','file:$(REPO_ROOT)/misc/iso/ubuntu-22.04.5-live-server-amd64.iso,hdc:cdrom,r']" \
	"kernel = '$(REPO_ROOT)/misc/iso/vmlinuz'" \
	"ramdisk = '$(REPO_ROOT)/misc/iso/initrd'" \
	"extra = 'autoinstall net.ifnames=0'" \
		> $(REPO_ROOT)/misc/xen-vms/ubuntu.cfg; \
	python3 $(XEN_IDENTITY) xl-cfg $(GUEST_FIRMWARE) >> $(REPO_ROOT)/misc/xen-vms/ubuntu.cfg; \
	sudo lvcreate -V 1T --thin -n ubuntu vg-root/thinpool; \
	xl create $(REPO_ROOT)/misc/xen-vms/ubuntu.cfg; \
	sed -Ei 's/^kernel.*|^ramdisk.*|^extra.*//g' $(REPO_ROOT)/misc/xen-vms/ubuntu.cfg;
	# TODO "/etc/lvm/lvm.conf" 12-baremetal-trial
	# thin_pool_autoextend_threshold = 80
	# thin_pool_autoextend_percent   = 20
	# sudo systemctl restart lvm2-monitor

win_installers:
	# What the Windows golden image installs, downloaded ONCE and verified
	# against automation/win-installers.list before any image is built from
	# it (2026-11-03). Until then misc/xen-vms/autounattend.xml fetched every
	# installer over HTTPS at install time with no check, three of them from
	# unversioned redirects, and ran a script from a third-party host as
	# SYSTEM; whatever those hosts served that day became the trust root of
	# every Windows clone, and no two builds of the image were the same. A
	# hash mismatch refuses the build; the fix is to look, then re-pin.
	#
	# The mirror first, the vendor second (2026-11-04). A file the mirror does
	# not have -- a fresh lab, a newly added installer -- comes from the vendor
	# and is verified the same way; `win_installers_mirror` then publishes it.
	# wget's exit code decides, not its silence (review 2026-11-04, item 3):
	# 8 is the mirror answering without the file and 4 is no mirror to answer,
	# both the normal case before it exists, so they fall back to the vendor
	# and say which; 5 is a certificate that did not verify against the CA,
	# which is a misconfigured or tampered mirror and STOPS the run rather
	# than quietly detouring around it. --no-config so that no wgetrc on Dom0
	# can turn the verification off. A .part left by a refused fetch is removed
	# before the vendor's download, so a 404 body can never be renamed into
	# place.
	set -e; \
	mkdir -p $(WIN_INSTALLERS); \
	grep -vE '^\s*(#|$$)' $(WIN_INSTALLERS_LIST) | while read -r file sha url; do \
	  if [ ! -f "$(WIN_INSTALLERS)/$$file" ]; then \
	    rm -f "$(WIN_INSTALLERS)/$$file.part"; rc=0; \
	    if [ -n "$(INSTALLERS_MIRROR)" ] && [ -r "$(INSTALLERS_MIRROR_CA)" ]; then \
	      wget -q --no-config --ca-certificate="$(INSTALLERS_MIRROR_CA)" -O "$(WIN_INSTALLERS)/$$file.part" "$(INSTALLERS_MIRROR)/$$file" || rc=$$?; \
	    else rc=4; fi; \
	    case "$$rc" in \
	      0) echo "$$file: from the mirror";; \
	      5) echo "$$file: the mirror's certificate did not verify against $(INSTALLERS_MIRROR_CA). NOT falling back to the vendor: a mirror that is there and fails TLS is a stop, not a detour" >&2; exit 1;; \
	      8) rm -f "$(WIN_INSTALLERS)/$$file.part"; echo "$$file: not on the mirror (HTTP error), from the vendor: $$url"; wget -O "$(WIN_INSTALLERS)/$$file.part" "$$url";; \
	      *) rm -f "$(WIN_INSTALLERS)/$$file.part"; echo "$$file: mirror unreachable or unset (wget exit $$rc), from the vendor: $$url"; wget -O "$(WIN_INSTALLERS)/$$file.part" "$$url";; \
	    esac; \
	    mv "$(WIN_INSTALLERS)/$$file.part" "$(WIN_INSTALLERS)/$$file"; \
	  fi; \
	  echo "$$sha  $(WIN_INSTALLERS)/$$file" | sha256sum -c -; \
	done

win_installers_mirror: win_installers
	# Publishes the verified cache to the platform's mirror (2026-11-04):
	# every file is checked against the list again, copied to a .part name,
	# renamed into place, and the nginx listener installed or refreshed from
	# automation/win-installers-mirror.conf. Then every file is fetched back
	# THROUGH the mirror and hashed, so a mirror that serves the wrong thing,
	# or nothing, fails here and not in the next Windows build. LAN only: the
	# tunnel's ingress names 8000 and 9000 and nothing else. The ssh inside
	# the loop is `ssh -n` (review 2026-11-04, item 1): without it ssh drains
	# the loop's stdin, the rest of the list, and only the first file is
	# published -- evasion-tests/search_common.sh met the same thing.
	set -e; \
	test -n "$(INSTALLERS_MIRROR)" || { echo "INSTALLERS_MIRROR is empty: nothing to publish to" >&2; exit 1; }; \
	test -r "$(INSTALLERS_MIRROR_CA)" || { echo "$(INSTALLERS_MIRROR_CA) is not readable: run make sandboxd first, it installs the CA Dom0 verifies the mirror with" >&2; exit 1; }; \
	ssh root@$(VMIP) 'install -d -m 755 -o root -g root $(INSTALLERS_MIRROR_DIR)'; \
	grep -vE '^\s*(#|$$)' $(WIN_INSTALLERS_LIST) | while read -r file sha url; do \
	  echo "$$sha  $(WIN_INSTALLERS)/$$file" | sha256sum -c - >/dev/null; \
	  scp -q "$(WIN_INSTALLERS)/$$file" "root@$(VMIP):$(INSTALLERS_MIRROR_DIR)/$$file.part"; \
	  ssh -n root@$(VMIP) "chmod 644 '$(INSTALLERS_MIRROR_DIR)/$$file.part' && mv '$(INSTALLERS_MIRROR_DIR)/$$file.part' '$(INSTALLERS_MIRROR_DIR)/$$file'"; \
	  echo "$$file: published"; \
	done; \
	sed -e 's|@VMIP@|$(VMIP)|g' -e 's|@MIRROR_DIR@|$(INSTALLERS_MIRROR_DIR)|g' $(INSTALLERS_MIRROR_CONF) | ssh root@$(VMIP) 'cat > /etc/nginx/conf.d/win-installers-mirror.conf && nginx -t && systemctl reload nginx'; \
	grep -vE '^\s*(#|$$)' $(WIN_INSTALLERS_LIST) | while read -r file sha url; do \
	  if wget -q --no-config --ca-certificate="$(INSTALLERS_MIRROR_CA)" -O - "$(INSTALLERS_MIRROR)/$$file" | sha256sum | grep -q "^$$sha "; then echo "$$file: served by the mirror, hash verified"; \
	  else echo "$$file: the mirror serves something else, or nothing" >&2; exit 1; fi; \
	done

windows_analysis_vm: win_installers
	@echo "Installing Windows 11 23H2 analysis VM"; \
	set -e; \
	apt install wget genisoimage -y; \
	rm -rf /tmp/win11iso/; \
	mkdir /tmp/win11iso/; \
	test -f $(REPO_ROOT)/misc/iso/Win11_23H2_EnglishInternational_x64.iso || wget $(WIN_ISO_URL) -O $(REPO_ROOT)/misc/iso/Win11_23H2_EnglishInternational_x64.iso ; \
	# Checked before anything reads it: the mirror can replace the file \
	echo "$(WIN_ISO_SHA256)  $(REPO_ROOT)/misc/iso/Win11_23H2_EnglishInternational_x64.iso" | sha256sum -c -; \
	sudo mount -o loop,ro $(REPO_ROOT)/misc/iso/Win11_23H2_EnglishInternational_x64.iso /mnt; \
	sudo cp -r /mnt/* /tmp/win11iso/; \
	sudo umount /mnt; \
	cp $(REPO_ROOT)/misc/xen-vms/autounattend.xml /tmp/win11iso/; \
	# The verified installers ride on the media; the answer file installs \
	# from there and makes no download but Office's own (win_installers). \
	cp -r $(WIN_INSTALLERS) /tmp/win11iso/installers; \
	sed -i 's|<Name>carlos</Name>|<Name>$(ANALYSIS_VM_USER)</Name>|g' /tmp/win11iso/autounattend.xml; \
	sed -i 's|<DisplayName>carlos</DisplayName>|<DisplayName>$(ANALYSIS_VM_USER)</DisplayName>|g' /tmp/win11iso/autounattend.xml; \
	sed -i 's|<Username>carlos</Username>|<Username>$(ANALYSIS_VM_USER)</Username>|g' /tmp/win11iso/autounattend.xml; \
	sed -i "s|'carlos'|'$(ANALYSIS_VM_USER)'|g" /tmp/win11iso/autounattend.xml; \
	sed -i 's|<Value>malware</Value>|<Value>$(ANALYSIS_VM_PASS)</Value>|g' /tmp/win11iso/autounattend.xml; \
	sed -i "s|'malware'|'$(ANALYSIS_VM_PASS)'|g" /tmp/win11iso/autounattend.xml; \
	genisoimage -o $(REPO_ROOT)/misc/iso/Win11_modified.iso \
	  -b boot/etfsboot.com -no-emul-boot -boot-load-seg 0x07C0 -boot-load-size 8 \
	  -eltorito-alt-boot -e efi/microsoft/boot/efisys.bin -no-emul-boot \
	  -udf -J -joliet-long -allow-limited-size \
	  -V "WIN11_SEABIOS" \
	  /tmp/win11iso/
	# The guest's hardware identity: docs/architecture/guest-identity.md \
	python3 $(XEN_IDENTITY) guest-files $(GUEST_FIRMWARE); \
	MAC=$$(python3 $(XEN_IDENTITY) mac windows); \
	printf "%s\n" \
	"arch = 'x86_64'" \
	"name = 'windows_analysis'" \
	"maxmem = 8192" \
	"memory = 8192" \
	"vcpus = 4" \
	"maxvcpus = 4" \
	"builder = 'hvm'" \
	"boot = 'cd'" \
	"hap = 1" \
	"on_poweroff = 'destroy'" \
	"on_reboot = 'restart'" \
	"on_crash = 'destroy'" \
	"vnc = 1" \
	"vnclisten = '127.0.0.1'" \
	"vga = 'stdvga'" \
	"usb = 1" \
	"usbdevice = 'tablet'" \
	"audio = 1" \
	"viridian = 0" \
	"cpuid = 'host,hypervisor=0'" \
	"altp2m = 2" \
	"shadow_memory = 128" \
	"vif = [ 'type=ioemu,model=e1000,mac=$$MAC,bridge=xenbr0' ]" \
	"disk = [ 'phy:/dev/vg-root/windows,hda,w', 'file:$(REPO_ROOT)/misc/iso/Win11_modified.iso,hdc:cdrom,r' ]" > $(REPO_ROOT)/misc/xen-vms/windows.cfg; \
	python3 $(XEN_IDENTITY) xl-cfg $(GUEST_FIRMWARE) >> $(REPO_ROOT)/misc/xen-vms/windows.cfg; \
	sudo lvcreate -V 1T --thin -n windows vg-root/thinpool; \
	xl create $(REPO_ROOT)/misc/xen-vms/windows.cfg

modify_windows:
	@echo "VNC is on Dom0's loopback: ssh -L 5900:127.0.0.1:5900 root@dom0, connect to localhost:5900, tune the Windows installation, then run setup_hooks_windows"
	# vnclisten is 127.0.0.1 since 2026-11-03. It was 0.0.0.0 with no
	# password on a domain whose vif sits on the LAN uplink, so anyone on the
	# LAN had the console of the image every clone is snapshotted from.
	# The clone templates (misc/xen-vms/*_sandbox.cfg) were on loopback
	# already; this is the same pattern evasion-tests/rdtsc_vnc.sh documents.
	xl create $(REPO_ROOT)/misc/xen-vms/windows.cfg

modify_ubuntu:
	@echo "VNC is on Dom0's loopback: ssh -L 5900:127.0.0.1:5900 root@dom0, connect to localhost:5900, then tune the Ubuntu installation"
	xl create $(REPO_ROOT)/misc/xen-vms/ubuntu.cfg


setup_hooks_windows:
	kpartx -a /dev/vg-root/windows; \
	mount -o ro /dev/mapper/vg--root-windows2 /mnt/; \
	cd $(REPO_ROOT); \
	# Every profile, the kernel's windows.json included, fetched over TLS: \
	# pdbconv's own fetch is cleartext http (review M-1) \
	python3 $(REPO_ROOT)/scripts/windows-symbol-profiles.py	--drakvuf $(REPO_ROOT)/drakvuf; \
	umount /mnt; \
	kpartx -d /dev/vg-root/windows; \
	lvcreate -s -kn -n windows_sandbox vg-root/windows; \
	# The guest's hardware identity: docs/architecture/guest-identity.md \
	python3 $(XEN_IDENTITY) guest-files $(GUEST_FIRMWARE); \
	MAC=$$(python3 $(XEN_IDENTITY) mac windows); \
	printf "%s\n" \
	"arch = 'x86_64'" \
	"name = 'windows_analysis_sandbox'" \
	"maxmem = 8192" \
	"memory = 8192" \
	"vcpus = 4" \
	"maxvcpus = 4" \
	"builder = 'hvm'" \
	"boot = 'dc'" \
	"hap = 1" \
	"on_poweroff = 'destroy'" \
	"on_reboot = 'restart'" \
	"on_crash = 'destroy'" \
	"vnc = 1" \
	"vnclisten = '127.0.0.1'" \
	"vga = 'stdvga'" \
	"usb = 1" \
	"usbdevice = 'tablet'" \
	"audio = 1" \
	"viridian = 0" \
	"cpuid = 'host,hypervisor=0'" \
	"altp2m = 2" \
	"shadow_memory = 128" \
	"vif = [ 'type=ioemu,model=e1000,mac=$$MAC,script=vif-openvswitch,bridge=xenbr1' ]" \
	"disk = [ 'phy:/dev/vg-root/windows_sandbox,hda,w' ]" > $(REPO_ROOT)/misc/xen-vms/windows_sandbox.cfg; \
	python3 $(XEN_IDENTITY) xl-cfg $(GUEST_FIRMWARE) >> $(REPO_ROOT)/misc/xen-vms/windows_sandbox.cfg; \
	xl create $(REPO_ROOT)/misc/xen-vms/windows_sandbox.cfg; \
	sleep 120; \
	INJECTION_PID=$$(vmi-process-list -d $$(xl domid windows_analysis_sandbox) -j $(REPO_ROOT)/profiles/windows.json \
	    | grep -Eo "\[\s*[0-9]+\]\s*explorer\.exe" | cut -d']' -f1 | grep -Eo "[0-9]+"); \
	echo "INJECTION_PID=$$INJECTION_PID"; \
	# Exactly one number, or stop: an empty match used to be sed-edited into \
	# sandboxd/config.py as `INJECTION_PID_WINDOWS = ` and the daemon no \
	# longer imported; several lines (two explorer.exe) is an anchor injector \
	# would silently attach to the wrong one of. Recorded in the untracked \
	# env file since 2026-11-03, not in the tracked config. \
	case "$$INJECTION_PID" in ''|*[!0-9]*) echo "explorer.exe not found exactly once in the process list (got '$$INJECTION_PID'); the anchor PID was NOT recorded" >&2; exit 1;; esac; \
	if grep -q '^SANDBOXD_INJECTION_PID_WINDOWS=' /etc/sandboxd/sandboxd.env; then sed -i "s/^SANDBOXD_INJECTION_PID_WINDOWS=.*/SANDBOXD_INJECTION_PID_WINDOWS=$$INJECTION_PID/" /etc/sandboxd/sandboxd.env; else echo "SANDBOXD_INJECTION_PID_WINDOWS=$$INJECTION_PID" >> /etc/sandboxd/sandboxd.env; fi; \
	# The save is the operator's, by hand (decision 2026-11-03): this target \
	# used to run it here, two minutes after the domain came up, whether or \
	# not the desktop was settled. Let the guest run at least 20 minutes \
	# first: the saved state carries its uptime into every clone, and a \
	# machine that has been up for two minutes is one of the first things a \
	# sample checks. The PID above is the running explorer.exe, so the guest \
	# must not be restarted between now and the save. \
	echo "windows_analysis_sandbox is running with INJECTION_PID=$$INJECTION_PID recorded."; \
	echo "Leave it running for AT LEAST 20 MINUTES before saving: every clone restores with this uptime, and a two-minute uptime is a sandbox tell samples check. Do not restart the guest. Then, by hand:"; \
	echo "  xl save windows_analysis_sandbox $(REPO_ROOT)/state/windows_sandbox.bak $(REPO_ROOT)/misc/xen-vms/windows_sandbox.cfg"

setup_hooks_ubuntu:
	# The golden Ubuntu root is READ here, never written, and Dom0 never
	# stays attached to the guest's LVM (2026-11-03). Until then both mounts
	# were read-write -- journal replay and atime wrote to the golden volume
	# every clone starts from, and Dom0's ext4 parsed guest-authored metadata
	# with write access -- and a failed step left ubuntu-vg active on Dom0.
	# `noload` skips the journal replay a read-only mount would still do; the
	# trap detaches everything on any exit, in reverse order, quietly.
	# `set +e` first inside the trap (2026-11-04): the trap runs under the
	# recipe's `set -e`, and on a run that had already unmounted everything
	# its first `umount` exits 32, which ended the trap there and became the
	# target's exit code -- `Error 32` after every step had succeeded, three
	# times on the day the target first ran as written. docs/TROUBLESHOOTING.md,
	# "make setup_hooks_ubuntu ends with Error 32".
	set -e; \
	trap 'set +e; umount /mnt/boot 2>/dev/null; umount /mnt 2>/dev/null; lvchange -an ubuntu-vg/ubuntu-lv 2>/dev/null; vgchange -an ubuntu-vg 2>/dev/null; kpartx -d /dev/mapper/vg--root-ubuntu3 2>/dev/null; kpartx -d /dev/vg-root/ubuntu 2>/dev/null; true' EXIT; \
	kpartx -a /dev/vg-root/ubuntu; \
	kpartx -a /dev/mapper/vg--root-ubuntu3; \
	vgchange -ay ubuntu-vg; \
	lvchange -ay ubuntu-vg/ubuntu-lv; \
	mount -o ro,noload /dev/mapper/ubuntu--vg-ubuntu--lv /mnt; \
	mount -o ro,noload /dev/mapper/vg--root-ubuntu2 /mnt/boot/; \
	cd $(REPO_ROOT)/drakvuf/dwarf2json; \
	go build; \
	./dwarf2json linux --system-map /mnt/boot/System.map-*-generic --elf /mnt/usr/lib/debug/boot/vmlinux-*-generic > $(REPO_ROOT)/profiles/linux.json; \
	umount /mnt/boot; \
	umount /mnt; \
	lvchange -an ubuntu-vg/ubuntu-lv; \
	vgchange -an ubuntu-vg; \
	kpartx -d /dev/mapper/vg--root-ubuntu3; \
	kpartx -d /dev/vg-root/ubuntu; \
	lvcreate -s -kn -n ubuntu_sandbox vg-root/ubuntu; \
	# The guest's hardware identity: docs/architecture/guest-identity.md \
	python3 $(XEN_IDENTITY) guest-files $(GUEST_FIRMWARE); \
	MAC=$$(python3 $(XEN_IDENTITY) mac ubuntu); \
	printf "%s\n" \
	"arch = 'x86_64'" \
	"name = 'ubuntu_analysis_sandbox'" \
	"maxmem = 8192" \
	"memory = 8192" \
	"vcpus = 4" \
	"maxvcpus = 4" \
	"builder = 'hvm'" \
	"boot = 'dc'" \
	"hap = 1" \
	"on_poweroff = 'destroy'" \
	"on_reboot = 'restart'" \
	"on_crash = 'destroy'" \
	"vnc = 1" \
	"vnclisten = '127.0.0.1'" \
	"vga = 'stdvga'" \
	"usb = 1" \
	"usbdevice = 'tablet'" \
	"audio = 1" \
	"viridian = 0" \
	"cpuid = 'host,hypervisor=0'" \
	"altp2m = 2" \
	"shadow_memory = 128" \
	"vif = [ 'type=ioemu,model=e1000,mac=$$MAC,script=vif-openvswitch,bridge=xenbr1' ]" \
	"disk = ['phy:/dev/vg-root/ubuntu_sandbox,hda,w' ]" \
		> $(REPO_ROOT)/misc/xen-vms/ubuntu_sandbox.cfg; \
	python3 $(XEN_IDENTITY) xl-cfg $(GUEST_FIRMWARE) >> $(REPO_ROOT)/misc/xen-vms/ubuntu_sandbox.cfg; \
	xl create $(REPO_ROOT)/misc/xen-vms/ubuntu_sandbox.cfg; \
	# PID 1 by design (systemd); written to the env file like Windows's, \
	# not sed-edited into sandboxd/config.py (2026-11-03). \
	if grep -q '^SANDBOXD_INJECTION_PID_UBUNTU=' /etc/sandboxd/sandboxd.env; then sed -i "s/^SANDBOXD_INJECTION_PID_UBUNTU=.*/SANDBOXD_INJECTION_PID_UBUNTU=1/" /etc/sandboxd/sandboxd.env; else echo "SANDBOXD_INJECTION_PID_UBUNTU=1" >> /etc/sandboxd/sandboxd.env; fi; \
	# The save is the operator's, by hand (decision 2026-11-03): this target \
	# used to sleep 120 s and save whatever state the guest was in by then. \
	# Let the guest run at least 20 minutes first: the saved state carries \
	# its uptime into every clone, and a two-minute uptime is a sandbox tell. \
	# Ubuntu anchors on PID 1, so nothing else needs the domain running. \
	echo "ubuntu_analysis_sandbox is running."; \
	echo "Leave it running for AT LEAST 20 MINUTES before saving: every clone restores with this uptime, and a two-minute uptime is a sandbox tell samples check. Then, by hand:"; \
	echo "  xl save ubuntu_analysis_sandbox $(REPO_ROOT)/state/ubuntu_sandbox.bak $(REPO_ROOT)/misc/xen-vms/ubuntu_sandbox.cfg"
