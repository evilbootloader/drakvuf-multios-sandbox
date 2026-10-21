SHELL	:= /bin/bash
.ONESHELL:

VM      := platform
CFG     := misc/xen-vms/platform.cfg
VMADDR	:= 192.168.1.12/24
VMIP := $(firstword $(subst /, ,$(VMADDR)))
VMROUTE	:= 192.168.1.1
RSA_KEY	:= 
SANDBOX_WEB := sandbox.evilbootloader.com
GARAGE_V := v2.4.1
S3_QUOTA := 100
S3_RETENTION := 30
SANDBOXDIP := 192.168.1.6
ANALYSIS_VM_PASS := malware
ANALYSIS_VM_USER := user
REPO_ROOT := $(shell pwd)
# Xen boot line, see docs/CURRENT-STATE.md §1.2
XEN_CMDLINE := dom0_mem=8192M,max:8192M dom0_max_vcpus=6 dom0_vcpus_pin=1 force-ept=1 ept=ad=0 hap_1gb=0 hap_2mb=0 altp2m=1 hpet=legacy-replacement smt=0 sched=credit
# Parallel vm_event processing deadlocks dom0 without it:
# https://lists.xenproject.org/archives/html/xen-devel/2026-10/msg01125.html
XEN_PATCH := $(REPO_ROOT)/automation/xen-altp2m-pause-vcpu.patch
# OVMF is built from tianocore's edk2 instead of the xenbits mirror Config.mk names
OVMF_URL := https://github.com/tianocore/edk2.git
OVMF_REVISION := 4dfdca63a93497203f197ec98ba20e2327e4afe4

.PHONY: xen web_vm web_sandbox sandboxd

xen:
	@echo "Building and installing Xen with the altp2m deadlock fix, then reboot into it"
	set -e; \
	sudo apt-get install -y wget git bcc bin86 gawk bridge-utils iproute2 libcurl4-openssl-dev bzip2 libpci-dev build-essential make gcc clang libc6-dev linux-libc-dev zlib1g-dev libncurses5-dev patch libvncserver-dev libssl-dev libsdl-dev iasl libbz2-dev e2fslibs-dev git-core uuid-dev ocaml libx11-dev bison flex ocaml-findlib xz-utils gettext libyajl-dev libpixman-1-dev libaio-dev libfdt-dev cabextract libglib2.0-dev autoconf automake libtool libjson-c-dev libfuse-dev liblzma-dev autoconf-archive kpartx python3-dev python3-pip golang libsystemd-dev nasm ninja-build llvm lld; \
	sudo apt-get install -y python3-pefile python3-construct; \
	cd $(REPO_ROOT); \
	git submodule update --init drakvuf; \
	cd drakvuf; \
	git submodule update --init xen; \
	cd xen; \
	git apply --reverse --check $(XEN_PATCH) 2>/dev/null || git apply $(XEN_PATCH); \
	sed -i -e 's|^OVMF_UPSTREAM_URL ?= .*|OVMF_UPSTREAM_URL ?= $(OVMF_URL)|' \
		-e 's|^OVMF_UPSTREAM_REVISION ?= .*|OVMF_UPSTREAM_REVISION ?= $(OVMF_REVISION)|' Config.mk; \
	grep -qx 'OVMF_UPSTREAM_REVISION ?= $(OVMF_REVISION)' Config.mk; \
	./configure --enable-githttp --enable-systemd --enable-ovmf --disable-pvshim; \
	make -j$$(nproc) dist-xen; \
	make -j$$(nproc) dist-tools; \
	make -j$$(nproc) debball; \
	sudo apt-get remove -y 'xen*' 'libxen*' || true; \
	sudo dpkg -i dist/xen*.deb; \
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
	sudo systemctl enable xencommons.service; \
	sudo systemctl enable xen-qemu-dom0-disk-backend.service; \
	sudo systemctl enable xen-init-dom0.service; \
	sudo systemctl enable xenconsoled.service; \
	sudo update-grub2; \
	sudo grep -q "multiboot2.*altp2m=1" /boot/grub/grub.cfg || { echo "update-grub2 wrote no Xen entry"; exit 1; }; \
	echo "Xen installed, reboot to start it"

web_vm:
	@echo "Installing $(VM)..."

	sudo apt install -y lvm2 debootstrap

	sudo lvcreate -V 20G  --thin -n $(VM) vg-root/thinpool
	sudo lvcreate -V 256G --thin -n $(VM)_data vg-root/thinpool

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
		mkdir -p /root/.ssh; \
		printf "%s %s\n" '$(RSA_KEY)' > /root/.ssh/authorized_keys; \
                chmod 700 /root/.ssh; \
		chmod 600 /root/.ssh/authorized_keys; \
		printf "%s\n" \
			"127.0.0.1 localhost" \
			"127.0.1.1 $(VM)" \
			"::1 localhost ip6-localhost ip6-loopback" \
			> /etc/hosts; \
	'

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
	ssh root@$(VMIP) bash -c 'apt update; \
	apt install -y postgresql postgresql-contrib python3 python3-venv python3-pip ca-certificates curl gnupg git libmagic1t64; \
	systemctl enable --now postgresql; \
	pg_dropcluster --stop  17 main; \
	pg_createcluster 17 main --locale=C.UTF-8 --start; \
	systemctl restart postgresql; \
	useradd -r -m -s /usr/sbin/nologin platform || true; \
	su - postgres -c "createuser platform"; \
	su - postgres -c "createdb -O platform -E UTF8 -T template0 sandbox_platform"; \
	su - platform -s /bin/bash -c "psql -d sandbox_platform -tAc \"select current_user\""; \
	apt-get install -y git; \
	install -d -o platform -g platform /opt/platform; \
	su - platform -s /bin/bash -c "git clone https://github.com/evilbootloader/drakvuf-multios-sandbox.git /opt/platform/src; \
	cd /opt/platform/src/platform; \
	python3 \-m venv .venv; \
	.venv/bin/pip install \-r requirements.txt; \
	  cd /opt/platform/src/platform; \
	  export DATABASE_URL=\"postgresql:///sandbox_platform\"; \
	  .venv/bin/python migrations/run.py --status; \
	  .venv/bin/python migrations/run.py; \
	"; \
	curl -fsSLo /usr/local/bin/garage.new "https://garagehq.deuxfleurs.fr/_releases/$(GARAGE_V)/x86_64-unknown-linux-musl/garage"; \
	sha256sum /usr/local/bin/garage.new; \
	install -m 755 -o root -g root /usr/local/bin/garage.new /usr/local/bin/garage; \
	rm /usr/local/bin/garage.new; \
	adduser --system --group --no-create-home --home /nonexistent garage; \
	RPC_SECRET=$$(openssl rand -hex 32); \
	ADMIN_TOKEN=$$(openssl rand -base64 32); \
	mkdir /srv/garagehq/meta; \
	mkdir /srv/garagehq/data; \
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
	chown root:garage /etc/garage.toml && chmod 640 /etc/garage.toml; \
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
	NODE=$$($$G node id -q | cut -d@ -f1) ; \
	$$G layout assign -z lab -c $(S3_QUOTA)G "$$NODE"; \
	$$G layout apply --version 1; \
	$$G layout show; \
	$$G status; \
	mkdir /etc/sandbox_platform ; \
	chown platform:platform /etc/sandbox_platform ; \
	BROWSER_ORIGIN=https://$(SANDBOX_WEB) BUCKET_QUOTA=$(S3_QUOTA)GiB RETENTION_DAYS=$(S3_RETENTION) /opt/platform/src/platform/garage/provision.sh; \
	set -a; . /etc/sandbox_platform/api.env; set +a \
	  /opt/platform/src/platform/.venv/bin/python \
	    /opt/platform/src/platform/garage/conformance.py \
	      --front  https://192.168.1.10:9000 \
	      --direct http://127.0.0.1:3900 \
	      --origin https://$(SANDBOX_WEB); \
	printf "%s\n" \
	"DATABASE_URL=postgresql:///sandbox_platform" \
	"" \
	"# TWO endpoints, and they are not interchangeable. SigV4 signs the Host" \
	"# header, so a URL signed for one host is rejected at the other. Dom0 reaches" \
	"# MinIO over the LAN, browsers reach it through the tunnel." \
	"S3_INTERNAL_ENDPOINT=https://$(VMIP):9000" \
	"S3_PUBLIC_ENDPOINT=https://$(SANDBOX_WEB)" \
	"S3_BUCKET=analysis" \
	"S3_REGION=eu-central-1" \
	"S3_CA_BUNDLE=/etc/sandbox_platform/tls/ca.crt" \
	"JWT_SIGNING_KEY=$$(openssl rand -hex 32)" \
	"JWT_ISSUER=sandbox.evilbootloader.com" \
	"JWT_AUDIENCE=sandbox-platform" \
	"ACCESS_TOKEN_TTL_MINUTES=60" \
	"REFRESH_TOKEN_TTL_DAYS=1" \
	"# --- login throttling ---------------------------------------------------" \
	"# Behind cloudflared the socket peer is ALWAYS the tunnel, so without this" \
	"# every user shares one rate-limit bucket and the per-IP limit is global." \
	"TRUSTED_CLIENT_IP_HEADER=" \
	"ATTEMPTS_PER_WINDOW=5" \
	"WINDOW_LENGTH_MINUTES=5" \
	"LOCKOUT_THRESHOLD=5" \
	"LOCKOUT_DURATION_MINUTES=5" \
	"DECAY_WINDOW_MINUTES=5" \
	"# 4 x 64 MiB argon2id = 256 MiB peak on a 4096 MiB DomU. Raise only with the" \
	"# host, and recompute the PRODUCT -- neither factor alone is the bound." \
	"MAX_CONCURRENT_HASHES=4" \
	"# --- self-service signup ------------------------------------------------" \
	"# OFF unless you want it. What it gates is not \"an account\" but the opening" \
	"# grant of 3600 analysis seconds, so an open2-__ route is free compute for anyone" \
	"# with an email address and a Telegram account. Closed, create_user.py is the" \
	"# only way in -- and password reset still works for accounts that exist." \
	"CONSOLE_ENABLED=True" \
	"REGISTRATION_OPEN=0" >> /etc/sandbox_platform/api.env;
	chmod 600 /etc/sandbox_platform/api.env; \
	chown platform:platform /etc/sandbox_platform/api.env; \
	su - platform -s /bin/bash -c "export CA_ALLOW_HERE=1; /opt/platform/src/tls/issue-cert.sh init; /opt/platform/src/tls/issue-cert.sh server sandbox_web 127.0.0.1 $(SANDBOX_WEB) $(VMIP); /opt/platform/src/tls/issue-cert.sh server s3bucket_web 127.0.0.1 $(SANDBOX_WEB) $(VMIP); /opt/platform/src/tls/issue-cert.sh server dom0-lab 127.0.0.1 $(SANDBOXDIP)"; \
	mv /opt/platform/src/tls/ca/ /etc/sandbox_platform/tls; \
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
	cd /opt/platform/src/platform; \
	sudo -u platform DATABASE_URL=postgresql:///sandbox_platform \
	 .venv/bin/python create_worker.py dom0-1; \
	'

sandboxd:
	@echo "Installing libvmi, drakvuf and sandboxd orquestrator"
	set -e; \
	xl domid $(VM) || xl create $(CFG) || echo "Run make web_vm and make web_sandbox"; \
	cd $(REPO_ROOT); \
	git submodule update --init; \
	cd drakvuf; \
	git submodule update --init; \
	cd libvmi; \
	autoreconf -vif; \
	./configure --disable-kvm --disable-bareflank --disable-file; \
	make; \
	make install; \
	if [ -n "$$LD_LIBRARY_PATH" ]; then \
		echo 'export LD_LIBRARY_PATH=$$LD_LIBRARY_PATH:/usr/local/lib' >> ~/.bashrc; \
	else \
		echo 'export LD_LIBRARY_PATH=/usr/local/lib' >> ~/.bashrc; \
	fi; \
	cd $(REPO_ROOT)/drakvuf/volatility3; \
	git fetch origin pull/650/head; \
	git switch -C pr-650 FETCH_HEAD; \
	python3 ./setup.py build; \
	sudo python3 ./setup.py install; \
	cd $(REPO_ROOT)/drakvuf; \
	meson setup build --native-file llvm.ini; \
	ninja -C build; \
	ninja -C build install; \
	mkdir /etc/sandboxd/tls -p; \
	scp $(VMIP):/etc/sandbox_platform/tls/ca.crt /etc/sandboxd/tls/; \
	scp $(VMIP):/etc/sandbox_platform/tls/dom0-lab.crt /etc/sandboxd/tls/; \
	scp $(VMIP):/etc/sandbox_platform/tls/dom0-lab.key /etc/sandboxd/tls/; \
	cd $(REPO_ROOT); \
	python3 -m venv .venv-sandboxd; \
	.venv-sandboxd/bin/pip install -r sandboxd/requirements.txt; \
	printf "%s\n" \
	"SANDBOXD_API=https://$(VMIP):8000" \
	"SANDBOXD_CACERT=/etc/sandboxd/tls/ca.crt" \
	"SANDBOXD_CLIENT_CERT=/etc/sandboxd/tls/dom0-lab.crt" \
	"SANDBOXD_CLIENT_KEY=/etc/sandboxd/tls/dom0-lab.key" \
	"SANDBOXD_MAX_CLONES=3" \
	"SANDBOXD_TOTAL_MIB=$$(( $$(xl info | grep free_mem | cut -d':' -f2) - 2000 ))" \
	"SANDBOXD_CONSOLE_API=https://$(VMIP):8000" \
	"SANDBOXD_CONSOLE_ENABLED=1" \
	"$$(ssh 192.168.1.12 'sudo -u platform DATABASE_URL=postgresql:///sandbox_platform /opt/platform/src/platform/.venv/bin/python /opt/platform/src/platform/create_worker.py dom0-1 --rotate;' | grep -Eo "WORKER_TOKEN.*")">> /etc/sandboxd/sandboxd.env; \
	sed -i 's|/root/drakvuf-multios-sandbox|$(REPO_ROOT)|g' $(REPO_ROOT)/sandboxd/config.py; \
	sed -i 's/ANALYSIS_USERNAME =.*/ANALYSIS_USERNAME = "$(ANALYSIS_VM_USER)"/g' $(REPO_ROOT)/sandboxd/config.py; \
	sudo lvcreate --type thin-pool -l 90%FREE --poolmetadatasize 16G -n thinpool vg-root



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
	"    - curtin in-target --target=/target -- snap install firefox" \
	"    - curtin in-target --target=/target -- bash -c 'KVER=\$$(ls /boot/vmlinuz-* | sed \"s|/boot/vmlinuz-||\" | sort -V | tail -1); apt-get install -y linux-image-\$${KVER}-dbgsym'" \
	"    - curtin in-target --target=/target -- mkdir -p /etc/gdm3" \
	"    - curtin in-target --target=/target -- sh -c 'printf \"[daemon]\nAutomaticLoginEnable=true\nAutomaticLogin=$(ANALYSIS_VM_USER)\n\" > /etc/gdm3/custom.conf'" \
	"  keyboard:" \
	"    layout: \"es\"" > user-data; \
	touch meta-data; \
	cloud-localds \
		"$(REPO_ROOT)/misc/iso/seed.iso" \
		"$(REPO_ROOT)/misc/iso/cidata/user-data" \
		"$(REPO_ROOT)/misc/iso/cidata/meta-data"; \
	\
	wget "https://releases.ubuntu.com/jammy/ubuntu-22.04.5-live-server-amd64.iso" -O $(REPO_ROOT)/misc/iso/ubuntu-22.04.5-live-server-amd64.iso ; \
	mount $(REPO_ROOT)/misc/iso/ubuntu-22.04.5-desktop-amd64.iso  /mnt; \
	cp /mnt/casper/initrd /mnt/casper/vmlinuz $(REPO_ROOT)/misc/iso/; \
	umount /mnt; \
	printf "%s\n" \
	"arch = 'x86_64'" \
	"name = 'ubuntu_analysis'" \
	"maxmem = 4096" \
	"memory = 4096" \
	"vcpus = 2" \
	"maxvcpus = 2" \
	"builder = 'hvm'" \
	"boot = 'cd'" \
	"hap = 1" \
	"on_poweroff = 'destroy'" \
	"on_reboot = 'restart'" \
	"on_crash = 'destroy'" \
	"vnc = 1" \
	"vnclisten = '0.0.0.0'" \
	"vga = 'stdvga'" \
	"usb = 1" \
	"usbdevice = 'tablet'" \
	"audio = 1" \
	"viridian = 1" \
	"altp2m = 2" \
	"shadow_memory = 32" \
	"vif = [ 'type=ioemu,model=e1000,bridge=xenbr0' ]" \
	"disk = ['phy:/dev/vg-root/ubuntu,hda,w','file:$(REPO_ROOT)/misc/iso/seed.iso,hdb:cdrom,r','file:$(REPO_ROOT)/misc/iso/ubuntu-22.04.5-live-server-amd64.iso,hdc:cdrom,r']" \
	"kernel = '$(REPO_ROOT)/misc/iso/vmlinuz'" \
	"ramdisk = '$(REPO_ROOT)/misc/iso/initrd'" \
	"extra = 'autoinstall'" \
		> $(REPO_ROOT)/misc/xen-vms/ubuntu.cfg; \
	sudo lvcreate -V 1T --thin -n ubuntu vg-root/thinpool; \
	xl create $(REPO_ROOT)/misc/xen-vms/ubuntu.cfg; \
	sed -Ei 's/^kernel.*|^ramdisk.*|^extra.*//g' $(REPO_ROOT)/misc/xen-vms/ubuntu.cfg;
	# TODO "/etc/lvm/lvm.conf" 12-baremetal-trial
	# thin_pool_autoextend_threshold = 80
	# thin_pool_autoextend_percent   = 20
	# sudo systemctl restart lvm2-monitor

windows_analysis_vm:
	@echo "Installing Windows 11 23H2 analysis VM"; \
	set -e; \
	apt install wget genisoimage -y; \
	rm -rf /tmp/win11iso/; \
	mkdir /tmp/win11iso/; \
	wget https://archive.org/download/win-11-23-h-2-english-international-x-64/Win11_23H2_EnglishInternational_x64.iso -O $(REPO_ROOT)/misc/iso/Win11_23H2_EnglishInternational_x64.iso ; \
	sudo mount -o loop,ro $(REPO_ROOT)/misc/iso/Win11_23H2_EnglishInternational_x64.iso /mnt; \
	sudo cp -r /mnt/* /tmp/win11iso/; \
	sudo umount /mnt; \
	cp $(REPO_ROOT)/misc/xen-vms/autounattend.xml /tmp/win11iso/; \
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
	printf "%s\n" \
	"arch = 'x86_64'" \
	"name = 'windows_analysis'" \
	"maxmem = 6144" \
	"memory = 6144" \
	"vcpus = 2" \
	"maxvcpus = 2" \
	"builder = 'hvm'" \
	"boot = 'cd'" \
	"hap = 1" \
	"on_poweroff = 'destroy'" \
	"on_reboot = 'restart'" \
	"on_crash = 'destroy'" \
	"vnc = 1" \
	"vnclisten = '0.0.0.0'" \
	"vga = 'stdvga'" \
	"usb = 1" \
	"usbdevice = 'tablet'" \
	"audio = 1" \
	"viridian = 1" \
	"altp2m = 2" \
	"shadow_memory = 32" \
	"vif = [ 'type=ioemu,model=e1000,bridge=xenbr0' ]" \
	"disk = [ 'phy:/dev/vg-root/windows,hda,w', 'file:$(REPO_ROOT)/misc/iso/Win11_modified.iso,hdc:cdrom,r' ]" > $(REPO_ROOT)/misc/xen-vms/windows.cfg; \
	sudo lvcreate -V 1T --thin -n windows vg-root/thinpool; \
	xl create $(REPO_ROOT)/misc/xen-vms/windows.cfg

modify_windows:
	@echo "Connect through VNC and tune Windows installation, then run setup_hooks"
	xl create $(REPO_ROOT)/misc/xen-vms/windows.cfg

modify_ubuntu:
	@echo "Connect through VNC and tune Ubuntu installation"
	xl create $(REPO_ROOT)/misc/xen-vms/ubuntu.cfg


setup_hooks_windows:
	kpartx -a /dev/vg-root/windows; \
	mount -o ro /dev/mapper/vg--root-windows2 /mnt/; \
	cd $(REPO_ROOT); \
	python3 drakvuf/volatility3/volatility3/framework/symbols/windows/pdbconv.py --guid $$(python3 drakvuf/tools/pdbguid.py /mnt/Windows/System32/ntoskrnl.exe | grep GUID | cut -d' ' -f 2) -p $$(python3 drakvuf/tools/pdbguid.py /mnt/Windows/System32/ntoskrnl.exe | grep Filename | cut -d' ' -f 2) -o $(REPO_ROOT)/profiles/windows.json ; \
	python3 $(REPO_ROOT)/scripts/windows-symbol-profiles.py	--drakvuf $(REPO_ROOT)/drakvuf; \
	umount /mnt; \
	kpartx -d /dev/vg-root/windows; \
	lvcreate -s -kn -n windows_sandbox vg-root/windows; \
	printf "%s\n" \
	"arch = 'x86_64'" \
	"name = 'windows_analysis_sandbox'" \
	"maxmem = 8192" \
	"memory = 8192" \
	"vcpus = 1" \
	"maxvcpus = 1" \
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
	"viridian = 1" \
	"altp2m = 2" \
	"shadow_memory = 32" \
	"vif = [ 'type=ioemu,model=e1000,bridge=xenbr0' ]" \
	"disk = [ 'phy:/dev/vg-root/windows_sandbox,hda,w' ]" > $(REPO_ROOT)/misc/xen-vms/windows_sandbox.cfg; \
	xl create $(REPO_ROOT)/misc/xen-vms/windows_sandbox.cfg; \
	sleep 30; \
	INJECTION_PID=$$(vmi-process-list -d $$(xl domid ubuntu_analysis_sandbox) -j $(REPO_ROOT)/profiles/windows.json \
	    | grep -Eo "\[\s*[0-9]+\]\s*explorer\.exe" | cut -d']' -f1 | grep -Eo "[0-9]+"); \
	echo "INJECTION_PID=$$INJECTION_PID"; \
	xl save windows_analysis_sandbox $(REPO_ROOT)/state/windows_sandbox.bak $(REPO_ROOT)/misc/xen-vms/windows_sandbox.cfg; \
	sed -Ei "s/INJECTION_PID_WINDOWS = .*/INJECTION_PID_WINDOWS = $$INJECTION_PID/g" $(REPO_ROOT)/sandboxd/config.py

setup_hooks_ubuntu:
	kpartx -a /dev/vg-root/ubuntu; \
	kpartx -a /dev/mapper/vg--root-ubuntu3; \
	vgchange -ay ubuntu-vg; \
	lvchange -ay ubuntu-vg/ubuntu-lv; \
	mount /dev/mapper/ubuntu--vg-ubuntu--lv /mnt; \
	mount /dev/mapper/vg--root-ubuntu2 /mnt/boot/; \
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
	printf "%s\n" \
	"arch = 'x86_64'" \
	"name = 'ubuntu_analysis_sandbox'" \
	"maxmem = 8192" \
	"memory = 8192" \
	"vcpus = 1" \
	"maxvcpus = 1" \
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
	"viridian = 1" \
	"altp2m = 2" \
	"shadow_memory = 32" \
	"vif = [ 'type=ioemu,model=e1000,bridge=xenbr0' ]" \
	"disk = ['phy:/dev/vg-root/ubuntu_sandbox,hda,w' ]" \
		> $(REPO_ROOT)/misc/xen-vms/ubuntu_sandbox.cfg; \
	xl create $(REPO_ROOT)/misc/xen-vms/ubuntu_sandbox.cfg; \
	sleep 30; \
	xl save ubuntu_analysis_sandbox $(REPO_ROOT)/state/ubuntu_sandbox.bak $(REPO_ROOT)/misc/xen-vms/ubuntu_sandbox.cfg; \
	sed -Ei "s/INJECTION_PID_UBUNTU = .*/INJECTION_PID_UBUNTU = 1/g" $(REPO_ROOT)/sandboxd/config.py
