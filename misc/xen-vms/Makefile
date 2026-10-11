SHELL	:= /bin/bash
.ONESHELL:

VM      := platform
CFG     := platform.cfg
VMADDR	:= 192.168.1.12/24
VMIP := $(firstword $(subst /, ,$(VMADDR)))
VMROUTE	:= 192.168.1.1
RSA_KEY	:= ""
SANDBOX_WEB := sandbox.evilbootloader.com
GARAGE_V := v2.4.1
S3_QUOTA := 100
S3_RETENTION := 30
SANDBOXDIP := 192.168.1.6

.PHONY: web_vm web_sandbox up down destroy reboot reset console status ssh clean

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
	BROWSER_ORIGIN=https://$(SANDBOX_WEB) BUCKET_QUOTA=$(S3_QUOTA)GiB RETENTION_DAYS=$(S3_RETENTION) /opt/platform/src/platform/garage/provision.sh; \
	set -a; . /etc/sandbox_platform/api.env; set +a \
	  /opt/platform/src/platform/.venv/bin/python \
	    /opt/platform/src/platform/garage/conformance.py \
	      --front  https://192.168.1.10:9000 \
	      --direct http://127.0.0.1:3900 \
	      --origin https://$(SANDBOX_WEB); \
	mkdir /etc/sandbox_platform/; \
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

up:
	@echo "Starting $(VM)..."
	sudo xl create $(CFG)

down:
	@echo "Gracefully shutting down $(VM)..."
	sudo xl shutdown $(VM)

destroy:
	@echo "Force destroying $(VM)..."
	-sudo xl destroy $(VM)

reboot:
	sudo xl reboot $(VM)

reset:
	-sudo xl destroy $(VM)
	sleep 1
	sudo xl create $(CFG)

console:
	sudo xl console $(VM)

status:
	sudo xl list $(VM)

ssh:
	ssh root@$(VMIP)

clean:
	-sudo xl destroy $(VM)
