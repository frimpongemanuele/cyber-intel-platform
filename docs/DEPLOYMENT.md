# DEPLOYMENT.md — Proxmox homelab, VPN-only

> Status: Phase 10 (2026-11-18). Everything marked **[CI]** is exercised on every pull
> request by `.github/workflows/deploy.yml` against the real Compose stack. The Proxmox
> and Tailscale steps are host setup and are not CI-tested.

## 1. What runs where

```
 Tailscale (HTTPS, *.ts.net cert)
        │  tailscale serve → 127.0.0.1:8080
┌───────▼──────────────────────────── Debian 12 VM (isolated VLAN) ─────────────────────┐
│  web ──────────┐  (net: web, published on loopback only; host rule: no new egress)    │
│                │                                                                       │
│  migrate ──┐   │                                                                       │
│  ingest ───┼── data (internal) ── db (PostgreSQL 16, not published)                    │
│  ai* ──────┤                     ▲                                                     │
│  backup ───┘                     └── backup → ./backups → copy off-host (PBS / NAS)    │
│                                                                                        │
│  ingest ── ingest_out (internal) ──┐                                                   │
│  ai* ───── ai_out (internal) ──────┼── egress (squid) ── internet, allowlisted hosts   │
│  ai* ───── ollama (internal) ── ollama*                     only, CONNECT :443 only   │
└────────────────────────────────────────────────────────────────────────────────────────┘
  * optional profiles
```

| Service | Image | Runs as | Database role | Network reach |
|---|---|---|---|---|
| `db` | `postgres:16-bookworm@sha256:…` | uid 999, no capabilities | — | `data` only, port not published |
| `migrate` (one-shot) | app | uid 10001 | `cit_owner` (owns schema) | `data` |
| `ingest` | app | uid 10001 | `cit_ingest` (facts read/write, no `ai_*`) | `data`, proxy port 3128 |
| `web` | app | uid 10001 | `cit_web` (SELECT; no raw AI output; read-only session) | `data`, loopback-published port |
| `backup` | postgres image | uid 999 | `cit_owner` (dump) | `data` |
| `egress` | Debian + squid | uid 13 | — | internet, allowlisted hosts only |
| `ai` (profile) | app | uid 10001 | `cit_ai` (read facts, append `ai_analyses`) | `data`, proxy port 3129, `ollama` |
| `ollama` (profile) | `ollama/ollama@sha256:…` | image default | — | `ollama` (internal: no internet) |

Every service: read-only root filesystem (except Ollama's model store), `cap_drop: ALL`, `no-new-privileges`, memory/PID limits, bounded logs, secrets as files owned `root:10001` mode `0440` **[CI]**.

## 2. Proxmox VM

1. **Network.** Put the VM on its own VLAN (e.g. tag 40) with no route to your other homelab VLANs. In the Proxmox firewall for the VM NIC: inbound drop everything except SSH from your admin network (or rely on Tailscale SSH) and UDP 41641 (Tailscale direct connections). Outbound: allow TCP 443, DNS to your resolver, NTP, UDP 41641.
2. **VM.** Debian 12, 4 vCPU, 8 GB RAM (16 GB+ if you will run Ollama), 60 GB disk on VirtIO SCSI, `qemu-guest-agent` enabled.
3. **Host basics.** SSH keys only (`PasswordAuthentication no`), `unattended-upgrades`, a non-root admin user.
4. **Docker Engine** from Docker's apt repository (not `docker.io` from Debian), with the Compose plugin. Membership of the `docker` group is root-equivalent; give it only to the admin user.

## 3. Remote access: Tailscale, HTTPS, nothing public

```bash
curl -fsSL https://tailscale.com/install.sh | sh     # or Tailscale's apt repository
sudo tailscale up
# In the Tailscale admin console: enable MagicDNS and HTTPS certificates.
sudo tailscale serve --bg --https=443 http://127.0.0.1:8080
```

The dashboard is then `https://<vm-name>.<tailnet>.ts.net/`, with a valid certificate, reachable only from your tailnet. Restrict it further with a Tailscale ACL (only your user → the VM's port 443). The app's `__Host-` cookies require HTTPS, which `tailscale serve` provides.

Note: behind `tailscale serve` every request reaches the app from 127.0.0.1, so the per-client login throttle acts as a single global budget. That is acceptable for a single-user, VPN-only tool.

## 4. Install

```bash
git clone https://github.com/frimpongemanuele/cyber-intel-platform.git /srv/cit
cd /srv/cit
cp .env.example .env            # set CIT_WEB_ALLOWED_HOSTS=<vm-name>.<tailnet>.ts.net
docker compose build            # base images and every Python package are pinned [CI]
sudo deploy/scripts/make-secrets.sh          # random DB passwords, session key, dashboard password [CI]
sudo deploy/scripts/host-firewall.sh         # web container: no new outbound connections [CI]
docker compose up -d
docker compose ps               # db/web/egress healthy, migrate exited 0 [CI]
```

Make the firewall rule survive reboots, for example with a oneshot unit:

```ini
# /etc/systemd/system/cit-firewall.service
[Unit]
After=docker.service
Requires=docker.service
[Service]
Type=oneshot
ExecStart=/srv/cit/deploy/scripts/host-firewall.sh
[Install]
WantedBy=multi-user.target
```

`sudo systemctl enable --now cit-firewall`. If your Docker uses the nftables firewall backend instead of iptables, add the equivalent rule in Docker's nftables chains.

**Optional keys.** Put an NVD API key in `deploy/secrets/nvd_api_key` (higher rate limit) and keep the ownership and mode (`sudo chown root:10001 …; sudo chmod 0440 …`).

**Import the research archive** (read-only clone of the private repository, e.g. with a read-only deploy key):

```bash
docker compose run --rm -v /srv/cyber-intel-archive:/archive:ro ingest \
  cyberintel.store.archive_import /archive
```

Re-importing replaces archive-origin stories, so validated AI analyses attached to them are removed with them (the runner recreates them on its next pass).

## 5. Optional AI layer

See docs/AI.md. Either:

- **Local model:** set `CIT_AI_PROVIDER=ollama`, `CIT_AI_MODEL=llama3.1:8b` in `.env`, then  
  `docker compose --profile ollama-pull run --rm ollama-pull pull llama3.1:8b` (the only step that gives Ollama internet access) and `docker compose --profile ollama --profile ai up -d`.
- **Hosted API (your key):** `CIT_AI_PROVIDER=anthropic`, `CIT_AI_MODEL=<model id>`, `CIT_AI_PROXY=http://egress:3129`, key in `deploy/secrets/ai_api_key`, then `docker compose --profile ai up -d`. The proxy's AI port allows only `api.anthropic.com`.

Show the panel with `CIT_WEB_AI=1` and `docker compose up -d web`.

## 6. Backups and restore

- The `backup` service writes a custom-format `pg_dump` every 24 h to `CIT_BACKUP_DIR`, verifies it with `pg_restore --list`, writes a SHA-256 next to it, and deletes dumps older than `CIT_BACKUP_KEEP_DAYS` **[CI]**.
- **Get the dumps off the VM.** Mount a Proxmox Backup Server / NAS share as `CIT_BACKUP_DIR` (owned by uid 999), or back up the whole VM with PBS as well. A backup on the same disk is not a backup.
- **Prove restores monthly:**
  ```bash
  docker compose exec db sh /backup-tools/restore-check.sh          # newest dump
  ```
  It verifies the checksum, restores into a scratch database with `--exit-on-error`, checks migrations, core tables and the priority view, then drops the scratch database **[CI]**.
- **Full restore** onto a fresh VM: install as in §4 (new secrets are fine), `docker compose up -d db`, wait until healthy, then
  ```bash
  docker compose exec -T db sh -c 'PGPASSWORD=$(cat /run/secrets/pg_superuser_password) \
    pg_restore --clean --if-exists --no-owner --role=cit_owner -d cit' < backups/cit-<stamp>.dump
  docker compose up -d     # migrate re-applies grants; services start
  ```

## 7. Operations

| Task | Command |
|---|---|
| Status / health | `docker compose ps`; `docker compose logs -f ingest` |
| Upgrade | `git pull` (review the diff), `docker compose build`, `docker compose up -d` (migrations and grants run automatically before services start) |
| Run one source now | `docker compose run --rm ingest cyberintel.ingest --source cisa-kev --force` |
| Change dashboard password | `sudo deploy/scripts/make-secrets.sh --web-password && docker compose up -d web` |
| Rotate a DB password | `docker compose exec db psql -U postgres -d cit -c "ALTER ROLE cit_web PASSWORD '…'"`, write the same value to `deploy/secrets/pg_web_password`, `docker compose up -d web` |
| Add or remove a source | edit `config/sources.toml`, regenerate the proxy config (`python -m cyberintel.deploy squid --ai-host api.anthropic.com > deploy/squid/squid.conf`; CI fails if you forget), `docker compose build && docker compose up -d` |

Pins: Dependabot proposes base-image, Python-lock and Actions updates weekly; each update must pass the build, Trivy scan and the Compose smoke test. The `pins` job in `deploy.yml` re-resolves hashes and digests for review.

## 8. What CI proves on every pull request

| Check | Result on the real stack |
|---|---|
| Images | Build from digest-pinned bases with `pip --require-hashes`; Trivy fails on fixable CRITICAL CVEs; hadolint and shellcheck clean |
| Containers | uid 10001, `CapEff` 0, read-only root, `no_new_privs`, no pip; db/egress/backup read-only with no-new-privileges; db not published; web only on 127.0.0.1 |
| Secrets | Created by the real `make-secrets.sh`; `root:10001 0440` |
| Database | Migrations + grants as `cit_owner`; `cit_web` cannot write or read raw AI output; `cit_ai` cannot touch facts; `cit_ingest` cannot touch `ai_*` or create tables; wrong password refused |
| Egress | Allowlisted host tunnels; other hosts, metadata IP, non-443 ports and plain HTTP refused by the proxy; direct egress impossible from the internal network; web container blocked by the host rule while inbound still works |
| Function | Real CISA KEV ingestion through the proxy; login and an authenticated page over that data; backup and a passing restore check |
