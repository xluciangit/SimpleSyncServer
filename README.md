# Simple Sync Server

[![Ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/xlucian)


A lightweight self-hosted file sync server with a web UI, designed to receive files from the [SimpleSync Companion](https://github.com/xluciangit/SimpleSync-Companion) Android app. Built with Node.js and SQLite, runs entirely in Docker.

---

## Features

- **Web dashboard** — see file counts and sizes
- **Multi-user** — admin creates accounts, each user has their own file space and API key
- **SHA-256 deduplication** — server skips files it already has, saving bandwidth
- **Date-organised storage** — files land in `/data/{username}/{folder}/{dd.mm.yyyy}/`
- **Configurable date format** — per-user `dd.mm.yyyy` or `mm.dd.yyyy`
- **Dark / light / system theme** — per-user preference
- **Large file support** — up to 20 GB per file; a Direct Upload URL bypasses Cloudflare's 100 MB tunnel limit for large files
- **Rate limiting** — login and API endpoints are rate-limited; repeat offenders are permanently IP-blocked
- **Secure sessions** — bcrypt password hashing, session secret stored in DB and survives restarts
- **Cloudflare Tunnel ready** — `trust proxy` is set; secure cookies work over both HTTPS tunnel and direct `http://IP:port`
- **Admin panel** — create/delete users, force password resets, view and unblock IPs

---

## Quick Start

### Using Docker Hub (recommended)

```bash
docker run -d \
  --name simple-sync-server \
  -p 3000:3000 \
  -v /your/path/data:/data \
  -v /your/path/config:/config \
  --restart unless-stopped \
  xlucian1007/simple-sync-server:latest
```

### Using Docker Compose

1. Copy `docker-compose.yml` and edit the volume paths to suit your system.

```yaml
services:
  simple-sync-server:
    image: xlucian1007/simple-sync-server:latest
    container_name: simple-sync-server
    ports:
      - "3000:3000"
    volumes:
      - /your/path/data:/data
      - /your/path/config:/config
    environment:
      - PORT=3000
      - DATA_DIR=/data
      - CONFIG_DIR=/config
    restart: unless-stopped
```

2. Start:

```bash
docker compose up -d
```

3. Open `http://localhost:3000` in your browser.

On first run, the admin credentials are printed to the container logs:

```bash
docker logs simple-sync-server
```

Look for a line like:

```
[FIRST RUN] Admin credentials → username: admin | password: xYz123...
```

---

## Environment Variables

| Variable     | Default    | Description                        |
|--------------|------------|------------------------------------|
| `PORT`       | `3000`     | Port the server listens on inside the container |
| `DATA_DIR`   | `/data`    | Where uploaded files are stored    |
| `CONFIG_DIR` | `/config`  | Where the SQLite database and session secret are stored |

---

## Volumes

| Container path | Purpose |
|----------------|---------|
| `/data`        | Uploaded files — organised as `/data/{username}/{folder}/{date}/` |
| `/config`      | `sss.db` (SQLite database) — persist this to keep users, settings, and file records across container restarts |

---

## Web UI

### Admin account

- Log in at `http://your-server:3000`
- The admin account has no file storage — it is management-only
- Admin is redirected to the **Users** page on login
- From Users you can: create accounts, delete accounts, force password change, view uploaded file counts, and unblock IPs

### User account

- Dashboard shows all sync folders with file listings grouped by date
- Settings page: change password, regenerate API key, set date format, set theme
- The API key shown in Settings is what goes into the Android app

### Admin Settings

- **Direct Upload URL** — set the local `http://LAN-IP:port` address. The Android app fetches this and uses it automatically for files over 100 MB (which exceed Cloudflare's tunnel limit).

---

## API

All API endpoints require the header `x-api-key: <user-api-key>`. The admin account cannot use the API.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/ping` | Health check, no auth required |
| `GET` | `/api/config` | Returns `{ local_url }` — the Direct Upload URL configured by admin |
| `POST` | `/api/check-hash` | Body: `{ hash, folder }` — returns `{ exists: bool }` |
| `POST` | `/api/upload` | Multipart: `file`, `folder`, `relative_path`, `hash`, `android_path` |
| `GET` | `/api/folders` | List user's folders |
| `POST` | `/api/folders` | Create a folder: body `{ name }` |
| `GET` | `/api/stats` | Returns file count and total size for the user |

---

## File Storage Layout

```
/data/
  alice/
    Documents/
      11.03.2025/
        report.pdf
        notes.txt
      12.03.2025/
        invoice.pdf
    Photos/
      11.03.2025/
        IMG_001.jpg
  bob/
    Backup/
      11.03.2025/
        ...
```

---

## Building from Source

```bash
git clone https://github.com/xluciangit/SimpleSyncServer.git
cd SimpleSyncServer
docker build -t simple-sync-server .
docker run -d -p 3000:3000 \
  -v $(pwd)/data:/data \
  -v $(pwd)/config:/config \
  simple-sync-server
```

---

## Cloudflare Tunnel Setup

SimpleSync Server works well behind a Cloudflare Tunnel for remote access:

1. Install and configure `cloudflared` pointing to `http://localhost:3000`
2. Set the Direct Upload URL in Admin → Settings to your **local** `http://LAN-IP:3000`
3. The Android app will automatically use the tunnel for files under 100 MB and the direct URL for larger files when on your home network

---

## Security Notes

- Passwords are hashed with bcrypt (cost 10)
- Sessions use a randomly generated secret stored in the database
- Login endpoint is rate-limited; 10 failed attempts from the same IP result in a permanent block
- API endpoints are separately rate-limited
- Path traversal is guarded on all file operations
- Admin cannot use API keys — the two roles are fully separated

---

## License

MIT
