# LanSync

> Lightweight self-hosted LAN collaboration hub — chat, file sharing, voice, screen share.  
> Zero-configuration, mDNS auto-discovery, PIN protection, SQLite history persistence.

[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/flask-3.0%2B-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/yourname/LanSync)](https://github.com/yourname/LanSync)

LanSync turns any local network into a private multi-device collaboration space. One machine runs the server, every other device on the LAN joins via browser — no app install, no account registration, no cloud dependency.

## ✨ Features

- **💬 Real-time chat** — Text, images, voice messages, typing indicators, read receipts
- **📁 File sharing** — Drag & drop, multi-file, video thumbnails, P2P-ready architecture
- **🎙️ Voice intercom** — Push-to-talk over WebRTC, low latency on local networks
- **🖥️ Screen sharing** — Watch presentations or demos from any device
- **🔍 Auto-discovery** — mDNS (`lansync.local`) + HTTP subnet scan fallback (works even when mDNS is blocked on corporate Wi-Fi)
- **🗂️ Message history** — SQLite persistence, survives restarts, auto-cleans media older than 30 days
- **🔒 PIN protection** — Optional PIN code gate for sensitive networks (no more random neighbors joining)
- **📡 Multi-device sync** — Phone, laptop, desktop all on the same session simultaneously
- **🎤 Webview mode** — Optional native desktop window with pywebview

## 🧱 Tech Stack

| Layer | Tech |
|-------|------|
| Backend | Flask + Flask-SocketIO |
| Frontend | Vanilla JS + Tailwind CSS (CDN) |
| Real-time | WebSocket (polling fallback) |
| P2P | WebRTC (voice, screen) |
| Storage | SQLite (WAL mode) |
| Discovery | mDNS (zeroconf) + HTTP subnet scan |
| Packaging | PyInstaller (Windows .exe) |

## 🚀 Quick Start

### Requirements

- Python 3.9+
- pip

### Install & Run

```bash
git clone https://github.com/yourname/LanSync.git
cd LanSync
pip install -r requirements.txt
python app.py
```

That's it. Open `http://<your-ip>:5050` on this machine, or scan the QR code shown in the terminal from any device on the same LAN.

### One-File Build (Windows)

```bash
pip install pyinstaller
pyinstaller LanSync.spec
# → dist/LanSync/LanSync.exe
```

### Configuration

Edit `config.json`:

```json
{
  "pin_code": "",
  "img_dir": "C:/Users/you/Pictures",
  "invite_token": "optional-private-room-code"
}
```

| Field | Description |
|-------|-------------|
| `pin_code` | Optional access code. Set to non-empty string to gate LAN connections. |
| `img_dir` | Directory for image uploads (relative or absolute path) |
| `invite_token` | Optional secret token for private invites |

## 📸 Screenshots

<!-- TODO: Add screenshots here -->

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                  LanSync Server                      │
│  ┌─────────┐  ┌──────────┐  ┌───────────────────┐  │
│  │  Flask  │  │ SocketIO │  │  SQLite (history) │  │
│  └────┬────┘  └────┬─────┘  └───────────────────┘  │
│       │             │                               │
│  HTTP REST      WebSocket                      mDNS  │
│  (QR, config)   (chat, events)             (discovery)│
└───────┬─────────────┬──────────────────────────────┘
        │             │
   ┌────▼────┐   ┌────▼────┐
   │ Browser │   │ Browser │  ← Any device on LAN
   │ (Phone) │   │ (Laptop) │
   └─────────┘   └─────────┘
        │             │
        └──────┬──────┘
               │ WebRTC (P2P)
          Voice / Screen
```

## 🗺️ Roadmap

- [ ] Multi-room / group channels
- [ ] End-to-end encrypted direct messages
- [ ] PWA offline mode
- [ ] Desktop tray app (systemd / launchd)
- [ ] Docker support

## 🤝 Contributing

Issues and PRs welcome! Please follow the existing code style (2-space indent, snake_case for Python, camelCase for JS).

## 📜 License

Released under the [MIT License](LICENSE).

---

### Why LanSync?

Most LAN chat tools are either over-engineered (Matrix, Mattermost) or toy-grade (abandoned Node demos). LanSync aims for the sweet spot: **production-stable features in a single Python app** that a school IT admin or small business owner can deploy in 30 seconds.

Built with ❤️ for teachers, lab managers, and anyone who just needs a private way to talk to everyone on the Wi-Fi.
