# VPN Dashboard

A self-hosted web dashboard for managing OpenVPN connections. Supports any provider that gives you `.ovpn` config files — pick a country, pick a server, connect.

![screenshot](https://raw.githubusercontent.com/Marc0233/vpn-dashboard/main/screenshot.png)

## Features

- **Multi-provider** — ExpressVPN, NordVPN, Surfshark, ProtonVPN, Mullvad, PIA, Windscribe, CyberGhost, IPVanish, custom
- **Country + server dropdowns** — auto-detects country from filename, shows flag and server count
- **Bulk upload** — drop a single `.ovpn` file or a `.zip` archive of configs
- **Kill switch** — iptables-based, blocks all non-VPN traffic if tunnel drops; LAN SSH and dashboard stay accessible
- **Status cards** — tunnel IP, LAN IP, connected server, uptime, rx/tx
- **Live logs** — last 60 lines from OpenVPN journal
- **Login page** — session auth with SHA-256 hashed credentials

## One-command install

```bash
curl -s https://raw.githubusercontent.com/Marc0233/vpn-dashboard/main/install.sh | sudo bash
```

Or download and run:

```bash
wget https://raw.githubusercontent.com/Marc0233/vpn-dashboard/main/install.sh
sudo bash install.sh
```

The installer will:
- Detect your LAN interface automatically
- Ask for a port (default 8080) and dashboard username/password
- Install Python 3, Flask, and OpenVPN
- Create a systemd service that starts on boot
- Open the firewall port if UFW is active

To uninstall:
```bash
sudo bash install.sh --uninstall
```

## Setup after install

1. Open `http://<your-server-ip>:8080`
2. Log in with the credentials you set during install
3. Click a VPN provider card
4. Upload your `.ovpn` files (or a `.zip` of them)
5. Enter your VPN username and password → **Save Credentials**
6. Pick a country and server → **Connect**

## Requirements

- Ubuntu / Debian (uses `apt`)
- Python 3.8+
- Root access (for iptables and OpenVPN)

## Config

Settings are stored in `/opt/vpn-dashboard/config.json`:

```json
{
  "lan_iface": "eth0",
  "port": 8080,
  "connect_sh": "/etc/openvpn/connect.sh"
}
```

OpenVPN config files go in `/etc/openvpn/providers/<provider-slug>/`.
