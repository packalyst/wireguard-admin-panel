# WireGuard Admin Panel

A unified web dashboard for managing WireGuard, Headscale (Tailscale-compatible), AdGuard Home DNS, and firewall rules.

## Features

- 🔒 **Dual VPN Management**: WireGuard manual peers + Headscale (Tailscale-compatible) nodes
- 🛡️ **Integrated Firewall**: nftables-based firewall with port management and port scan detection
- 🌐 **DNS Filtering**: AdGuard Home integration with query logging and filtering
- 🚦 **Traffic Monitoring**: Real-time VPN traffic statistics
- 🐳 **Docker Management**: View and control all stack containers
- 🎨 **Modern UI**: Svelte 5 + KTUI CSS framework with dark mode
- 🔄 **Hot Reload**: Development mode with instant UI updates

## Architecture

```
├── Traefik         - Reverse proxy with routing
├── Headscale       - Tailscale control plane (DERP relay)
├── WireGuard       - Manual VPN peers
├── AdGuard Home    - DNS filtering and query logging
├── Unified API     - Go backend (host network mode)
│   ├── /api/wg     - WireGuard management
│   ├── /api/hs     - Headscale management
│   ├── /api/fw     - Firewall management
│   ├── /api/traefik- Traefik configuration
│   ├── /api/adguard- AdGuard settings
│   ├── /api/docker - Container management
│   └── /api/auth   - Authentication
└── UI              - Svelte 5 dashboard
```

## Quick Start

### Prerequisites

- Linux server with root access
- Docker & Docker Compose
- WireGuard kernel module

### Installation

1. Clone the repository:
```bash
git clone https://github.com/YOUR_USERNAME/wireguard-admin-panel.git
cd wireguard-admin-panel
```

2. Copy and configure environment:
```bash
cp .env.example .env
nano .env  # Set YOUR_SERVER_IP and other values
```

3. Start the stack:
```bash
./start.sh
```

### Access

- **Dashboard**: `http://YOUR_SERVER_IP/`
- **Traefik**: `http://YOUR_SERVER_IP:8080`
- **AdGuard**: `http://YOUR_SERVER_IP:8083`
- **API**: `http://YOUR_SERVER_IP:8081`

### First Login

Default credentials (change immediately):
- Username: `admin`
- Password: `admin`

## Development Mode

Enable hot reload for UI development:

```bash
# In .env
DEV_MODE=true

# Start
./start.sh
```

Changes to `.svelte` files will reflect instantly without rebuilding.

## Configuration

### Environment Variables

See `.env.example` for all available options.

Key settings:
- `SERVER_IP` - Your server's public IP
- `WG_IP_RANGE` - WireGuard peer IP range (100.65.0.0/16)
- `HEADSCALE_IP_RANGE` - Headscale/Tailscale IP range (100.64.0.0/16)
- `DEV_MODE` - Enable UI hot reload (true/false)

### Templates

Configuration files are generated from templates in:
- `headscale/config/config.yaml.template`
- `traefik/traefik.yml.template`
- `traefik/dynamic.yml.template`
- `adguard/conf/AdGuardHome.yaml.template`

## Project Structure

```
├── api/                    # Go backend
│   ├── cmd/               # Main entry point
│   ├── internal/          # Business logic
│   │   ├── auth/         # Authentication
│   │   ├── firewall/     # nftables management
│   │   ├── wireguard/    # WireGuard config
│   │   ├── headscale/    # Headscale API proxy
│   │   ├── adguard/      # AdGuard API proxy
│   │   ├── traefik/      # Traefik config
│   │   └── docker/       # Container management
│   └── configs/          # API endpoint configuration
├── ui/                    # Svelte 5 frontend
│   ├── src/
│   │   ├── views/        # Page components
│   │   ├── lib/          # Utilities and API client
│   │   └── App.svelte    # Root component
│   └── vite.config.js    # Build configuration
├── headscale/            # Headscale (Tailscale) config
├── traefik/              # Reverse proxy config
├── adguard/              # DNS filtering config
├── docker-compose.yml    # Production stack
├── docker-compose.dev.yml# Development overrides
└── start.sh              # Startup script
```

## Security

- API requires authentication for all endpoints (except setup)
- Headscale API is restricted to VPN networks only
- Firewall with port scan detection and auto-blocking
- Rate limiting on all API routes
- Security headers (XSS protection, frame deny, etc.)

## License

MIT

## Contributing

Pull requests welcome! Please test thoroughly before submitting.
