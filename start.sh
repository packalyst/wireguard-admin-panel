#!/bin/bash
set -e

# ===========================================
# VPN Stack Startup Script
# Interactive setup with auto-detection
# ===========================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== VPN Stack Interactive Setup ===${NC}"
echo ""

# ===========================================
# Helper Functions
# ===========================================

detect_public_ip() {
    # Try multiple services to detect public IP
    local ip=""
    ip=$(curl -s --max-time 3 ifconfig.me 2>/dev/null) || \
    ip=$(curl -s --max-time 3 icanhazip.com 2>/dev/null) || \
    ip=$(curl -s --max-time 3 ipinfo.io/ip 2>/dev/null) || \
    ip=$(curl -s --max-time 3 api.ipify.org 2>/dev/null)
    echo "$ip"
}

prompt_yes_no() {
    local prompt="$1"
    local default="${2:-n}"
    local response

    if [ "$default" = "y" ]; then
        prompt="$prompt [Y/n]: "
    else
        prompt="$prompt [y/N]: "
    fi

    read -p "$prompt" response
    response=${response:-$default}

    [[ "$response" =~ ^[Yy] ]]
}

update_env_value() {
    local key="$1"
    local value="$2"

    if grep -q "^${key}=" .env 2>/dev/null; then
        sed -i "s|^${key}=.*|${key}=${value}|g" .env
    else
        echo "${key}=${value}" >> .env
    fi
}

# ===========================================
# Environment File Setup
# ===========================================

if [ ! -f ".env" ]; then
    echo -e "${YELLOW}No .env file found. Creating from template...${NC}"
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo -e "${GREEN}Created .env from .env.example${NC}"
    else
        echo -e "${RED}ERROR: .env.example not found${NC}"
        exit 1
    fi
fi

# Load existing environment
set -a
source .env 2>/dev/null || true
set +a

# ===========================================
# Interactive Configuration
# ===========================================

echo -e "${BLUE}Configuration:${NC}"
echo ""

# 1. Detect and configure SERVER_IP
echo -e "${YELLOW}[1/3] Detecting public IP address...${NC}"
DETECTED_IP=$(detect_public_ip)

if [ -n "$DETECTED_IP" ]; then
    echo -e "Detected IP: ${GREEN}${DETECTED_IP}${NC}"
    if [ -n "$SERVER_IP" ] && [ "$SERVER_IP" != "YOUR_SERVER_IP" ]; then
        echo -e "Current IP in .env: ${YELLOW}${SERVER_IP}${NC}"
    fi

    if prompt_yes_no "Use detected IP ($DETECTED_IP)?"; then
        SERVER_IP="$DETECTED_IP"
        update_env_value "SERVER_IP" "$SERVER_IP"
        echo -e "${GREEN}✓ SERVER_IP set to: ${SERVER_IP}${NC}"
    else
        read -p "Enter your server IP address: " SERVER_IP
        update_env_value "SERVER_IP" "$SERVER_IP"
        echo -e "${GREEN}✓ SERVER_IP set to: ${SERVER_IP}${NC}"
    fi
else
    echo -e "${YELLOW}Could not auto-detect IP address${NC}"
    if [ -z "$SERVER_IP" ] || [ "$SERVER_IP" = "YOUR_SERVER_IP" ]; then
        read -p "Enter your server IP address: " SERVER_IP
        update_env_value "SERVER_IP" "$SERVER_IP"
        echo -e "${GREEN}✓ SERVER_IP set to: ${SERVER_IP}${NC}"
    else
        echo -e "Using existing IP from .env: ${GREEN}${SERVER_IP}${NC}"
    fi
fi

# Update TRAEFIK_API with SERVER_IP (it uses container IP, keep as is)
# Just reload the env after SERVER_IP update
set -a
source .env
set +a

echo ""

# 2. Development Mode
echo -e "${YELLOW}[2/3] Development Mode:${NC}"
echo "  - Production: Optimized build, nginx server"
echo "  - Development: Hot reload, instant code changes"
echo ""

if prompt_yes_no "Enable development mode with hot reload?" "n"; then
    DEV_MODE="true"
    echo -e "${GREEN}✓ Development mode enabled${NC}"
else
    DEV_MODE="false"
    echo -e "${GREEN}✓ Production mode enabled${NC}"
fi

echo ""

# 3. Check AdGuard credentials
echo -e "${YELLOW}[3/3] Checking configuration...${NC}"

if [ -z "$ADGUARD_USER" ] || [ "$ADGUARD_USER" = "admin" ]; then
    echo -e "${YELLOW}⚠ Using default AdGuard credentials (admin/admin)${NC}"
    echo -e "${YELLOW}  You should change these after first login!${NC}"
fi

if [ -z "$ADGUARD_PASS_HASH" ] || [ "$ADGUARD_PASS_HASH" = "YOUR_BCRYPT_HASH_HERE" ]; then
    echo -e "${RED}ERROR: ADGUARD_PASS_HASH not set${NC}"
    echo "Please set a bcrypt password hash in .env"
    echo "Generate with: htpasswd -nbB admin yourpassword | cut -d: -f2"
    exit 1
fi

echo -e "${GREEN}✓ Configuration validated${NC}"
echo ""

# ===========================================
# List of Required Variables
# ===========================================

REQUIRED_VARS=(
    "SERVER_IP"
    "HTTP_PORT"
    "HTTPS_PORT"
    "TRAEFIK_PORT"
    "API_PORT"
    "ADGUARD_PORT"
    "HEADSCALE_INTERNAL_PORT"
    "STUN_PORT"
    "WG_PORT"
    "DNS_PORT"
    "WG_INTERFACE"
    "WG_IP_RANGE"
    "WG_SERVER_IP"
    "WG_DNS"
    "HEADSCALE_IP_RANGE"
    "HEADSCALE_IP_RANGE_V6"
    "HEADSCALE_BASE_DOMAIN"
    "HEADSCALE_METRICS_PORT"
    "HEADSCALE_GRPC_PORT"
    "DERP_REGION_ID"
    "DERP_REGION_CODE"
    "DERP_REGION_NAME"
    "UPSTREAM_DNS_1"
    "UPSTREAM_DNS_2"
    "UPSTREAM_DNS_3"
    "UPSTREAM_DNS_DOH_1"
    "UPSTREAM_DNS_DOH_2"
    "ADGUARD_USER"
    "ADGUARD_PASS_HASH"
    "ADGUARD_PPROF_PORT"
    "IGNORE_NETWORKS"
    "TRAEFIK_API"
    "RATE_LIMIT_AVERAGE"
    "RATE_LIMIT_BURST"
    "RATE_LIMIT_STRICT_AVERAGE"
    "RATE_LIMIT_STRICT_BURST"
)

# Check all required variables are set
echo -e "${YELLOW}Validating environment variables...${NC}"
MISSING=()
for var in "${REQUIRED_VARS[@]}"; do
    if [ -z "${!var+x}" ]; then
        MISSING+=("$var")
    fi
done

if [ ${#MISSING[@]} -gt 0 ]; then
    echo -e "${RED}ERROR: Missing required environment variables:${NC}"
    for var in "${MISSING[@]}"; do
        echo "  - $var"
    done
    echo ""
    echo "Please check your .env file and ensure all variables are set."
    exit 1
fi

echo -e "${GREEN}✓ All variables validated${NC}"
echo ""

# ===========================================
# Generate Configs from Templates
# ===========================================

echo -e "${YELLOW}Generating config files from templates...${NC}"

# Headscale config
if [ -f "headscale/config/config.yaml.template" ]; then
    envsubst < headscale/config/config.yaml.template > headscale/config/config.yaml
    echo "  ✓ headscale/config/config.yaml"
fi

# Traefik configs
if [ -f "traefik/traefik.yml.template" ]; then
    envsubst < traefik/traefik.yml.template > traefik/traefik.yml
    echo "  ✓ traefik/traefik.yml"
fi

if [ -f "traefik/dynamic.yml.template" ]; then
    envsubst < traefik/dynamic.yml.template > traefik/dynamic.yml
    echo "  ✓ traefik/dynamic.yml"
fi

# AdGuard config
if [ -f "adguard/conf/AdGuardHome.yaml.template" ]; then
    envsubst < adguard/conf/AdGuardHome.yaml.template > adguard/conf/AdGuardHome.yaml
    echo "  ✓ adguard/conf/AdGuardHome.yaml"
fi

echo ""

# ===========================================
# Start Docker Compose
# ===========================================

echo -e "${YELLOW}Starting docker compose...${NC}"

if [ "$DEV_MODE" = "true" ]; then
    echo -e "${BLUE}Mode: Development (hot reload enabled)${NC}"
    docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d "$@"
else
    echo -e "${BLUE}Mode: Production (optimized build)${NC}"
    docker compose up -d "$@"
fi

echo ""
echo -e "${GREEN}=== VPN Stack Started ===${NC}"
echo ""
echo -e "${BLUE}Access your services:${NC}"
echo -e "  ${GREEN}Dashboard:${NC}   http://${SERVER_IP}/"
echo -e "  ${GREEN}Traefik:${NC}     http://${SERVER_IP}:${TRAEFIK_PORT}"
echo -e "  ${GREEN}AdGuard:${NC}     http://${SERVER_IP}:${ADGUARD_PORT}"
echo -e "  ${GREEN}API:${NC}         http://${SERVER_IP}:${API_PORT}"
echo ""
echo -e "${YELLOW}Default credentials:${NC} admin / admin"
echo -e "${YELLOW}⚠ Change password after first login!${NC}"
echo ""
