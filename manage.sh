#!/bin/bash
set -e

# ===========================================
# VPN Stack Smart Management Script
# Dependency checking, Docker management, and interactive setup
# ===========================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== VPN Stack Management ===${NC}"
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

validate_domain_dns() {
    local domain="$1"
    local expected_ip="$2"

    # Check if dig is available, otherwise use host or nslookup
    local resolved_ip=""

    if command -v dig &> /dev/null; then
        resolved_ip=$(dig +short "$domain" A 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
    elif command -v host &> /dev/null; then
        resolved_ip=$(host "$domain" 2>/dev/null | grep "has address" | head -1 | awk '{print $NF}')
    elif command -v nslookup &> /dev/null; then
        resolved_ip=$(nslookup "$domain" 2>/dev/null | grep -A1 "Name:" | grep "Address:" | awk '{print $2}' | head -1)
    else
        echo "no-dns-tool"
        return 2
    fi

    if [ -z "$resolved_ip" ]; then
        echo "unresolved"
        return 1
    fi

    if [ "$resolved_ip" = "$expected_ip" ]; then
        echo "$resolved_ip"
        return 0
    else
        echo "$resolved_ip"
        return 1
    fi
}

validate_email() {
    local email="$1"
    # Basic email validation regex
    if [[ "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        return 0
    else
        return 1
    fi
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

check_dependency() {
    local cmd="$1"
    local name="$2"

    if command -v "$cmd" &> /dev/null; then
        echo -e "  ${GREEN}✓${NC} $name"
        return 0
    else
        echo -e "  ${RED}✗${NC} $name ${YELLOW}(missing)${NC}"
        return 1
    fi
}

install_docker() {
    echo -e "${YELLOW}Installing Docker...${NC}"

    # Detect OS
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    else
        echo -e "${RED}Cannot detect OS${NC}"
        return 1
    fi

    case "$OS" in
        ubuntu|debian)
            sudo apt-get update
            sudo apt-get install -y ca-certificates curl gnupg
            sudo install -m 0755 -d /etc/apt/keyrings
            curl -fsSL https://download.docker.com/linux/$OS/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
            sudo chmod a+r /etc/apt/keyrings/docker.gpg
            echo \
              "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$OS \
              $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
              sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
            sudo apt-get update
            sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
            ;;
        centos|rhel|fedora)
            sudo yum install -y yum-utils
            sudo yum-config-manager --add-repo https://download.docker.com/linux/$OS/docker-ce.repo
            sudo yum install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
            sudo systemctl start docker
            sudo systemctl enable docker
            ;;
        *)
            echo -e "${RED}Unsupported OS: $OS${NC}"
            echo "Please install Docker manually: https://docs.docker.com/engine/install/"
            return 1
            ;;
    esac

    echo -e "${GREEN}✓ Docker installed${NC}"
}

install_wireguard() {
    echo -e "${YELLOW}Installing WireGuard...${NC}"

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    else
        echo -e "${RED}Cannot detect OS${NC}"
        return 1
    fi

    case "$OS" in
        ubuntu|debian)
            sudo apt-get update
            sudo apt-get install -y wireguard wireguard-tools
            ;;
        centos|rhel|fedora)
            sudo yum install -y epel-release elrepo-release
            sudo yum install -y kmod-wireguard wireguard-tools
            ;;
        *)
            echo -e "${RED}Unsupported OS: $OS${NC}"
            echo "Please install WireGuard manually: https://www.wireguard.com/install/"
            return 1
            ;;
    esac

    echo -e "${GREEN}✓ WireGuard installed${NC}"
}

# ===========================================
# Check if Docker is already running
# ===========================================

DOCKER_RUNNING=false
if command -v docker &> /dev/null; then
    if docker compose ps 2>/dev/null | grep -q "Up\|running"; then
        DOCKER_RUNNING=true
    fi
fi

if [ "$DOCKER_RUNNING" = true ]; then
    echo -e "${CYAN}Docker containers are already running.${NC}"
    echo ""
    docker compose ps
    echo ""

    echo -e "${YELLOW}What would you like to do?${NC}"
    echo "  1) Stop containers"
    echo "  2) Restart containers"
    echo "  3) View logs"
    echo "  4) Clean everything (stop, remove containers, volumes, images)"
    echo "  5) Continue to reconfigure and restart"
    echo "  6) Exit"
    echo ""

    read -p "Enter your choice [1-6]: " choice

    case "$choice" in
        1)
            echo -e "${YELLOW}Stopping containers...${NC}"
            docker compose down
            echo -e "${GREEN}✓ Containers stopped${NC}"
            exit 0
            ;;
        2)
            echo -e "${YELLOW}Restarting containers...${NC}"
            docker compose restart
            echo -e "${GREEN}✓ Containers restarted${NC}"
            docker compose ps
            exit 0
            ;;
        3)
            echo -e "${YELLOW}Choose service to view logs:${NC}"
            echo "  1) All services"
            echo "  2) UI"
            echo "  3) API"
            echo "  4) Traefik"
            echo "  5) Headscale"
            echo "  6) AdGuard"
            echo ""
            read -p "Enter your choice [1-6]: " log_choice

            case "$log_choice" in
                1) docker compose logs -f ;;
                2) docker compose logs -f ui ;;
                3) docker compose logs -f api ;;
                4) docker compose logs -f traefik ;;
                5) docker compose logs -f headscale ;;
                6) docker compose logs -f adguard ;;
                *) echo -e "${RED}Invalid choice${NC}"; exit 1 ;;
            esac
            exit 0
            ;;
        4)
            echo -e "${RED}⚠ WARNING: This will remove all containers, volumes, and images!${NC}"
            if prompt_yes_no "Are you sure?" "n"; then
                echo -e "${YELLOW}Cleaning everything...${NC}"
                docker compose down -v --rmi all

                # Clean generated configs
                rm -f headscale/config/config.yaml
                rm -f traefik/traefik.yml
                rm -f traefik/dynamic.yml
                rm -f traefik/acme.json
                rm -f adguard/conf/AdGuardHome.yaml

                # Clean data directories
                rm -rf headscale/data/*
                rm -rf adguard/work/*
                rm -rf traefik/logs/*

                echo -e "${GREEN}✓ Everything cleaned${NC}"
            fi
            exit 0
            ;;
        5)
            echo -e "${YELLOW}Stopping containers for reconfiguration...${NC}"
            docker compose down
            echo ""
            ;;
        6)
            echo -e "${BLUE}Exiting...${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid choice${NC}"
            exit 1
            ;;
    esac
fi

# ===========================================
# Check Dependencies
# ===========================================

echo -e "${BLUE}Checking dependencies...${NC}"
MISSING_DEPS=()

if ! check_dependency "docker" "Docker"; then
    MISSING_DEPS+=("docker")
fi

# Check Docker Compose (plugin or standalone)
if command -v docker &> /dev/null; then
    if docker compose version &> /dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} Docker Compose"
    elif command -v docker-compose &> /dev/null; then
        echo -e "  ${GREEN}✓${NC} Docker Compose (standalone)"
    else
        echo -e "  ${RED}✗${NC} Docker Compose ${YELLOW}(missing)${NC}"
        MISSING_DEPS+=("docker-compose")
    fi
else
    echo -e "  ${RED}✗${NC} Docker Compose ${YELLOW}(missing)${NC}"
    MISSING_DEPS+=("docker-compose")
fi

if ! check_dependency "envsubst" "envsubst (gettext)"; then
    MISSING_DEPS+=("envsubst")
fi

if ! check_dependency "curl" "curl"; then
    MISSING_DEPS+=("curl")
fi

# Check WireGuard
if ! lsmod | grep -q wireguard && ! check_dependency "wg" "WireGuard"; then
    MISSING_DEPS+=("wireguard")
fi

echo ""

# Install missing dependencies
if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
    echo -e "${YELLOW}Missing dependencies detected:${NC}"
    for dep in "${MISSING_DEPS[@]}"; do
        echo "  - $dep"
    done
    echo ""

    if prompt_yes_no "Install missing dependencies?" "y"; then
        for dep in "${MISSING_DEPS[@]}"; do
            case "$dep" in
                docker|docker-compose)
                    install_docker || exit 1
                    ;;
                wireguard)
                    install_wireguard || exit 1
                    ;;
                envsubst)
                    echo -e "${YELLOW}Installing gettext...${NC}"
                    if [ -f /etc/debian_version ]; then
                        sudo apt-get update && sudo apt-get install -y gettext-base
                    elif [ -f /etc/redhat-release ]; then
                        sudo yum install -y gettext
                    fi
                    echo -e "${GREEN}✓ gettext installed${NC}"
                    ;;
                curl)
                    echo -e "${YELLOW}Installing curl...${NC}"
                    if [ -f /etc/debian_version ]; then
                        sudo apt-get update && sudo apt-get install -y curl
                    elif [ -f /etc/redhat-release ]; then
                        sudo yum install -y curl
                    fi
                    echo -e "${GREEN}✓ curl installed${NC}"
                    ;;
            esac
        done
        echo ""
    else
        echo -e "${RED}Cannot proceed without required dependencies${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}✓ All dependencies satisfied${NC}"
echo ""

# ===========================================
# Check Port 53 (DNS) Availability
# ===========================================

echo -e "${BLUE}Checking port 53 availability...${NC}"

if ss -tulpn 2>/dev/null | grep -q ':53 ' || netstat -tulpn 2>/dev/null | grep -q ':53 '; then
    echo -e "${YELLOW}⚠ Port 53 is already in use${NC}"

    # Check if it's systemd-resolved
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        echo -e "  ${YELLOW}systemd-resolved is running and using port 53${NC}"
        echo ""
        echo "AdGuard needs port 53 for DNS. systemd-resolved must be disabled."
        echo ""

        if prompt_yes_no "Disable systemd-resolved to free port 53?" "y"; then
            echo -e "${YELLOW}Disabling systemd-resolved...${NC}"

            sudo systemctl stop systemd-resolved
            sudo systemctl disable systemd-resolved

            # Backup and replace resolv.conf
            if [ -L /etc/resolv.conf ]; then
                sudo rm /etc/resolv.conf
            elif [ -f /etc/resolv.conf ]; then
                sudo mv /etc/resolv.conf /etc/resolv.conf.backup
            fi

            echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf > /dev/null
            echo "nameserver 1.1.1.1" | sudo tee -a /etc/resolv.conf > /dev/null

            echo -e "${GREEN}✓ systemd-resolved disabled${NC}"
            echo -e "${GREEN}✓ DNS temporarily set to 8.8.8.8 and 1.1.1.1${NC}"
        else
            echo -e "${RED}Cannot proceed - port 53 is required for AdGuard DNS${NC}"
            exit 1
        fi
    else
        echo -e "${RED}Port 53 is in use by another service${NC}"
        echo "Please stop the service using port 53 and try again."
        echo "Check with: sudo ss -tulpn | grep :53"
        exit 1
    fi
else
    echo -e "  ${GREEN}✓${NC} Port 53 is available"
fi

echo ""

# ===========================================
# Check Firewall Conflicts (UFW/Fail2ban)
# ===========================================

echo -e "${BLUE}Checking for firewall conflicts...${NC}"

FIREWALL_CONFLICTS=()

# Check UFW
if command -v ufw &> /dev/null; then
    UFW_STATUS=$(sudo ufw status 2>/dev/null | head -1)
    if [[ "$UFW_STATUS" == *"active"* ]]; then
        FIREWALL_CONFLICTS+=("ufw")
        echo -e "  ${YELLOW}⚠${NC} UFW is active"
    else
        echo -e "  ${GREEN}✓${NC} UFW is inactive"
    fi
else
    echo -e "  ${GREEN}✓${NC} UFW not installed"
fi

# Check Fail2ban
if command -v fail2ban-client &> /dev/null; then
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        FIREWALL_CONFLICTS+=("fail2ban")
        echo -e "  ${YELLOW}⚠${NC} Fail2ban is running"
    else
        echo -e "  ${GREEN}✓${NC} Fail2ban is inactive"
    fi
else
    echo -e "  ${GREEN}✓${NC} Fail2ban not installed"
fi

# Check iptables rules (that might conflict with nftables)
IPTABLES_RULES=$(sudo iptables -L -n 2>/dev/null | grep -v "^Chain\|^target\|^$" | wc -l)
if [ "$IPTABLES_RULES" -gt 0 ]; then
    echo -e "  ${YELLOW}⚠${NC} iptables has $IPTABLES_RULES active rules"
fi

echo ""

# Handle conflicts
if [ ${#FIREWALL_CONFLICTS[@]} -gt 0 ]; then
    echo -e "${YELLOW}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║${NC}  ${RED}⚠ FIREWALL CONFLICT DETECTED${NC}                              ${YELLOW}║${NC}"
    echo -e "${YELLOW}╠════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${YELLOW}║${NC}                                                            ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}  Wireguard Admin uses nftables for its firewall.          ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}  The following services may conflict:                     ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}                                                            ${YELLOW}║${NC}"
    for conflict in "${FIREWALL_CONFLICTS[@]}"; do
        printf "${YELLOW}║${NC}    • %-50s ${YELLOW}║${NC}\n" "$conflict"
    done
    echo -e "${YELLOW}║${NC}                                                            ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}  Running both may cause:                                   ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}    - Rule conflicts and unexpected blocking               ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}    - Performance issues                                   ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}    - Duplicate firewall management                        ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}                                                            ${YELLOW}║${NC}"
    echo -e "${YELLOW}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    echo -e "${CYAN}What would you like to do?${NC}"
    echo "  1) Disable conflicting services (recommended)"
    echo "  2) Continue anyway (may cause issues)"
    echo "  3) Exit and resolve manually"
    echo ""

    read -p "Enter your choice [1-3]: " fw_choice

    case "$fw_choice" in
        1)
            echo ""
            for conflict in "${FIREWALL_CONFLICTS[@]}"; do
                case "$conflict" in
                    ufw)
                        echo -e "${YELLOW}Disabling UFW...${NC}"
                        sudo ufw disable
                        echo -e "${GREEN}✓ UFW disabled${NC}"
                        ;;
                    fail2ban)
                        echo -e "${YELLOW}Stopping Fail2ban...${NC}"
                        sudo systemctl stop fail2ban
                        sudo systemctl disable fail2ban
                        echo -e "${GREEN}✓ Fail2ban stopped and disabled${NC}"
                        ;;
                esac
            done
            echo ""
            echo -e "${GREEN}✓ Firewall conflicts resolved${NC}"
            echo -e "${CYAN}Note: Wireguard Admin will manage firewall rules via nftables${NC}"
            ;;
        2)
            echo -e "${YELLOW}Continuing with potential conflicts...${NC}"
            echo -e "${RED}⚠ You may experience firewall issues${NC}"
            ;;
        3)
            echo -e "${BLUE}Exiting...${NC}"
            echo ""
            echo "To resolve manually:"
            for conflict in "${FIREWALL_CONFLICTS[@]}"; do
                case "$conflict" in
                    ufw)
                        echo "  sudo ufw disable"
                        ;;
                    fail2ban)
                        echo "  sudo systemctl stop fail2ban && sudo systemctl disable fail2ban"
                        ;;
                esac
            done
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid choice${NC}"
            exit 1
            ;;
    esac
    echo ""
else
    echo -e "${GREEN}✓ No firewall conflicts detected${NC}"
    echo ""
fi

# ===========================================
# Environment File Setup
# ===========================================

if [ ! -f ".env" ]; then
    echo -e "${YELLOW}No .env file found. Creating from template...${NC}"
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo -e "${GREEN}✓ Created .env from .env.example${NC}"
    else
        echo -e "${RED}ERROR: .env.example not found${NC}"
        exit 1
    fi
fi

# Generate ENCRYPTION_SECRET if not set
if ! grep -q "^ENCRYPTION_SECRET=.\+" .env 2>/dev/null; then
    ENCRYPTION_SECRET=$(openssl rand -hex 32)
    update_env_value "ENCRYPTION_SECRET" "$ENCRYPTION_SECRET"
    echo -e "${GREEN}✓ Generated ENCRYPTION_SECRET${NC}"
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
echo -e "${YELLOW}[1/5] Detecting public IP address...${NC}"
DETECTED_IP=$(detect_public_ip)

if [ -n "$DETECTED_IP" ]; then
    echo -e "Detected IP: ${GREEN}${DETECTED_IP}${NC}"
    if [ -n "$SERVER_IP" ] && [ "$SERVER_IP" != "YOUR_SERVER_IP" ]; then
        echo -e "Current IP in .env: ${YELLOW}${SERVER_IP}${NC}"
    fi

    if prompt_yes_no "Use detected IP ($DETECTED_IP)?" "y"; then
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

# Reload environment
set -a
source .env
set +a

echo ""

# 2. Development Mode
echo -e "${YELLOW}[2/5] Development Mode:${NC}"
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

# 3. Admin Panel Domain (VPN-only)
echo -e "${YELLOW}[3/5] Admin Panel Domain (VPN-only):${NC}"
echo "  Configure a custom domain for the admin panel (requires VPN connection)"
echo ""

read -p "Enter domain name [manage.me]: " ADMIN_DOMAIN
ADMIN_DOMAIN=${ADMIN_DOMAIN:-manage.me}
update_env_value "ADMIN_DOMAIN" "$ADMIN_DOMAIN"
echo -e "${GREEN}✓ Admin domain set to: ${ADMIN_DOMAIN}${NC}"
echo ""

# 4. SSL/HTTPS Configuration
echo -e "${YELLOW}[4/5] SSL/HTTPS Configuration:${NC}"
echo "  Enable automatic HTTPS with Let's Encrypt certificates"
echo ""

# Load existing values
CURRENT_SSL_DOMAIN="${SSL_DOMAIN:-}"
CURRENT_SSL_EMAIL="${LETSENCRYPT_EMAIL:-}"

if prompt_yes_no "Enable HTTPS with Let's Encrypt?" "y"; then
    SSL_ENABLED="true"
    echo ""

    # Get domain
    if [ -n "$CURRENT_SSL_DOMAIN" ]; then
        echo -e "Current SSL domain: ${CYAN}${CURRENT_SSL_DOMAIN}${NC}"
        read -p "Enter domain for SSL certificate (or press Enter to keep current): " SSL_DOMAIN_INPUT
        SSL_DOMAIN="${SSL_DOMAIN_INPUT:-$CURRENT_SSL_DOMAIN}"
    else
        read -p "Enter domain for SSL certificate (e.g., vpn.example.com): " SSL_DOMAIN
        if [ -z "$SSL_DOMAIN" ]; then
            echo -e "${RED}✗ Domain is required for SSL${NC}"
            SSL_ENABLED="false"
        fi
    fi

    if [ "$SSL_ENABLED" = "true" ] && [ -n "$SSL_DOMAIN" ]; then
        # Validate domain DNS
        echo ""
        echo -e "${YELLOW}Validating domain DNS...${NC}"

        DNS_RESULT=$(validate_domain_dns "$SSL_DOMAIN" "$SERVER_IP")
        DNS_STATUS=$?

        if [ $DNS_STATUS -eq 2 ]; then
            echo -e "${YELLOW}⚠ No DNS lookup tool available (dig/host/nslookup)${NC}"
            echo -e "  Cannot verify domain points to this server."
            if prompt_yes_no "Continue anyway? (Make sure $SSL_DOMAIN points to $SERVER_IP)" "n"; then
                echo -e "${YELLOW}⚠ Proceeding without DNS validation${NC}"
            else
                SSL_ENABLED="false"
                echo -e "${YELLOW}SSL disabled - please configure DNS and try again${NC}"
            fi
        elif [ $DNS_STATUS -eq 0 ]; then
            echo -e "${GREEN}✓ Domain $SSL_DOMAIN resolves to $SERVER_IP${NC}"
        else
            if [ "$DNS_RESULT" = "unresolved" ]; then
                echo -e "${RED}✗ Domain $SSL_DOMAIN does not resolve to any IP${NC}"
                echo -e "  Please add an A record pointing to: ${CYAN}${SERVER_IP}${NC}"
            else
                echo -e "${RED}✗ Domain $SSL_DOMAIN resolves to ${DNS_RESULT}, not ${SERVER_IP}${NC}"
                echo -e "  Please update the A record to point to: ${CYAN}${SERVER_IP}${NC}"
            fi
            echo ""
            if prompt_yes_no "Continue anyway? (SSL will fail if DNS is incorrect)" "n"; then
                echo -e "${YELLOW}⚠ Proceeding with mismatched DNS${NC}"
            else
                SSL_ENABLED="false"
                echo -e "${YELLOW}SSL disabled - please fix DNS and run ./manage.sh again${NC}"
            fi
        fi
    fi

    # Get email for Let's Encrypt
    if [ "$SSL_ENABLED" = "true" ]; then
        echo ""
        if [ -n "$CURRENT_SSL_EMAIL" ]; then
            echo -e "Current email: ${CYAN}${CURRENT_SSL_EMAIL}${NC}"
            read -p "Enter email for Let's Encrypt (or press Enter to keep current): " SSL_EMAIL_INPUT
            LETSENCRYPT_EMAIL="${SSL_EMAIL_INPUT:-$CURRENT_SSL_EMAIL}"
        else
            read -p "Enter email for Let's Encrypt notifications: " LETSENCRYPT_EMAIL
        fi

        if [ -n "$LETSENCRYPT_EMAIL" ]; then
            if validate_email "$LETSENCRYPT_EMAIL"; then
                echo -e "${GREEN}✓ Email validated${NC}"
            else
                echo -e "${YELLOW}⚠ Email format looks invalid, but continuing...${NC}"
            fi
        else
            echo -e "${RED}✗ Email is required for Let's Encrypt${NC}"
            SSL_ENABLED="false"
        fi
    fi

    # Save SSL configuration
    if [ "$SSL_ENABLED" = "true" ]; then
        update_env_value "SSL_ENABLED" "true"
        update_env_value "SSL_DOMAIN" "$SSL_DOMAIN"
        update_env_value "LETSENCRYPT_EMAIL" "$LETSENCRYPT_EMAIL"
        echo ""
        echo -e "${GREEN}✓ SSL enabled for: ${SSL_DOMAIN}${NC}"
        echo -e "${GREEN}✓ Certificates will be auto-renewed${NC}"
    else
        update_env_value "SSL_ENABLED" "false"
    fi
else
    SSL_ENABLED="false"
    update_env_value "SSL_ENABLED" "false"
    echo -e "${YELLOW}✓ SSL disabled - using HTTP only${NC}"
    echo -e "  ${CYAN}Tip: Use Cloudflare Flexible SSL if you want HTTPS without local certs${NC}"
fi

echo ""

# 5. Check AdGuard credentials
echo -e "${YELLOW}[5/5] Checking AdGuard credentials...${NC}"

GENERATED_PASSWORD=""

if [ -z "$ADGUARD_PASS_HASH" ] || [ "$ADGUARD_PASS_HASH" = "YOUR_BCRYPT_HASH_HERE" ]; then
    echo -e "${YELLOW}AdGuard password not configured. Generating secure password...${NC}"

    # Generate random 16-character password
    GENERATED_PASSWORD=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 16)

    # Generate bcrypt hash using htpasswd or python
    if command -v htpasswd &> /dev/null; then
        ADGUARD_PASS_HASH=$(htpasswd -nbB admin "$GENERATED_PASSWORD" | cut -d: -f2)
    elif command -v python3 &> /dev/null; then
        ADGUARD_PASS_HASH=$(python3 -c "import bcrypt; print(bcrypt.hashpw('$GENERATED_PASSWORD'.encode(), bcrypt.gensalt()).decode())" 2>/dev/null)
    else
        echo -e "${RED}ERROR: Cannot generate password hash${NC}"
        echo "Please install apache2-utils (htpasswd) or python3 with bcrypt"
        echo "  Ubuntu/Debian: sudo apt install apache2-utils"
        echo "  Or: pip3 install bcrypt"
        exit 1
    fi

    # Save to .env (escape $ for Docker Compose)
    ADGUARD_PASS_HASH_ESCAPED=$(echo "$ADGUARD_PASS_HASH" | sed 's/\$/\$\$/g')
    update_env_value "ADGUARD_PASS_HASH" "$ADGUARD_PASS_HASH_ESCAPED"

    echo -e "${GREEN}✓ Generated secure password${NC}"
fi

if [ -z "$ADGUARD_USER" ]; then
    ADGUARD_USER="admin"
    update_env_value "ADGUARD_USER" "$ADGUARD_USER"
fi

echo -e "${GREEN}✓ AdGuard credentials configured${NC}"
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
    "ADMIN_DOMAIN"
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

# Create acme.json for SSL certificates (if SSL enabled)
if [ "$SSL_ENABLED" = "true" ]; then
    if [ ! -f "traefik/acme.json" ]; then
        touch traefik/acme.json
        chmod 600 traefik/acme.json
        echo "  ✓ traefik/acme.json (created with 600 permissions)"
    else
        # Ensure permissions are correct
        chmod 600 traefik/acme.json
        echo "  ✓ traefik/acme.json (permissions verified)"
    fi
fi

# Headscale config
if [ -f "headscale/config/config.yaml.template" ]; then
    envsubst < headscale/config/config.yaml.template > headscale/config/config.yaml
    echo "  ✓ headscale/config/config.yaml"
fi

# Traefik configs - with SSL support
if [ "$SSL_ENABLED" = "true" ]; then
    echo -e "  ${GREEN}SSL enabled${NC} - configuring Let's Encrypt for ${SSL_DOMAIN}"

    # Generate traefik.yml with SSL configuration
    cat > traefik/traefik.yml << EOF
# Traefik Static Configuration (SSL enabled)
api:
  dashboard: true
  insecure: true

experimental:
  localPlugins:
    silentdrop:
      moduleName: local/silentdrop

entryPoints:
  web:
    address: ":${HTTP_PORT}"
    http:
      redirections:
        entryPoint:
          to: websecure
          scheme: https
  websecure:
    address: ":${HTTPS_PORT}"
  traefik:
    address: ":${TRAEFIK_PORT}"

providers:
  file:
    filename: /etc/traefik/dynamic.yml
    watch: true

certificatesResolvers:
  letsencrypt:
    acme:
      email: ${LETSENCRYPT_EMAIL}
      storage: /etc/traefik/acme.json
      httpChallenge:
        entryPoint: web

log:
  level: INFO
  filePath: /var/log/traefik/traefik.log

accessLog:
  filePath: /var/log/traefik/access.log
  format: json
  fields:
    headers:
      defaultMode: drop
      names:
        User-Agent: keep
        X-Forwarded-For: keep
        X-Real-IP: keep
EOF
    echo "  ✓ traefik/traefik.yml (with SSL)"
elif [ -f "traefik/traefik.yml.template" ]; then
    # Generate traefik.yml without SSL
    envsubst < traefik/traefik.yml.template > traefik/traefik.yml
    echo "  ✓ traefik/traefik.yml"
fi

if [ -f "traefik/dynamic.yml.template" ]; then
    # Convert IGNORE_NETWORKS from comma-separated to YAML list format
    IFS=',' read -ra NETS <<< "$IGNORE_NETWORKS"
    VPN_SOURCE_RANGE=""
    for net in "${NETS[@]}"; do
        VPN_SOURCE_RANGE+="            - \"$net\""$'\n'
    done
    export VPN_SOURCE_RANGE="${VPN_SOURCE_RANGE%$'\n'}"  # Remove trailing newline

    # Generate base dynamic.yml
    envsubst < traefik/dynamic.yml.template > traefik/dynamic.yml

    # If SSL enabled, insert SSL routers before the services section
    if [ "$SSL_ENABLED" = "true" ] && [ -f "traefik/dynamic-ssl-routers.yml.template" ]; then
        # Read SSL routers template and substitute variables
        SSL_ROUTERS=$(envsubst < traefik/dynamic-ssl-routers.yml.template)

        # Insert SSL routers before "  services:" line
        # Using awk to insert content before the services section
        awk -v ssl="$SSL_ROUTERS" '
            /^  services:/ { print ssl }
            { print }
        ' traefik/dynamic.yml > traefik/dynamic.yml.tmp && mv traefik/dynamic.yml.tmp traefik/dynamic.yml

        echo "  ✓ traefik/dynamic.yml (with SSL routers)"
    else
        echo "  ✓ traefik/dynamic.yml"
    fi
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
    docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build "$@"
else
    echo -e "${BLUE}Mode: Production (optimized build)${NC}"
    docker compose up -d --build "$@"
fi

echo ""
echo -e "${GREEN}=== VPN Stack Started ===${NC}"
echo ""
echo -e "${BLUE}Access your services:${NC}"
if [ "$SSL_ENABLED" = "true" ]; then
    echo -e "  ${GREEN}Dashboard:${NC}   https://${SSL_DOMAIN}/ ${CYAN}(SSL enabled)${NC}"
    echo -e "                 or http://${ADMIN_DOMAIN} via VPN"
else
    echo -e "  ${GREEN}Dashboard:${NC}   http://${SERVER_IP}/ (or http://${ADMIN_DOMAIN} via VPN)"
fi
echo -e "  ${GREEN}Traefik:${NC}     http://${SERVER_IP}:${TRAEFIK_PORT}"
echo -e "  ${GREEN}AdGuard:${NC}     http://${SERVER_IP}:${ADGUARD_PORT}"
echo -e "  ${GREEN}API:${NC}         http://${SERVER_IP}:${API_PORT}"
echo ""

if [ "$SSL_ENABLED" = "true" ]; then
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}✓ SSL/HTTPS enabled with Let's Encrypt${NC}                    ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}                                                            ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  Domain: ${YELLOW}${SSL_DOMAIN}${NC}"
    printf "${CYAN}║${NC}  %-56s ${CYAN}║${NC}\n" ""
    echo -e "${CYAN}║${NC}  Certificates will be auto-renewed.                       ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}                                                            ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${YELLOW}Cloudflare settings:${NC}                                      ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}    SSL/TLS → Full (strict)                                ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
fi

if [ -n "$GENERATED_PASSWORD" ]; then
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║${NC}  ${YELLOW}AdGuard Credentials (SAVE THESE!)${NC}                        ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}                                                            ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  Username: ${CYAN}${ADGUARD_USER}${NC}                                        ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  Password: ${CYAN}${GENERATED_PASSWORD}${NC}                            ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}                                                            ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  ${RED}⚠ This password will not be shown again!${NC}                 ${GREEN}║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
else
    echo -e "${YELLOW}AdGuard credentials:${NC} ${ADGUARD_USER} / (password in .env)"
fi

echo -e "${CYAN}Tip: Run ./manage.sh again to manage running containers${NC}"
echo ""
