#!/bin/bash
# Generate DKIM keys for KumoMTA
# Usage: ./generate-dkim.sh domain.com [selector]

DOMAIN="${MAIL_DOMAIN:-$1}"
SELECTOR="${DKIM_SELECTOR:-${2:-mail}}"
KEY_DIR="/var/lib/kumomta/dkim"
KEY_FILE="${KEY_DIR}/${DOMAIN}.key"

if [ -z "$DOMAIN" ]; then
    echo "Error: MAIL_DOMAIN environment variable or domain argument required"
    echo "Usage: MAIL_DOMAIN=example.com ./generate-dkim.sh"
    echo "   or: ./generate-dkim.sh example.com [selector]"
    exit 1
fi

mkdir -p "$KEY_DIR"

# Check if key already exists
if [ -f "$KEY_FILE" ]; then
    echo "DKIM key already exists for $DOMAIN"
else
    echo "Generating DKIM key for $DOMAIN..."
    openssl genrsa -out "$KEY_FILE" 2048 2>/dev/null
    chmod 600 "$KEY_FILE"
    echo "DKIM private key generated: $KEY_FILE"
fi

# Extract public key and format for DNS
echo ""
echo "=========================================="
echo "DNS RECORD TO ADD:"
echo "=========================================="
echo ""
echo "Add this TXT record to your DNS:"
echo ""
echo "Host/Name: ${SELECTOR}._domainkey.${DOMAIN}"
echo "Type: TXT"
echo "Value:"
echo ""

# Extract public key, remove headers, join lines
PUBKEY=$(openssl rsa -in "$KEY_FILE" -pubout 2>/dev/null | grep -v "PUBLIC KEY" | tr -d '\n')

echo "v=DKIM1; k=rsa; p=${PUBKEY}"
echo ""
echo "=========================================="
echo ""
echo "Also add these DNS records:"
echo ""
echo "SPF (TXT on ${DOMAIN}):"
echo "v=spf1 ip4:YOUR_SERVER_IP -all"
echo ""
echo "DMARC (TXT on _dmarc.${DOMAIN}):"
echo "v=DMARC1; p=quarantine; rua=mailto:postmaster@${DOMAIN}"
echo ""
echo "=========================================="
