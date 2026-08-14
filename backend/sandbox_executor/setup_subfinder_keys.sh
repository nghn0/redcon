#!/usr/bin/env bash
# Subfinder API Key Setup Script
# Guides you through registering for free API keys and saves them to provider-config.yaml

set -e

CONFIG_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_FILE="$CONFIG_DIR/provider-config.yaml"

echo "=========================================="
echo "  Subfinder API Key Setup"
echo "=========================================="
echo ""
echo "This script helps you set up free API keys for subfinder."
echo "The more keys you configure, the more subdomains subfinder can discover."
echo ""

add_key() {
    local source_name="$1"
    local signup_url="$2"
    local var_name="$3"
    local prompt_text="$4"
    local current_value

    current_value=$(grep -A1 "^# $source_name:" "$CONFIG_FILE" 2>/dev/null | tail -1 | sed 's/^#* *//')

    if [ -n "$current_value" ] && [ "$current_value" != "- YOUR_API_KEY" ] && [ "$current_value" != "- YOUR_SECRET" ]; then
        echo "[SKIP] $source_name already configured."
        return
    fi

    echo ""
    echo "--- $source_name ---"
    echo "  Sign up at: $signup_url"
    echo "  $prompt_text"
    read -p "  Enter API key (or press Enter to skip): " key
    if [ -n "$key" ] && [ "$key" != "YOUR_API_KEY" ] && [ "$key" != "YOUR_SECRET" ]; then
        if [ "$var_name" = "api_key" ]; then
            sed -i "" "s/^#$source_name:\n#  - YOUR_API_KEY/$source_name:\n  - $key/" "$CONFIG_FILE" 2>/dev/null || \
            sed -i "" "s/#  - YOUR_API_KEY/  - $key/" "$CONFIG_FILE"
        elif [ "$var_name" = "api_secret" ]; then
            sed -i "" "0,/#  - YOUR_API_KEY/s//  - $key/" "$CONFIG_FILE"
            sed -i "" "0,/#  - YOUR_SECRET/s//  - $key2/" "$CONFIG_FILE"
        else
            sed -i "" "s/#$source_name:/$source_name:/" "$CONFIG_FILE"
            sed -i "" "s/#  - YOUR_API_KEY/  - $key/" "$CONFIG_FILE"
        fi
        echo "  [OK] $source_name configured."
    else
        echo "  [SKIP] Skipped."
    fi
}

echo "Recommended free API keys (no credit card required):"
echo "  1. SecurityTrails   - 50 queries/month - best coverage"
echo "  2. AlienVault OTX   - Free, unlimited"
echo "  3. URLScan.io       - Free tier"
echo "  4. VirusTotal       - Free tier"
echo "  5. Shodan           - Free tier"
echo "  6. GitHub           - Free with GitHub account"
echo ""

read -p "Configure all recommended sources? (Y/n): " all
all="${all:-Y}"

if [ "$all" = "Y" ] || [ "$all" = "y" ]; then
    # Copy the template config if it doesn't exist
    if [ ! -f "$CONFIG_FILE" ]; then
        cp "$CONFIG_DIR/provider-config.yaml" "$CONFIG_FILE" 2>/dev/null || true
    fi

    echo ""
    echo "Open the following URLs in your browser to sign up for free API keys."
    echo "After signing up, come back and paste the keys here."
    echo ""

    echo "SecurityTrails API (https://securitytrails.com)"
    echo "  Sign up, go to Dashboard > API, copy your API key."
    read -p "  API key (Enter to skip): " st_key
    if [ -n "$st_key" ]; then
        sed -i "" "s/#securitytrails:/securitytrails:/" "$CONFIG_FILE"
        sed -i "" "s/#  - YOUR_API_KEY/  - $st_key/" "$CONFIG_FILE"
        echo "  [OK] SecurityTrails configured."
    fi

    echo ""
    echo "AlienVault OTX (https://otx.alienvault.com)"
    echo "  Sign up, go to Settings > API, copy your API key."
    read -p "  API key (Enter to skip): " av_key
    if [ -n "$av_key" ]; then
        sed -i "" "s/#alienvault:/alienvault:/" "$CONFIG_FILE"
        grep -n "^alienvault:" "$CONFIG_FILE" > /dev/null && \
        sed -i "" "/^alienvault:/a\\"$'\n'"  - $av_key" "$CONFIG_FILE" || true
        echo "  [OK] AlienVault configured."
    fi

    echo ""
    echo "URLScan.io (https://urlscan.io)"
    echo "  Sign up, go to User > API, copy your API key."
    read -p "  API key (Enter to skip): " url_key
    if [ -n "$url_key" ]; then
        sed -i "" "s/#urlscan:/urlscan:/" "$CONFIG_FILE"
        sed -i "" "s/#  - YOUR_API_KEY/  - $url_key/" "$CONFIG_FILE"
        echo "  [OK] URLScan configured."
    fi

    echo ""
    echo "VirusTotal (https://www.virustotal.com/gui/join-us)"
    echo "  Sign up, go to your profile > API key."
    read -p "  API key (Enter to skip): " vt_key
    if [ -n "$vt_key" ]; then
        sed -i "" "s/#virustotal:/virustotal:/" "$CONFIG_FILE"
        sed -i "" "s/#  - YOUR_API_KEY/  - $vt_key/" "$CONFIG_FILE"
        echo "  [OK] VirusTotal configured."
    fi

    echo ""
    echo "Shodan (https://account.shodan.io/register)"
    echo "  Sign up, go to Account > API key."
    read -p "  API key (Enter to skip): " shodan_key
    if [ -n "$shodan_key" ]; then
        sed -i "" "s/#shodan:/shodan:/" "$CONFIG_FILE"
        sed -i "" "s/#  - YOUR_API_KEY/  - $shodan_key/" "$CONFIG_FILE"
        echo "  [OK] Shodan configured."
    fi
fi

echo ""
echo "=========================================="
echo "  Configuration saved to: $CONFIG_FILE"
echo "=========================================="
echo ""
echo "Next steps:"
echo "  1. The config is mounted into the sandbox container automatically"
echo "  2. Run subfinder again — it will now use the configured API keys"
echo "  3. To add more keys later, edit $CONFIG_FILE"
echo ""
