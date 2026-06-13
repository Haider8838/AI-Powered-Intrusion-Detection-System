#!/usr/bin/env bash
# ============================================================
# AI-Powered IDS — Linux / macOS Setup Script
# Usage:  chmod +x setup_unix.sh && ./setup_unix.sh
# ============================================================

set -e

echo ""
echo "======================================================"
echo " AI-Powered IDS — Linux/macOS Setup"
echo "======================================================"
echo ""

# ── Python check ─────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    echo "[ERROR] python3 not found."
    echo "        Ubuntu/Debian: sudo apt install python3 python3-pip"
    echo "        macOS:         brew install python3"
    exit 1
fi
echo "[OK] $(python3 --version)"

# ── pip upgrade ───────────────────────────────────────────────
echo ""
echo "[*] Upgrading pip..."
python3 -m pip install --upgrade pip -q

# ── libpcap (needed by Scapy) ─────────────────────────────────
OS=$(uname -s)
echo ""
echo "[*] Checking libpcap..."
if [ "$OS" = "Linux" ]; then
    if ! dpkg -l libpcap-dev &>/dev/null 2>&1; then
        echo "[*] Installing libpcap-dev..."
        sudo apt-get install -y libpcap-dev 2>/dev/null || \
        sudo yum install -y libpcap-devel 2>/dev/null || \
        echo "[WARN] Could not auto-install libpcap. Install manually if needed."
    fi
elif [ "$OS" = "Darwin" ]; then
    echo "[OK] macOS has libpcap built-in."
fi

# ── Python packages ───────────────────────────────────────────
echo ""
echo "[*] Installing Python packages (may take a few minutes)..."
python3 -m pip install -r requirements.txt

echo "[OK] Python packages installed."

# ── .env setup ────────────────────────────────────────────────
if [ ! -f .env ]; then
    cp .env.example .env
    echo "[OK] .env created — edit it to add your API keys (optional)."
else
    echo "[OK] .env already exists."
fi

# ── Summary ───────────────────────────────────────────────────
echo ""
echo "======================================================"
echo " Setup Complete!"
echo "======================================================"
echo ""
echo " Run demos (no live capture):"
echo "   python3 ids_app.py"
echo ""
echo " Run with live traffic capture (requires root/sudo):"
echo "   sudo python3 ids_app.py --live"
echo "   sudo python3 ids_app.py --live --duration 120"
echo "   sudo python3 ids_app.py --live --interface eth0"
echo ""
echo " Run the Jupyter notebook:"
echo "   jupyter notebook 'AI_Powered_IDS_Final (1).ipynb'"
echo ""
