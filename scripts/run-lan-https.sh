#!/usr/bin/env bash
# Run Sendit! on all interfaces with HTTPS so phones on the LAN get crypto.subtle.
# Browsers require a secure context for Web Crypto; plain http://192.168.x.x fails login.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CERT_DIR="${SENDIT_CERT_DIR:-$ROOT/.certs}"
PORT="${SENDIT_PORT:-8443}"
HOST_IP="${SENDIT_LAN_IP:-}"

detect_lan_ip() {
  local ip=""
  # macOS
  if command -v ipconfig >/dev/null 2>&1; then
    ip="$(ipconfig getifaddr en0 2>/dev/null || true)"
    [[ -z "$ip" ]] && ip="$(ipconfig getifaddr en1 2>/dev/null || true)"
  fi
  # Linux: hostname -I (must not trip pipefail / set -e when unavailable)
  if [[ -z "$ip" ]] && command -v hostname >/dev/null 2>&1; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  fi
  # Linux ip route
  if [[ -z "$ip" ]] && command -v ip >/dev/null 2>&1; then
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
  fi
  # macOS: default route interface
  if [[ -z "$ip" ]] && command -v route >/dev/null 2>&1; then
    local iface
    iface="$(route -n get default 2>/dev/null | awk '/interface:/{print $2}' || true)"
    if [[ -n "$iface" ]]; then
      ip="$(ipconfig getifaddr "$iface" 2>/dev/null || true)"
    fi
  fi
  echo "${ip:-127.0.0.1}"
}

if [[ -z "$HOST_IP" ]]; then
  HOST_IP="$(detect_lan_ip)"
fi

echo "Sendit! LAN HTTPS helper"
echo "  project:  $ROOT"
echo "  LAN IP:   $HOST_IP"
echo "  port:     $PORT"
echo ""

mkdir -p "$CERT_DIR"
CERT="$CERT_DIR/lan.pfx"
PASSWORD="sendit-dev"

if [[ ! -f "$CERT" ]]; then
  if ! command -v openssl >/dev/null 2>&1; then
    echo "error: openssl is required to generate a dev certificate." >&2
    exit 1
  fi
  echo "Generating self-signed cert for $HOST_IP (and localhost)…"
  TMP="$(mktemp -d)"
  # Only clean temp on exit from this block — not after exec
  cleanup_tmp() { rm -rf "$TMP"; }
  trap cleanup_tmp EXIT

  OPENSSL_ERR="$TMP/openssl.err"
  if ! openssl req -x509 -newkey rsa:2048 -sha256 -days 825 -nodes \
      -keyout "$TMP/key.pem" -out "$TMP/cert.pem" \
      -subj "/CN=Sendit! LAN Dev" \
      -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:${HOST_IP}" \
      2>"$OPENSSL_ERR"; then
    echo "  (SAN -addext failed; trying basic cert…)"
    cat "$OPENSSL_ERR" >&2 || true
    openssl req -x509 -newkey rsa:2048 -sha256 -days 825 -nodes \
      -keyout "$TMP/key.pem" -out "$TMP/cert.pem" \
      -subj "/CN=${HOST_IP}"
  fi

  openssl pkcs12 -export -out "$CERT" \
    -inkey "$TMP/key.pem" -in "$TMP/cert.pem" \
    -passout "pass:${PASSWORD}"
  cleanup_tmp
  trap - EXIT
  echo "Wrote $CERT"
  echo ""
fi

if [[ ! -f "$CERT" ]]; then
  echo "error: certificate missing at $CERT" >&2
  exit 1
fi

if ! command -v dotnet >/dev/null 2>&1; then
  echo "error: dotnet not found on PATH" >&2
  exit 1
fi

export ASPNETCORE_ENVIRONMENT="${ASPNETCORE_ENVIRONMENT:-Development}"
export ASPNETCORE_URLS="https://0.0.0.0:${PORT}"
export ASPNETCORE_Kestrel__Certificates__Default__Path="$CERT"
export ASPNETCORE_Kestrel__Certificates__Default__Password="$PASSWORD"
export SENDIT_PUBLIC_BASE_URL="https://${HOST_IP}:${PORT}"
export SENDIT_STATIC_ROOT="${SENDIT_STATIC_ROOT:-$ROOT/public}"
export SENDIT_DB_PATH="${SENDIT_DB_PATH:-$ROOT/sendit.dev.db}"

if [[ ! -d "$SENDIT_STATIC_ROOT" ]]; then
  echo "warning: static root not found at $SENDIT_STATIC_ROOT"
  echo "         run: python3 scripts/build-frontend.py"
  echo ""
fi

echo "  On this machine:  https://127.0.0.1:${PORT}"
echo "  On your phone:    https://${HOST_IP}:${PORT}"
echo ""
echo "  Accept the browser security warning once (self-signed cert)."
echo "  Without HTTPS, login crypto fails on mobile (importKey / subtle)."
echo ""
echo "Starting: dotnet run --project src/Sendit.Api --no-launch-profile"
echo ""

cd "$ROOT"
exec dotnet run --project src/Sendit.Api --no-launch-profile
