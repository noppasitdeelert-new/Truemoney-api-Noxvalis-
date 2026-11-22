#!/data/data/com.termux/files/usr/bin/bash
# ngm-panel — Termux installer
#
# Usage (inside Termux):
#   cd ~/ngm-panel
#   bash packaging/termux/install-termux.sh
#
# Installs python + optional Termux:API helpers, installs the package in
# editable mode and drops a launcher in $PREFIX/bin so `ngm-panel` works from
# any directory. Nothing leaves the device.
set -eu

say() { printf '\033[36m[ngm-panel]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[ngm-panel]\033[0m %s\n' "$*"; }

if [ -z "${TERMUX_VERSION:-}" ] && [ "${PREFIX:-}" != *"com.termux"* ]; then
  warn "This script is for Termux. On Windows use packaging\\build.ps1 instead."
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
say "project: $ROOT"

say "updating package lists"
pkg update -y || warn "pkg update failed (continuing)"

say "installing python / git / termux-api"
pkg install -y python git termux-api || warn "termux-api not installed — mobile.* hardware commands will explain how"

if ! command -v python >/dev/null 2>&1; then
  warn "python not found after pkg install; aborting"
  exit 1
fi

say "installing ngm-panel (pip install -e .)"
cd "$ROOT"
python -m pip install --upgrade pip >/dev/null 2>&1 || true
python -m pip install -e .

LAUNCHER="${PREFIX:-/data/data/com.termux/files/usr}/bin/ngm-panel"
say "writing launcher: $LAUNCHER"
cat > "$LAUNCHER" <<'EOF'
#!/data/data/com.termux/files/usr/bin/sh
exec python -m ngm_panel "$@"
EOF
chmod 755 "$LAUNCHER"

say "smoke test"
ngm-panel --version
ngm-panel catalog --check >/dev/null && say "catalog OK" || warn "catalog check failed"

if [ ! -d "$HOME/storage" ]; then
  warn "shared storage not set up yet — run: termux-setup-storage"
fi

cat <<'EOF'

Done. Useful commands:

  ngm-panel doctor
  ngm-panel mobile.doctor
  ngm-panel mobile.status
  ngm-panel help osint
  ngm-panel osint.username <name>
  ngm-panel run

Keep long jobs alive:

  termux-wake-lock
  ngm-panel run
  termux-wake-unlock

EOF
