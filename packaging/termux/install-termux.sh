#!/data/data/com.termux/files/usr/bin/bash
# ngm-panel — Termux installer / updater
#
# Usage (inside Termux):
#   bash packaging/termux/install-termux.sh            # first install
#   bash packaging/termux/install-termux.sh --update   # pkg + git pull + reinstall
#
# Installs python + git (+ optional Termux:API helpers), installs the package in
# editable mode and drops a launcher in $PREFIX/bin so `ngm-panel` works from
# any directory. Nothing leaves the device.
set -eu

MODE="install"
for arg in "$@"; do
  case "$arg" in
    --update) MODE="update" ;;
    -h|--help)
      sed -n '2,9p' "$0"
      exit 0
      ;;
    *)
      printf 'unknown option: %s (try --help)\n' "$arg" >&2
      exit 2
      ;;
  esac
done

say() { printf '\033[36m[ngm-panel]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[ngm-panel]\033[0m %s\n' "$*"; }
die() { printf '\033[31m[ngm-panel]\033[0m %s\n' "$*" >&2; exit 1; }

if [ -z "${TERMUX_VERSION:-}" ] && [ "${PREFIX:-}" != *"com.termux"* ]; then
  warn "This script is for Termux. On Windows use packaging\\build.ps1 instead."
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
if [ ! -f "$ROOT/pyproject.toml" ]; then
  if [ -f "$HOME/ngm-panel/pyproject.toml" ]; then
    ROOT="$HOME/ngm-panel"
  else
    die "ngm-panel checkout not found. Run: git clone https://github.com/noppasitdeelert-new/Truemoney-api-Noxvalis- ~/ngm-panel"
  fi
fi
say "project: $ROOT"
say "mode: $MODE"

say "updating package lists"
pkg update -y || warn "pkg update failed (continuing)"

if [ "$MODE" = "update" ]; then
  say "upgrading installed packages"
  pkg upgrade -y || warn "pkg upgrade failed (continuing)"
fi

say "installing python / git / termux-api"
pkg install -y python git termux-api || warn "termux-api not installed — mobile.* hardware commands will explain how"

command -v python >/dev/null 2>&1 || die "python not found after pkg install"
command -v git >/dev/null 2>&1 || die "git not found after pkg install"

if [ -d "$ROOT/.git" ]; then
  say "git pull --ff-only"
  git -C "$ROOT" pull --ff-only || warn "git pull failed — continuing with the current checkout"
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
  ngm-panel update --check    # ตรวจว่ามี pkg/git/pip ครบไหม
  ngm-panel update --run      # pkg update/upgrade + git pull + pip install -e .
  bash packaging/termux/install-termux.sh --update   # อัปเดตด้วยสคริปต์นี้
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
