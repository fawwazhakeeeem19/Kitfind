


set -euo pipefail

REPO="github.com/kitfind/kitfind"
VERSION="1.0.0"
BINARY_NAME="kitfind"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; DIM='\033[2m'; NC='\033[0m'; BOLD='\033[1m'

banner() {
  echo -e "${CYAN}${BOLD}"
  echo ' ██╗  ██╗██╗████████╗███████╗██╗███╗   ██╗██████╗'
  echo ' ██║ ██╔╝██║╚══██╔══╝██╔════╝██║████╗  ██║██╔══██╗'
  echo ' █████╔╝ ██║   ██║   █████╗  ██║██╔██╗ ██║██║  ██║'
  echo ' ██╔═██╗ ██║   ██║   ██╔══╝  ██║██║╚██╗██║██║  ██║'
  echo ' ██║  ██╗██║   ██║   ██║     ██║██║ ╚████║██████╔╝'
  echo ' ╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝'
  echo -e "${NC}${DIM}  Security Reconnaissance Tool v${VERSION} — Authorized Use Only${NC}"
  echo
}

info()    { echo -e "  ${CYAN}→${NC} $1"; }
success() { echo -e "  ${GREEN}✓${NC} $1"; }
error()   { echo -e "  ${RED}✗${NC} $1" >&2; exit 1; }

banner


info "Checking prerequisites..."

command -v go >/dev/null 2>&1 || error "Go not found. Install from https://go.dev/dl/"
GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
info "Go version: ${GO_VERSION}"

MIN_GO="1.21"
if [ "$(printf '%s\n' "$MIN_GO" "$GO_VERSION" | sort -V | head -n1)" != "$MIN_GO" ]; then
  error "Go ${MIN_GO}+ required, found ${GO_VERSION}"
fi


if command -v python3 >/dev/null 2>&1; then
  PY_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
  info "Python version: ${PY_VERSION} (optional modules available)"
fi


info "Downloading dependencies..."
go mod download

success "Dependencies downloaded"

info "Building KitFind..."
CGO_ENABLED=0 go build \
  -ldflags="-s -w -X main.version=${VERSION}" \
  -o "${BINARY_NAME}" \
  ./cmd/kitfind/

success "Build successful: ./${BINARY_NAME}"


if [ "${1:-}" = "--no-install" ]; then
  info "Skipping system install (--no-install). Binary at: ./${BINARY_NAME}"
  exit 0
fi

info "Installing to ${INSTALL_DIR}/${BINARY_NAME}..."
if [ -w "${INSTALL_DIR}" ]; then
  cp "${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
else
  sudo cp "${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
fi
success "Installed to ${INSTALL_DIR}/${BINARY_NAME}"


CONFIG_DIR="${HOME}/.kitfind"
mkdir -p "${CONFIG_DIR}"
if [ ! -f "${CONFIG_DIR}/kitfind.yaml" ]; then
  cp configs/kitfind.yaml "${CONFIG_DIR}/kitfind.yaml"
  success "Config written to ${CONFIG_DIR}/kitfind.yaml"
fi


if command -v python3 >/dev/null 2>&1 && [ -f "modules/python/requirements.txt" ]; then
  info "Installing Python analysis modules (optional)..."
  python3 -m pip install -q -r modules/python/requirements.txt && \
    success "Python modules installed" || \
    echo -e "  ${DIM}⚠ Python modules skipped (not required for core features)${NC}"
fi

echo
success "KitFind v${VERSION} installed successfully!"
echo
echo -e "${DIM}  Quick start:${NC}"
echo -e "    kitfind scan example.com"
echo -e "    kitfind dns example.com --subdomains"
echo -e "    kitfind ssl example.com"
echo -e "    kitfind report example.com -f html"
echo -e "    kitfind tui"
echo
echo -e "${DIM}  Documentation: https://github.com/kitfind/kitfind${NC}"
echo -e "${RED}${BOLD}  ⚠  Authorized use only. Only scan systems you own or have written permission to assess.${NC}"
