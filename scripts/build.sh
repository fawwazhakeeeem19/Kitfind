

set -euo pipefail

VERSION="${VERSION:-1.0.0}"
OUTPUT_DIR="./dist"
LDFLAGS="-s -w -X main.version=${VERSION}"

mkdir -p "${OUTPUT_DIR}"

echo "Building KitFind v${VERSION}..."

targets=(
  "linux/amd64"
  "linux/arm64"
  "darwin/amd64"
  "darwin/arm64"
  "windows/amd64"
)

for target in "${targets[@]}"; do
  OS="${target%/*}"
  ARCH="${target#*/}"
  NAME="kitfind-${OS}-${ARCH}"
  [ "${OS}" = "windows" ] && NAME="${NAME}.exe"

  echo -n "  Building ${OS}/${ARCH}... "
  GOOS="${OS}" GOARCH="${ARCH}" CGO_ENABLED=0 \
    go build -ldflags="${LDFLAGS}" -o "${OUTPUT_DIR}/${NAME}" ./cmd/kitfind/
  echo "✓ ${OUTPUT_DIR}/${NAME}"
done

echo
echo "Build complete. Binaries in ${OUTPUT_DIR}/"
ls -lh "${OUTPUT_DIR}/"
