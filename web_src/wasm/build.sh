#!/bin/bash
# Build the post-quantum crypto WASM module and generate integrity hash.
# Run from the gitea root directory: bash web_src/wasm/build.sh

set -e

CRATE_DIR="web_src/wasm/gitea-crypto"
OUT_DIR="public/assets/wasm"

echo "Building gitea-crypto WASM module..."
cd "$CRATE_DIR"

# Build with wasm-pack for web target
wasm-pack build --target web --release --out-dir "../../../$OUT_DIR"

cd "../../.."

# Remove unnecessary files
rm -f "$OUT_DIR/package.json" "$OUT_DIR/.gitignore" "$OUT_DIR/README.md"

# Generate integrity hash
WASM_FILE="$OUT_DIR/gitea_crypto_bg.wasm"
HASH=$(sha256sum "$WASM_FILE" | cut -d' ' -f1)
echo "$HASH" > "$OUT_DIR/gitea_crypto_bg.wasm.sha256"

echo ""
echo "Build complete!"
echo "  WASM: $WASM_FILE ($(wc -c < "$WASM_FILE") bytes)"
echo "  SHA-256: $HASH"
echo ""
echo "Users can verify integrity with:"
echo "  sha256sum $WASM_FILE"
echo "  Expected: $HASH"
