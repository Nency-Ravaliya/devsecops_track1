#!/bin/bash
# Install Kind if not present
if ! command -v kind &> /dev/null; then
    echo "Installing Kind..."
    curl -Lo $HOME/.local/bin/kind https://kind.sigs.k8s.io/dl/v0.27.0/kind-darwin-arm64
    chmod +x $HOME/.local/bin/kind
    echo "Kind installed to $HOME/.local/bin/kind"
fi

# Add to PATH
export PATH=$HOME/.local/bin:$PATH

# Check version
kind version