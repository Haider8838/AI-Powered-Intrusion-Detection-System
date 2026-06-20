#!/usr/bin/env bash
set -euo pipefail

# If MODEL_URLS or MODEL_URL provided, download to /app (skips if file exists)
MODEL_URLS="${MODEL_URLS-}"
MODEL_URL="${MODEL_URL-}"

mkdir -p /app

download_if_missing() {
  url="$1"
  filename=$(basename "$url")
  dest="/app/$filename"
  if [ -f "$dest" ]; then
    echo "Model $filename already present, skipping download."
    return
  fi
  echo "Downloading $url -> $dest"
  if command -v curl >/dev/null 2>&1; then
    curl -fSL "$url" -o "$dest"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$dest" "$url"
  else
    echo "No curl or wget to download models; skipping."
    return
  fi
}

if [ -n "${MODEL_URLS}" ]; then
  IFS=',' read -ra urls <<< "${MODEL_URLS}"
  for u in "${urls[@]}"; do
    download_if_missing "$u"
  done
elif [ -n "${MODEL_URL}" ]; then
  download_if_missing "$MODEL_URL"
fi

# Use PORT env var if provided, default 5000
: "${PORT:=5000}"

exec gunicorn -k eventlet -w 1 server:app -b 0.0.0.0:"${PORT}"
