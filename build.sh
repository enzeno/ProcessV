#!/bin/zsh
set -euo pipefail

project_dir="${0:A:h}"
build_dir="$project_dir/.build"
dist_dir="$project_dir/dist"
app_dir="$dist_dir/ProcessV.app"

mkdir -p "$build_dir/arm64-cache"
mkdir -p "$build_dir/x86_64-cache"
mkdir -p "$app_dir/Contents/MacOS"

xcrun swiftc \
  -parse-as-library \
  -O \
  -target arm64-apple-macos26.0 \
  -module-cache-path "$build_dir/arm64-cache" \
  "$project_dir/ProcessV.swift" \
  -o "$build_dir/ProcessV-arm64"

xcrun swiftc \
  -parse-as-library \
  -O \
  -target x86_64-apple-macos26.0 \
  -module-cache-path "$build_dir/x86_64-cache" \
  "$project_dir/ProcessV.swift" \
  -o "$build_dir/ProcessV-x86_64"

lipo -create \
  "$build_dir/ProcessV-arm64" \
  "$build_dir/ProcessV-x86_64" \
  -output "$app_dir/Contents/MacOS/ProcessV"

cp "$project_dir/Info.plist" "$app_dir/Contents/Info.plist"
codesign --force --deep --sign - "$app_dir"

echo "Built $app_dir"
file "$app_dir/Contents/MacOS/ProcessV"
