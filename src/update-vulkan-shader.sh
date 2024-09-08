#!/bin/sh

set -eu

srcdir=${1:-.}
shader=$srcdir/vulkan-bruteforce.comp
output=$srcdir/vulkan_shader.inc
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/yazc-shader.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT HUP INT TERM

for tool in glslc spirv-val; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		echo "required shader tool not found: $tool" >&2
		exit 1
	fi
done

glslc -O "$shader" -o "$tmpdir/vulkan-bruteforce.spv"
spirv-val "$tmpdir/vulkan-bruteforce.spv"
glslc -O -mfmt=c "$shader" -o "$output"
