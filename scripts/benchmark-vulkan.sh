#!/bin/sh

set -eu

usage() {
	cat <<'EOF'
Usage: benchmark-vulkan.sh [-h|--help]

Run fixed-length Vulkan brute-force workloads for password lengths 6, 7,
and 8. Each archive uses a lowercase password made entirely of 'z', so the
complete search space is evaluated.

Environment:
  YAZC=PATH          yazc executable (default: src/yazc)
  RUNS=N             repetitions for each workload (default: 1)
  VULKAN_DEVICE=N    Vulkan device index (default: 0)
EOF
}

case "${1:-}" in
	'') ;;
	-h|--help)
		usage
		exit 0
		;;
	*)
		echo "unknown option: $1" >&2
		usage >&2
		exit 2
		;;
esac

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
YAZC=${YAZC:-$ROOT/src/yazc}
RUNS=${RUNS:-1}
VULKAN_DEVICE=${VULKAN_DEVICE:-0}
CHARSET=abcdefghijklmnopqrstuvwxyz

case "$RUNS" in
	''|*[!0-9]*) echo "RUNS must be a positive integer" >&2; exit 2 ;;
esac
if [ "$RUNS" -lt 1 ]; then
	echo "RUNS must be a positive integer" >&2
	exit 2
fi

case "$VULKAN_DEVICE" in
	''|*[!0-9]*)
		echo "VULKAN_DEVICE must be a non-negative integer" >&2
		exit 2
		;;
esac

for input in \
	"$YAZC" \
	"$ROOT/data/bruteforce-6char.zip" \
	"$ROOT/data/bruteforce-7char.zip" \
	"$ROOT/data/bruteforce-8char.zip"; do
	if [ ! -e "$input" ]; then
		echo "required input not found: $input" >&2
		exit 1
	fi
done

tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/yazc-vulkan-benchmark.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT HUP INT TERM

if ! "$YAZC" vulkan --list-devices >"$tmpdir/devices.out" \
	2>"$tmpdir/devices.err"; then
	echo "failed to enumerate Vulkan devices:" >&2
	cat "$tmpdir/devices.err" >&2
	exit 1
fi
if ! grep -q "^$VULKAN_DEVICE:" "$tmpdir/devices.out"; then
	echo "Vulkan device $VULKAN_DEVICE is not available" >&2
	cat "$tmpdir/devices.out" >&2
	exit 1
fi

run_workload() {
	length=$1
	candidates=$2
	archive=$3
	password=$4
	name=vulkan-length-$length
	samples=$tmpdir/$name.samples
	: > "$samples"

	printf '%s\n' "$name"
	printf '  candidates: %s\n' "$candidates"
	printf '  command: %s vulkan -S -c %s -l %s --min-length %s --device %s %s\n' \
		"$YAZC" "$CHARSET" "$length" "$length" "$VULKAN_DEVICE" \
		"$archive"

	i=1
	while [ "$i" -le "$RUNS" ]; do
		if ! "$YAZC" vulkan -S -c "$CHARSET" \
			-l "$length" --min-length "$length" \
			--device "$VULKAN_DEVICE" "$archive" \
			>"$tmpdir/$name.$i.out" 2>"$tmpdir/$name.$i.err"; then
			echo "  run $i failed:" >&2
			cat "$tmpdir/$name.$i.err" >&2
			cat "$tmpdir/$name.$i.out" >&2
			exit 1
		fi

		if ! grep -q "^Password is: $password$" \
			"$tmpdir/$name.$i.out"; then
			echo "  run $i returned an unexpected password:" >&2
			cat "$tmpdir/$name.$i.out" >&2
			exit 1
		fi

		runtime=$(awk '/^Runtime:/ { print $2; exit }' \
			"$tmpdir/$name.$i.out")
		if [ -z "$runtime" ]; then
			echo "  run $i did not report Runtime" >&2
			cat "$tmpdir/$name.$i.out" >&2
			exit 1
		fi
		printf '%s\n' "$runtime" >> "$samples"
		i=$((i + 1))
	done

	awk -v runs="$RUNS" -v candidates="$candidates" '
		BEGIN { min = -1; max = 0; sum = 0 }
		{
			if (min < 0 || $1 < min) min = $1
			if ($1 > max) max = $1
			sum += $1
		}
		END {
			average = sum / runs
			printf "  runs: %d, min: %.6f secs, max: %.6f secs, average: %.6f secs\n",
			       runs, min, max, average
			printf "  average rate: %.3f million candidates/sec\n",
			       candidates / average / 1000000
		}' "$samples"
}

echo "yazc Vulkan compute performance report"
echo "Executable: $YAZC"
echo "Runs: $RUNS"
echo "Vulkan device: $VULKAN_DEVICE"
sed -n "s/^$VULKAN_DEVICE: /Device name: /p" "$tmpdir/devices.out"
echo

run_workload 6 308915776 "$ROOT/data/bruteforce-6char.zip" zzzzzz
echo
run_workload 7 8031810176 "$ROOT/data/bruteforce-7char.zip" zzzzzzz
echo
run_workload 8 208827064576 "$ROOT/data/bruteforce-8char.zip" zzzzzzzz
