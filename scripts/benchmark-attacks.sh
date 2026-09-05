#!/bin/sh

set -eu

usage() {
	cat <<'EOF'
Usage: benchmark-attacks.sh [-h|--help]

Run the brute-force and plaintext performance workloads and summarize the
Runtime values reported by yazc --stats.

Environment:
  YAZC=PATH    yazc executable (default: src/yazc)
  RUNS=N       repetitions for each workload (default: 1)
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

case "$RUNS" in
	''|*[!0-9]*) echo "RUNS must be a positive integer" >&2; exit 2 ;;
esac
if [ "$RUNS" -lt 1 ]; then
	echo "RUNS must be a positive integer" >&2
	exit 2
fi

plain_archive=$ROOT/data/perfdata_ptext.zip
encrypted_archive=$ROOT/data/perfdata_ctext.zip
brute_archive=$ROOT/tests/noradi.zip

for input in "$YAZC" "$plain_archive" "$encrypted_archive" "$brute_archive"; do
	if [ ! -e "$input" ]; then
		echo "required input not found: $input" >&2
		exit 1
	fi
done

tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/yazc-benchmark.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT HUP INT TERM

run_attack() {
	name=$1
	shift
	samples=$tmpdir/$name.samples
	: > "$samples"

	printf '%s\n' "$name"
	printf '  command:'
	for arg in "$@"; do
		printf ' %s' "$arg"
	done
	printf '\n'

	i=1
	while [ "$i" -le "$RUNS" ]; do
		if ! "$@" >"$tmpdir/$name.$i.out" 2>"$tmpdir/$name.$i.err"; then
			echo "  run $i failed:" >&2
			cat "$tmpdir/$name.$i.err" >&2
			cat "$tmpdir/$name.$i.out" >&2
			exit 1
		fi
		runtime=$(awk '/^Runtime:/ { print $2; exit }' "$tmpdir/$name.$i.out")
		if [ -z "$runtime" ]; then
			echo "  run $i did not report Runtime" >&2
			cat "$tmpdir/$name.$i.out" >&2
			exit 1
		fi
		printf '%s\n' "$runtime" >> "$samples"
		i=$((i + 1))
	done

	awk -v runs="$RUNS" -v name="$name" '
		BEGIN { min = -1; max = 0; sum = 0 }
		{
			if (min < 0 || $1 < min) min = $1
			if ($1 > max) max = $1
			sum += $1
		}
		END {
			printf "  runs: %d, min: %.6f secs, max: %.6f secs, average: %.6f secs\n",
			       runs, min, max, sum / runs
		}' "$samples"
}

echo "yazc attack performance report"
echo "Executable: $YAZC"
echo "Runs: $RUNS"
echo

run_attack bruteforce \
	"$YAZC" bruteforce -S -a "$brute_archive"
echo
run_attack plaintext \
	"$YAZC" plaintext -S "$plain_archive" file_0 "$encrypted_archive" file_0
