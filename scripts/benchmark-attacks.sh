#!/bin/sh

set -eu

usage() {
	cat <<'EOF'
Usage: benchmark-attacks.sh [-h|--help]

Run the brute-force and plaintext performance workloads and summarize the
Runtime values reported by yazc --stats.

Environment:
  YAZC=PATH              yazc executable (default: src/yazc)
  RUNS=N                 repetitions for each workload (default: 1)
  BRUTEFORCE_THREADS=N|auto
                         brute-force worker count (default: auto)
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
BRUTEFORCE_THREADS=${BRUTEFORCE_THREADS:-auto}

case "$RUNS" in
	''|*[!0-9]*) echo "RUNS must be a positive integer" >&2; exit 2 ;;
esac
if [ "$RUNS" -lt 1 ]; then
	echo "RUNS must be a positive integer" >&2
	exit 2
fi

case "$BRUTEFORCE_THREADS" in
	auto) ;;
	''|*[!0-9]*)
		echo "BRUTEFORCE_THREADS must be 'auto' or a positive integer" >&2
		exit 2
		;;
	*)
		if [ "$BRUTEFORCE_THREADS" -lt 1 ]; then
			echo "BRUTEFORCE_THREADS must be 'auto' or a positive integer" >&2
			exit 2
		fi
		;;
esac

plain_archive=$ROOT/data/perfdata_ptext.zip
encrypted_archive=$ROOT/data/perfdata_ctext.zip
brute_archive=$ROOT/data/bruteforce-7char.zip

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
	candidates=$2
	shift 2
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

	awk -v runs="$RUNS" -v candidates="$candidates" '
		BEGIN { min = -1; max = 0; sum = 0 }
		{
			if (min < 0 || $1 < min) min = $1
			if ($1 > max) max = $1
			sum += $1
		}
		END {
			printf "  runs: %d, min: %.6f secs, max: %.6f secs, average: %.6f secs\n",
			       runs, min, max, sum / runs
			if (candidates > 0)
				printf "  average rate: %.3f million candidates/sec\n",
				       candidates / (sum / runs) / 1000000
		}' "$samples"
}

echo "yazc attack performance report"
echo "Executable: $YAZC"
echo "Runs: $RUNS"
echo "Brute-force threads: $BRUTEFORCE_THREADS"
echo

run_attack bruteforce 8353082582 \
	"$YAZC" bruteforce -S -a -l7 -t"$BRUTEFORCE_THREADS" "$brute_archive"
echo
run_attack plaintext 0 \
	"$YAZC" plaintext -S "$plain_archive" file_0 "$encrypted_archive" file_0
