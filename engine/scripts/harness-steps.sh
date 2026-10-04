# Step bookkeeping for hardware-validation.sh. Sourced, never executed.
#
# Split out so it can be tested without a device. The Phase A run that produced
# results-20260904T163645Z printed "COMPLETE" over a wipe that covered 512 bytes
# of a 7.76 GB stick: the erase engine had already written "purge_achieved":
# false, the verifier had already written "passed": false, the report step had
# already crashed, and the console said none of it. Every function here exists
# so that a failure has to be printed and has to reach the exit status.
#
# The caller defines say/note/warn. Fallbacks are defined here only so the file
# can be sourced on its own by the test suite.

declare -F note >/dev/null || note() { printf '   %s\n' "$*"; }
declare -F warn >/dev/null || warn() { printf '   ! %s\n' "$*"; }

#: One entry per failed phase, "label: reason". The run's exit status.
HARNESS_FAILURES=()

harness_reset() { HARNESS_FAILURES=(); }

# Record a failed phase and say so on the console.
harness_fail() {
    local label="$1" reason="$2"
    HARNESS_FAILURES+=("$label: $reason")
    warn "$label FAILED: $reason"
}

# Print a step's captured stderr. A traceback in a file nobody reads is the
# same as no traceback: A.7 crashed on a key path and the console stayed blank.
harness_dump_err() {
    local err="$1"
    [[ -s "$err" ]] || return 0
    note "--- stderr: $err ---"
    while IFS= read -r line; do note "| $line"; done < "$err"
    note "--- end stderr ---"
}

# Judge one step. Non-zero exit is a failure; so is a zero-byte output file,
# because a step that exits 0 and writes nothing has measured nothing.
harness_check() {
    local label="$1" rc="$2" out="$3" err="$4"
    if [[ "$rc" -ne 0 ]]; then
        harness_fail "$label" "exit $rc"
        harness_dump_err "$err"
        return 1
    fi
    if [[ ! -s "$out" ]]; then
        harness_fail "$label" "exit 0 but $out is zero bytes"
        harness_dump_err "$err"
        return 1
    fi
    # Non-empty is not the same as usable. A step that writes a log line to
    # stdout ahead of its JSON exits 0 and produces a non-empty file that
    # json.loads refuses, and every reader downstream then reports an empty
    # field over a value that was computed correctly. The KEY step did exactly
    # that for 33 minutes of a --full stage:
    #
    #   2026-09-05 15:12:08 [info  ] signing_key_created  path=.../key.pem
    #   {"fingerprint": "27:9F:14:..."}
    #
    # A step whose output cannot be parsed has not succeeded, whatever its exit
    # status said. Checked here so it stops the run at the step that produced
    # it rather than surfacing as an empty string somewhere later.
    if [[ "$out" == *.json ]] && ! harness_json_parses "$out"; then
        harness_fail "$label" "exit 0 but $out is not parsable JSON"
        note "     first line: $(head -c 200 "$out" | head -1)"
        harness_dump_err "$err"
        return 1
    fi
    return 0
}

# True when the file holds one JSON document and nothing else.
harness_json_parses() {
    "$PY" - "$1" <<'PYTHON' 2>/dev/null
import json
import sys

try:
    json.loads(open(sys.argv[1]).read())
except (OSError, ValueError):
    raise SystemExit(1)
raise SystemExit(0)
PYTHON
}

# ==========================================================================
# Where large output is allowed to land.
#
# PhotoRec's dovecot signature emits one 81,920-byte file per all-zero 80 KiB
# block, so a device holding 0x00 produces a recup tree roughly the size of the
# device: a zeroed 7.4 GiB stick gave 94,720 files, 7.76 GB. Under mktemp -d on
# a host where /tmp is tmpfs, all of that is written into RAM. It does not fail.
# The host starts swapping, and a swapping host presents as 1% CPU, no progress,
# a clean dmesg and no error at all - forty minutes of a rehearsal window spent
# looking for a hang that was a full memory disk.
#
# The first fix for this was a warning. A warning read at 2am is not a guard, so
# these refuse.
# ==========================================================================

#: Where to relocate when TMPDIR is memory-backed. Overridable for tests.
HARNESS_WORKDIR_FALLBACK="${HARNESS_WORKDIR_FALLBACK:-/var/tmp}"

#: Filesystem types that are RAM wearing a directory's clothes.
HARNESS_MEMORY_FSTYPES="tmpfs ramfs"

# The filesystem type backing a path, or "" if it cannot be determined.
harness_fstype() {
    df --output=fstype "$1" 2>/dev/null | tail -1 | tr -d '[:space:]'
}

# True when a path is backed by memory rather than by a disk.
harness_is_memory_fs() {
    local fstype="$1" candidate
    for candidate in $HARNESS_MEMORY_FSTYPES; do
        [[ "$fstype" == "$candidate" ]] && return 0
    done
    return 1
}

# Bytes available to a non-root writer at a path. 0 when it cannot be read,
# which is deliberately the answer that fails a size check rather than one that
# passes it.
harness_free_bytes() {
    local avail
    avail="$(df --output=avail -B1 "$1" 2>/dev/null | tail -1 | tr -d '[:space:]')"
    [[ "$avail" =~ ^[0-9]+$ ]] || avail=0
    printf '%s' "$avail"
}

# Size of a device or image file in bytes, or 0 when neither.
harness_device_bytes() {
    local target="$1"
    if [[ -b "$target" ]]; then
        blockdev --getsize64 "$target" 2>/dev/null || printf '0'
    elif [[ -f "$target" ]]; then
        stat -c%s "$target" 2>/dev/null || printf '0'
    else
        printf '0'
    fi
}

# Bytes as the units the device vendor and the demo script both quote.
harness_gb() {
    awk -v bytes="$1" 'BEGIN { printf "%.2f GB", bytes / 1000000000 }'
}

#: Set by harness_workdir on success. Read it there, not from a subshell: the
#: function prints its reasoning to stdout, so command substitution would
#: swallow the explanation this exists to give.
HARNESS_WORKDIR=""

# Choose a work directory that can actually hold what the run will write.
#   harness_workdir <bytes the run may write>
#
# Refuses rather than warns, on either count: a memory-backed filesystem with no
# disk-backed fallback, or a volume with less free space than the run needs.
# Sets HARNESS_WORKDIR and returns 0, or explains and returns 1.
harness_workdir() {
    local need="${1:-0}"
    local base="${TMPDIR:-/tmp}"
    HARNESS_WORKDIR=""

    local fstype; fstype="$(harness_fstype "$base")"
    if harness_is_memory_fs "$fstype"; then
        local fallback="$HARNESS_WORKDIR_FALLBACK"
        local fallback_fstype; fallback_fstype="$(harness_fstype "$fallback")"
        warn "$base is $fstype - memory, not disk. Output written there is RAM,"
        warn "  and a carve of a zeroed device can reach the size of the device."
        if [[ ! -d "$fallback" ]] || harness_is_memory_fs "$fallback_fstype"; then
            warn "  $fallback is ${fallback_fstype:-not a directory} too, so there is"
            warn "  nowhere disk-backed to relocate to. Set TMPDIR to a real"
            warn "  filesystem and run this again."
            return 1
        fi
        base="$fallback"
        note "work directory relocated to $base ($fallback_fstype), because"
        note "  $fstype cannot hold a recup tree without holding it in memory"
    fi

    local free; free="$(harness_free_bytes "$base")"
    if [[ "$need" -gt 0 && "$free" -lt "$need" ]]; then
        warn "$base has $(harness_gb "$free") free, and this run can write up to"
        warn "  $(harness_gb "$need") - a recup tree reaches the size of the device"
        warn "  it was carved from. Free space there, or point TMPDIR at a volume"
        warn "  that has it."
        return 1
    fi

    local dir
    if ! dir="$(TMPDIR="$base" mktemp -d -t sanctum-work.XXXXXXXX 2>/dev/null)"; then
        warn "could not create a work directory under $base"
        return 1
    fi
    HARNESS_WORKDIR="$dir"
    note "work    $dir ($(harness_fstype "$dir"), $(harness_gb "$free") free)"
    return 0
}

# Run one command, capture stdout/stderr to files, and judge it.
#   harness_step <label> <out.json> <err file> <argv...>
harness_step() {
    local label="$1" out="$2" err="$3"
    shift 3
    "$@" > "$out" 2> "$err"
    harness_check "$label" "$?" "$out" "$err"
}

# ==========================================================================
# PhotoRec
#
# One definition, sourced by both the validation harness and the demo reset.
# They had two, and the whole point of the before/after count is that the two
# runs are the same measurement - a difference either script could acquire
# without anyone noticing is a difference in a number we put on a slide.
#
# The option set is the one recorded in docs/validation/hardware.md, which is
# what makes a demo run comparable to the Phase A figures. Narrowing it is a
# deliberate act, not a default: see SANCTUM_PHOTOREC_OPTS below.
# ==========================================================================

declare -F now >/dev/null || now() { date +%s; }
declare -F since >/dev/null || since() { echo $(( $(date +%s) - $1 )); }

#: The recorded invocation. Every published before/after number used this.
HARNESS_PHOTOREC_OPTS_FULL="partition_none,fileopt,everything,enable,search"

#: Only the formats the demo actually plants, for a rehearsal where wall-clock
#: matters more than comparability. Fewer signatures also means fewer false
#: positives. It is NOT the default: a run using this cannot be compared with
#: the figures in docs/validation/hardware.md, and the 14-of-14 slide depends
#: on that comparison holding.
HARNESS_PHOTOREC_OPTS_PLANTED="partition_none,fileopt,everything,disable,jpg,enable,png,enable,pdf,enable,zip,enable,gif,enable,sqlite,enable,search"

#: Seconds before a PhotoRec call is killed. Both recorded Phase A runs on a
#: 7.4 GiB stick finished in 309s and 563s, so 1500 is roughly 2.6x the worst
#: measurement - long enough to be certain, short enough that it cannot eat a
#: pre-demo window. Read at call time, not here: an override has to work when
#: it is set on the call, which is where an operator will reach for it.
HARNESS_PHOTOREC_TIMEOUT_S=1500

#: How often the console says the scan is alive. A step that can run for
#: minutes in silence is indistinguishable from one that has hung, and that
#: cost an evening.
HARNESS_PHOTOREC_HEARTBEAT_S=30

# Count recovered files, excluding PhotoRec's own report and log.
harness_photorec_count() {
    local outdir="$1"
    find "$outdir" -path "$outdir/recup*" -type f \
        ! -name 'report.xml' ! -name '*.log' 2>/dev/null | wc -l
}

# Run one scan, with a bound and a pulse.
#   harness_photorec <label> <device> <outdir> <json out>
# Returns non-zero when the scan failed or timed out. Always writes the JSON.
harness_photorec() {
    local label="$1" device="$2" outdir="$3" json="$4"
    local opts="${SANCTUM_PHOTOREC_OPTS:-$HARNESS_PHOTOREC_OPTS_FULL}"
    local timeout_s="${SANCTUM_PHOTOREC_TIMEOUT_S:-$HARNESS_PHOTOREC_TIMEOUT_S}"
    local heartbeat_s="${SANCTUM_PHOTOREC_HEARTBEAT_S:-$HARNESS_PHOTOREC_HEARTBEAT_S}"
    local log="$outdir/photorec.out"

    mkdir -p "$outdir"

    # A recup tree on tmpfs is a recup tree in RAM. PhotoRec's dovecot signature
    # emits an 81,920-byte file per all-zero block, so a zeroed 7.4 GiB device
    # produces 94,720 of them - 7.76 GB into memory, which does not fail, it
    # swaps, and a swapping host looks exactly like a hung one. This used to
    # warn. Refusing is the only version of it that works on a tired operator.
    local fstype
    fstype="$(harness_fstype "$outdir")"
    if harness_is_memory_fs "$fstype"; then
        harness_fail "photorec $label" \
            "$outdir is $fstype - memory, not disk. A carve of a zeroed device fills it and the host swaps instead of failing."
        note "  set TMPDIR to a real filesystem, or pass an output directory on one"
        printf '{"skipped": "output directory is %s, which is memory-backed"}\n' \
            "$fstype" > "$json"
        return 1
    fi

    # The size check is separate from the filesystem check because a disk-backed
    # volume with 2 GB free fails the same way tmpfs does, only with ENOSPC in a
    # log nobody is reading. The recup tree can reach the size of the device.
    local need; need="$(harness_device_bytes "$device")"
    local free; free="$(harness_free_bytes "$outdir")"
    if [[ "$need" -gt 0 && "$free" -lt "$need" ]]; then
        harness_fail "photorec $label" \
            "$outdir has $(harness_gb "$free") free; a carve of $device can write $(harness_gb "$need")."
        printf '{"skipped": "insufficient free space at output directory"}\n' > "$json"
        return 1
    fi

    note "photorec $label: scanning $device"
    note "  options  $opts"
    note "  output   $outdir"
    note "  bound    ${timeout_s}s, heartbeat every ${heartbeat_s}s"

    local start; start="$(now)"
    timeout --signal=TERM --kill-after=30 "${timeout_s}s" \
        photorec /log /d "$outdir/recup" /cmd "$device" "$opts" \
        > "$log" 2>&1 &
    local pid=$!

    while kill -0 "$pid" 2>/dev/null; do
        sleep "$heartbeat_s"
        kill -0 "$pid" 2>/dev/null || break
        note "  ... ${label} alive at $(since "$start")s, $(harness_photorec_count "$outdir") files, $(du -sh "$outdir" 2>/dev/null | cut -f1) on disk"
    done
    wait "$pid"; local rc=$?

    local elapsed; elapsed="$(since "$start")"
    local count; count="$(harness_photorec_count "$outdir")"
    local timed_out=false

    # 124 is what `timeout` exits when it fired. Named, because "photorec failed"
    # and "photorec was still running after 25 minutes" lead to different actions.
    if [[ $rc -eq 124 || $rc -eq 137 ]]; then
        timed_out=true
        harness_fail "photorec $label" \
            "still running after ${timeout_s}s and was killed"
        note "  the partial recup tree is at $outdir"
        note "  tail of $log:"
        tail -5 "$log" 2>/dev/null | while IFS= read -r line; do note "  | $line"; done
    elif [[ $rc -ne 0 ]]; then
        # Non-zero is "nobody looked", not "nothing was recoverable", and the two
        # support opposite conclusions about the wipe.
        harness_fail "photorec $label" "exit $rc"
        harness_dump_err "$log"
    fi

    {
        printf '{"label": "%s", "returncode": %d, "elapsed_seconds": %s, ' \
            "$label" "$rc" "$elapsed"
        printf '"files_recovered": %d, "timed_out": %s, "timeout_seconds": %s, ' \
            "$count" "$timed_out" "$timeout_s"
        printf '"options": "%s", ' "$opts"
        printf '"command": "photorec /log /d %s/recup /cmd %s %s"}\n' \
            "$outdir" "$device" "$opts"
    } > "$json"

    note "photorec $label: $count files in ${elapsed}s"
    [[ $rc -eq 0 ]]
}

harness_failure_count() { printf '%s' "${#HARNESS_FAILURES[@]}"; }

# Write the failures where the write-up can find them, always - an empty list
# is the evidence that nothing failed, and is worth as much as a full one.
harness_write_failures() {
    local path="$1" first=1
    {
        printf '{"failed_phases": ['
        for item in "${HARNESS_FAILURES[@]}"; do
            [[ $first -eq 1 ]] || printf ', '
            first=0
            printf '"%s"' "${item//\"/\\\"}"
        done
        printf '], "failures": %s}\n' "${#HARNESS_FAILURES[@]}"
    } > "$path"
}

# The last word. Returns non-zero if any phase failed, so the caller's exit
# status carries it.
harness_summary() {
    if [[ ${#HARNESS_FAILURES[@]} -eq 0 ]]; then
        note "all phases completed with no recorded failure"
        return 0
    fi
    warn "${#HARNESS_FAILURES[@]} phase(s) FAILED:"
    for item in "${HARNESS_FAILURES[@]}"; do note "  - $item"; done
    return 1
}

# Count matching lines without the "0\n0" that `grep -c ... || echo 0` produces.
# grep -c prints its count and *then* exits 1 when the count is zero, so the
# fallback fired on top of a perfectly good 0 and A.1 logged "exit 0; 0\n0
# disagreement(s)".
count_matches() {
    local n
    n="$(grep -c -- "$1" "$2" 2>/dev/null || true)"
    printf '%s' "${n:-0}"
}

# Print every field of a VerificationResult, and fail the phase when it did not
# pass. A.5 printed "strategy=full_read" over passed=false and 7388 failing
# offsets, which is the one result this project must never lose.
harness_report_verification() {
    local label="$1" json="$2" text
    text="$("$PY" - "$json" <<'PYTHON'
import json
import sys

document = json.loads(open(sys.argv[1]).read() or "{}")
result = document.get("result") or {}
if not result:
    print("verification: NO RESULT IN OUTPUT")
    raise SystemExit(2)
offsets = result.get("failed_offsets") or []
print(
    "verification: passed={passed} strategy={strategy} "
    "bytes_checked={bytes_checked} sample_count={sample_count} "
    "confidence_bp={confidence_bp}".format(
        passed=result.get("passed"),
        strategy=result.get("strategy"),
        bytes_checked=result.get("bytes_checked"),
        sample_count=result.get("sample_count"),
        confidence_bp=result.get("confidence_bp"),
    )
)
if offsets:
    print(
        f"failed_offsets: {len(offsets)} "
        f"(min {min(offsets)}, max {max(offsets)})"
    )
else:
    print("failed_offsets: 0")
print(f"hw_attested: {result.get('hw_attested')}")
print(f"note: {result.get('probability_note')}")
raise SystemExit(0 if result.get("passed") else 1)
PYTHON
)"
    local rc=$?
    while IFS= read -r line; do note "$line"; done <<< "$text"
    [[ $rc -eq 0 ]] || harness_fail "$label" "verification did not pass"
    return $rc
}

# Print what the erase engine concluded about residual risk, and fail the phase
# when the write did not cover the device. The engine had already written
# "level": "high" and bytes_written: 512; the console said "wipe finished".
harness_report_erase() {
    local label="$1" json="$2" expected_bytes="$3" text
    text="$("$PY" - "$json" "$expected_bytes" <<'PYTHON'
import json
import sys

document = json.loads(open(sys.argv[1]).read() or "{}")
expected = int(sys.argv[2] or 0)
result = document.get("result") or {}
if not result:
    print("erase: NO RESULT IN OUTPUT")
    if document.get("error"):
        print(f"erase error: {document['error']}")
    raise SystemExit(2)

written = int(result.get("bytes_written") or 0)
risk = result.get("residual_risk") or {}
share = (written / expected * 100) if expected else 0.0
print(
    f"erase: method={result.get('method')} level={result.get('level')} "
    f"passes={result.get('passes')} hw_attested={result.get('hw_attested')}"
)
print(f"bytes_written: {written} of {expected} ({share:.2f}% of the device)")
print(
    f"residual risk: {risk.get('level')} "
    f"purge_achieved={risk.get('purge_achieved')}"
)
print(f"residual notes: {risk.get('notes')}")
for item in result.get("limitations") or []:
    print(f"limitation: {item}")
if expected and written < expected:
    print("SHORT WRITE: the erase did not cover the whole device")
    raise SystemExit(1)
raise SystemExit(0)
PYTHON
)"
    local rc=$?
    while IFS= read -r line; do note "$line"; done <<< "$text"
    if [[ $rc -eq 1 ]]; then
        harness_fail "$label" "the erase covered less than the whole device"
    elif [[ $rc -ne 0 ]]; then
        harness_fail "$label" "the erase produced no result"
    fi
    return $rc
}

# Print the tamper/restore table. A.7 crashed before it could produce one and
# the console showed nothing at all, which reads exactly like a step that was
# never reached. The table is the whole point of the step: an altered report
# has to be detected, and a restored one has to verify again.
report_tamper_table() {
    local json="$1" text rc
    text="$("$PY" - "$json" <<'PYTHON'
import json
import sys

document = json.loads(open(sys.argv[1]).read() or "{}")
if "verify_as_written" not in document:
    print("report: NO TAMPER RESULT IN OUTPUT")
    raise SystemExit(2)

print(f"report json: {document.get('json_path')} ({document.get('json_bytes')} bytes)")
print(f"report pdf:  {document.get('pdf_path')} ({document.get('pdf_bytes')} bytes)")
tamper = document.get("tamper") or {}
print(
    f"tampered one byte at offset {tamper.get('offset')}: "
    f"{tamper.get('original_byte')} -> {tamper.get('tampered_byte')}"
)

expected = {"verify_as_written": True, "verify_tampered": False, "verify_restored": True}
bad = []
for key, should_pass in expected.items():
    stage = document.get(key) or {}
    ok = bool(stage.get("ok"))
    verdict = "ok" if ok is should_pass else "UNEXPECTED"
    print(f"{stage.get('label', key):<18} ok={ok!s:<5} {verdict}")
    for check in stage.get("checks") or []:
        status = check.get("status") or "-"
        print(
            f"    {check['name']:<28} passed={check['passed']!s:<5} "
            f"applicable={check['applicable']!s:<5} status={status:<18} "
            f"{check['detail']}"
        )
    if ok is not should_pass:
        bad.append(key)

raise SystemExit(1 if bad else 0)
PYTHON
)"
    rc=$?
    while IFS= read -r line; do note "$line"; done <<< "$text"
    if [[ $rc -eq 1 ]]; then
        harness_fail "A.7 report" "the tamper/restore cycle did not behave as required"
    elif [[ $rc -ne 0 ]]; then
        harness_fail "A.7 report" "the report step produced no tamper result"
    fi
    return $rc
}

# Read one top-level field out of a step's JSON. Counting braces or grepping for
# a key name is how "planted 11 files" got printed for 14 planted files: the
# manifest was keyed by digest and two pairs of identical files collapsed.
harness_json_field() {
    local json="$1" field="$2"
    # An unreadable or unparsable file still yields "" - callers interpolate
    # this into console lines and must not die mid-sentence - but it says so on
    # stderr. Returning "" in silence is how an empty fingerprint got printed
    # over a key that had been created correctly.
    "$PY" - "$json" "$field" <<'PYTHON'
import json
import sys

path, field = sys.argv[1], sys.argv[2]
try:
    document = json.loads(open(path).read() or "{}")
except OSError as error:
    print(f"harness_json_field: cannot read {path}: {error}", file=sys.stderr)
    document = {}
except ValueError as error:
    print(f"harness_json_field: {path} is not JSON: {error}", file=sys.stderr)
    document = {}
value = document.get(field)
if value is None:
    print(f"harness_json_field: {path} has no field {field!r}", file=sys.stderr)
print("" if value is None else value)
PYTHON
}

# The fill byte the erase actually wrote, from its own plan, or empty when the
# plan does not name one. Without this the standalone A.5 verify compares the
# medium against the method's default 0x00, and an erase that correctly wrote
# 0xA5 to a zero-eliding controller would be reported as a failed wipe.
harness_erase_fill() {
    local json="$1"
    "$PY" - "$json" <<'PYTHON'
import json
import sys

try:
    document = json.loads(open(sys.argv[1]).read() or "{}")
except (OSError, ValueError):
    document = {}
plan = ((document.get("result") or {}).get("plan")) or {}
fills = plan.get("fill_bytes") or []
print(fills[-1] if fills else "")
PYTHON
}

# Clear the block layer's read-only flag, and confirm it cleared.
#
# core.carve.acquire.apply_write_block sets BLKROSET and deliberately never
# clears it: after an acquisition the source should stay protected. Phase B is
# the case that inverts the assumption - it re-purposes an evidence device as a
# test fixture, and a second invocation (once per filesystem) opens with parted
# and mkfs on a device the first invocation left read-only. Clearing it is
# therefore an explicit, logged step rather than a side effect, and the phase
# fails if it does not take.
harness_clear_write_block() {
    local device="$1" label="$2" before after
    before="$("$PY" - "$device" <<'PYTHON'
import fcntl, os, struct, sys
try:
    fd = os.open(sys.argv[1], os.O_RDONLY)
except OSError as exc:
    print(f"unreadable:{exc.errno}")
    raise SystemExit(0)
try:
    print(struct.unpack("i", fcntl.ioctl(fd, 0x125E, struct.pack("i", 0)))[0])
except OSError as exc:
    print(f"unsupported:{exc.errno}")
finally:
    os.close(fd)
PYTHON
)"
    if [[ "$before" == "0" ]]; then
        note "write block: $device is already writable, nothing to clear"
        return 0
    fi
    note "write block: $device reads read-only ($before); clearing it because"
    note "  phase B re-purposes this device as a test fixture and must write to it"
    after="$("$PY" - "$device" <<'PYTHON'
import fcntl, os, struct, sys
fd = os.open(sys.argv[1], os.O_RDONLY)
try:
    fcntl.ioctl(fd, 0x125D, struct.pack("i", 0))
    print(struct.unpack("i", fcntl.ioctl(fd, 0x125E, struct.pack("i", 0)))[0])
except OSError as exc:
    print(f"failed:{exc.errno}")
finally:
    os.close(fd)
PYTHON
)"
    if [[ "$after" == "0" ]]; then
        note "write block: cleared, $device now reads writable"
        return 0
    fi
    harness_fail "$label" "BLKROSET could not be cleared on $device (read back $after)"
    return 1
}

# ==========================================================================
# Resumable multi-step runs
# ==========================================================================
#
# demo-reset.sh --full is a ninety-five-minute job whose steps write to a real
# device. It crashed thirty-three minutes in, at step 3 of 7, and the only way
# to retry was to start again from the thirty-minute pattern write. A run
# declares its steps in order, records each one as it completes, and can be
# told where to pick up.
#
# Resume is explicit, never automatic. A checkpoint file says what finished; it
# cannot say whether the device still holds what that step left behind, and a
# reset that silently assumed so would be staging a demo on a guess.

HARNESS_STEPS=()
HARNESS_RESUME_INDEX=0
HARNESS_RESUME_FROM=""
HARNESS_STEP_FILE=""

#: Declare the ordered steps of a run, and where to record progress.
harness_steps_define() {
    HARNESS_STEPS=("$@")
    HARNESS_RESUME_INDEX=0
    HARNESS_RESUME_FROM=""
}

harness_step_file() { HARNESS_STEP_FILE="$1"; }

harness_steps_list() {
    local name
    for name in ${HARNESS_STEPS[@]+"${HARNESS_STEPS[@]}"}; do printf '%s\n' "$name"; done
}

#: Position of a step in the declared order, or non-zero if it is not one.
harness_step_index() {
    local want="$1" index=0 name
    for name in ${HARNESS_STEPS[@]+"${HARNESS_STEPS[@]}"}; do
        if [[ "$name" == "$want" ]]; then
            printf '%s' "$index"
            return 0
        fi
        index=$((index + 1))
    done
    return 1
}

#: Start at this step. Non-zero when the name is not a declared step, so the
#: caller can print the list rather than running a job the operator did not ask
#: for.
harness_resume_from() {
    local want="$1" index
    index="$(harness_step_index "$want")" || return 1
    HARNESS_RESUME_FROM="$want"
    HARNESS_RESUME_INDEX="$index"
    return 0
}

#: True when this step is at or after the resume point. A step name that was
#: never declared is a programming error, not a step to skip: skipping it
#: silently would drop work from a destructive run.
harness_should_run() {
    local index
    index="$(harness_step_index "$1")" || {
        harness_fail "steps" "undeclared step '$1'"
        return 1
    }
    (( index >= HARNESS_RESUME_INDEX ))
}

harness_checkpoint() {
    [[ -n "$HARNESS_STEP_FILE" ]] || return 0
    printf '%s\n' "$1" > "$HARNESS_STEP_FILE"
}

#: The step a retry should start from: the one after the last that completed.
#: Empty when every step finished.
harness_next_step() {
    local last="" index
    [[ -n "$HARNESS_STEP_FILE" && -s "$HARNESS_STEP_FILE" ]] && last="$(cat "$HARNESS_STEP_FILE")"
    if [[ -z "$last" ]]; then
        printf '%s' "${HARNESS_STEPS[0]:-}"
        return 0
    fi
    index="$(harness_step_index "$last")" || {
        printf '%s' "${HARNESS_STEPS[0]:-}"
        return 0
    }
    printf '%s' "${HARNESS_STEPS[$((index + 1))]:-}"
}

# ==========================================================================
# The code a run measured
# ==========================================================================

# Write the commit, `git describe` and whether tracked files were modified.
#   harness_record_code <repo> <out.json>
#
# Returns 1, writing nothing, when there is nothing to name: a results
# directory that cannot say which code produced it is not evidence, and the
# caller refuses to run. Untracked files do not make the tree dirty - the
# harness writes its own results inside the repository.
#
# `safe.directory` is set per call because the harness runs as root against a
# checkout owned by the operator, and git refuses that ownership mismatch.
harness_record_code() {
    local repo="$1" out="$2"
    if ! command -v git > /dev/null; then
        warn "git is not installed, so this run cannot name the code it measured"
        return 1
    fi
    local git_cmd=(git -c "safe.directory=$repo" -C "$repo")
    local sha describe porcelain dirty modified
    if ! sha="$("${git_cmd[@]}" rev-parse HEAD 2>/dev/null)"; then
        warn "$repo is not a git checkout with a commit, so this run cannot name the code it measured"
        return 1
    fi
    describe="$("${git_cmd[@]}" describe --tags --always --dirty 2>/dev/null)"
    porcelain="$("${git_cmd[@]}" status --porcelain --untracked-files=no 2>/dev/null)"
    modified=0
    [[ -n "$porcelain" ]] && modified="$(printf '%s\n' "$porcelain" | wc -l | tr -d ' ')"
    dirty=false
    [[ "$modified" -gt 0 ]] && dirty=true
    printf '{"git_sha": "%s", "git_describe": "%s", "git_dirty": %s, "modified_tracked_files": %s}\n' \
        "$sha" "$describe" "$dirty" "$modified" > "$out"
    note "code    $describe ($sha)"
    if [[ "$dirty" == true ]]; then
        warn "tree is DIRTY: $modified tracked file(s) modified. These results describe code"
        warn "  that is in no commit; commit and re-run if they are going to be quoted."
    fi
    return 0
}
