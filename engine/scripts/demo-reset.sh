#!/usr/bin/env bash
# Stage every device and every artefact the six-minute demo needs, from scratch.
#
# Rehearsing ten times means resetting ten times, and a reset done by hand ten
# times will be done differently ten times. This script is the difference
# between a rehearsal that proves something and one that proves the operator
# remembered the steps.
#
# Three modes, because a full stage is ~45 minutes and rehearsing ten times
# must not be seven hours of waiting.
#
#   --full        Everything, from a blank stick. Once per session.
#                 sudo ./scripts/demo-reset.sh --full --usb /dev/sdX \
#                     --i-understand-this-destroys-data
#                 One USB stick is enough for the whole demo. A second one is
#                 optional (--usb-b) and only moves the 0:45 wipe off the stage
#                 device; nothing in the six minutes needs it.
#
#   --quick       Only what a rehearsal consumes. Between runs. ~20 seconds.
#                 sudo ./scripts/demo-reset.sh --quick
#                 Takes no device arguments: it reads them out of the snapshot
#                 --full wrote, and re-checks the serial before formatting
#                 anything.
#
#   --check-only  Writes nothing. Five minutes before going on.
#                 sudo ./scripts/demo-reset.sh --check-only
#
# --check-only writes nothing. It re-reads every artefact the runbook depends
# on, re-verifies the digests recorded at stage time, and prints one row per
# demo beat. Every row must read OK.
#
# It is deliberately destructive on --usb and --sd, and it says so at every
# gate. See docs/demo/runbook.md for what each artefact is used for.
set -uo pipefail

# Run from a copy of this file, never from the file itself.
#
# bash does not read a script into memory. It reads a chunk, executes what it
# parsed, records a byte offset, then seeks back for more. A --full reset spends
# ~37 minutes inside a single wipe step, and any edit to this file during that
# window moves the bytes underneath the offset bash is holding. The next read
# then starts mid-line, and bash reports a syntax error on a line that is
# correct - the error names the branch it happened to land in, not the defect.
# That is exactly how "syntax error near unexpected token `('" appeared at the
# resumed-run skip branch after a wipe that had completed.
#
# So the first thing this script does is copy itself somewhere bash can hold
# open and nothing else will touch, and hand execution to that copy. The copy
# unlinks itself immediately: on Linux the open descriptor keeps the contents
# alive, so there is nothing left behind even if the run is killed.
if [[ -z "${SANCTUM_RESET_PIN:-}" ]]; then
    __pin_src="${BASH_SOURCE[0]}"
    if __pin="$(mktemp -t sanctum-demo-reset.XXXXXXXX.sh 2>/dev/null)" \
        && cat "$__pin_src" > "$__pin"; then
        SANCTUM_RESET_ROOT="$(cd "$(dirname "$__pin_src")/.." && pwd)"
        SANCTUM_RESET_SELF="$0"
        export SANCTUM_RESET_PIN="$__pin" SANCTUM_RESET_ROOT SANCTUM_RESET_SELF
        exec bash "$__pin" "$@"
    fi
    # Could not pin. Say so and carry on rather than block a reset: the risk is
    # only realised if someone edits the file mid-run.
    printf '!  could not pin this script to a temporary copy; do not edit it while it runs\n' >&2
    rm -f "${__pin:-}"
else
    rm -f "$SANCTUM_RESET_PIN"
fi

# NOT set -e, for the same reason hardware-validation.sh is not: a step that
# fails is a row that reads STALE in the check table, not a reason to abandon
# the reset and leave the operator with no idea which beats still work.

# After the pin above, BASH_SOURCE[0] is the temporary copy, so the repository
# root comes from the environment the original run exported.
REPO="${SANCTUM_RESET_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

# Every command this script prints for the operator to retype must name the
# path they invoked, not the pinned copy that path was run from.
SELF="${SANCTUM_RESET_SELF:-$0}"
PY="$REPO/.venv/bin/python"

USB=""
USB_B=""
STATE_DIR="/var/lib/sanctum-demo"
CONFIRMED=0
CHECK_ONLY=0
MODE=""
RESUME_FROM=""
LIST_STEPS=0
WITH_RECOVERY=0
SKIP_PHOTOREC=0
SKIP_RECOVERY=0
ALLOW_FIXED=0
MAX_SANE_BYTES=$((137438953472))   # 128 GiB. A larger "USB stick" is probably a disk.

usage() {
    cat <<'USAGE'
Stage the demo devices and artefacts from scratch.

Options:
  --usb PATH                           The stage device, and by default the only
                                       device the demo needs. Pattern-written,
                                       populated, scanned, wiped, scanned again,
                                       then repopulated as the recovery volume.
                                       REQUIRED unless --check-only or --quick.
  --usb-b PATH                         Optional second stick. Only effect: the
                                       0:45 live wipe targets it instead of
                                       --usb, so the recovery volume survives
                                       the rehearsal. Nothing in the six minutes
                                       requires it.
  --skip-recovery                      Stage no recovery volume. The 2:15 beat
                                       then runs from the synthetic image and
                                       the runbook says so.
  --state-dir DIR                      Default: /var/lib/sanctum-demo
  --i-understand-this-destroys-data    Required for --full.
  --skip-photorec                      Skip both PhotoRec scans (~7.5 min on a
                                       4 GB stick). The 1:30 beat then has no
                                       live numbers.
  --allow-fixed                        Permit a non-removable device.
  -h, --help                           This.

Modes:
  --full                               Stage everything from scratch. ~45 min
                                       on a 4 GB stick. Default when --usb is
                                       given. Takes a snapshot at the end.
  --quick                              Restore only what a rehearsal consumed.
                                       ~20 s. No device arguments needed - the
                                       paths come from the snapshot. Refuses if
                                       --full has never run.
  --with-recovery                      --quick only: also re-acquire and re-carve
                                       the recovery volume. Usually unnecessary
                                       (see below) and it costs a full read of
                                       the device, about 5 min on 7.4 GiB.
  --check-only                         Verify the pre-demo state. Writes nothing.
  --resume-from STEP                   --full only: skip every step before STEP.
                                       A --full stage is ~95 minutes and its
                                       steps write to a real device; a crash in
                                       step 5 should not cost another 30-minute
                                       pattern write. The run records each step
                                       as it completes and prints the exact
                                       resume command when it stops early.
                                       Resume is never automatic: the
                                       checkpoint says what finished, not
                                       whether the device still holds it.
  --list-steps                         Print the --full step names, in order.

What --quick restores, and what it deliberately does not:

  restored   the ledger, the signing key, the signed report and the demo JSONs,
             from the snapshot --full took. This DISCARDS ledger entries that
             rehearsal jobs appended; they are archived, not deleted.
  cleared    the carve output directory.
  restaged   whichever stick the 0:45 beat wiped, back to a FAT32 volume with
             ten files and five deleted. With one stick that is the stage
             stick; with two it is the second one. Format and populate only:
             deterministic, ~10 s, and no pattern pass.
  NOT redone the PhotoRec scans. The 1:30 beat reads its counts out of JSON
             written at --full time; rehearsing cannot change them.
  NOT redone the recovery acquisition. The 2:15 beat carves the image taken at
             --full time, and acquisition is read-only, so a rehearsal never
             consumes it. Pass --with-recovery to re-acquire and re-carve
             anyway - that costs a full read of the device.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --usb) USB="$2"; shift 2 ;;
        --usb-b) USB_B="$2"; shift 2 ;;
        --skip-recovery) SKIP_RECOVERY=1; shift ;;
        --state-dir) STATE_DIR="$2"; shift 2 ;;
        --i-understand-this-destroys-data) CONFIRMED=1; shift ;;
        --full) MODE="full"; shift ;;
        --quick) MODE="quick"; shift ;;
        --resume-from) RESUME_FROM="${2:-}"; shift 2 ;;
        --list-steps) LIST_STEPS=1; shift ;;
        --with-recovery) WITH_RECOVERY=1; shift ;;
        --check-only) CHECK_ONLY=1; shift ;;
        --skip-photorec) SKIP_PHOTOREC=1; shift ;;
        --allow-fixed) ALLOW_FIXED=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
    esac
done

# An invocation that names a device and no mode means what it always meant.
[[ -n "$MODE" ]] || MODE="full"

DEMO="$STATE_DIR/demo"
LEDGER="$STATE_DIR/ledger"
KEYS="$STATE_DIR/keys"
REPORTS="$STATE_DIR/reports"
STATE_JSON="$DEMO/demo-state.json"

#: What --full leaves behind so --quick can put it back. Everything a rehearsal
#: mutates, and nothing a rehearsal reads without mutating.
SNAP="$STATE_DIR/snapshot"
SNAP_STAMP="$SNAP/taken-at.txt"

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
note() { printf '   %s\n' "$*"; }
warn() { printf '\033[33m   ! %s\033[0m\n' "$*"; }
die()  { printf '\033[31m\nREFUSED: %s\033[0m\n' "$*" >&2; exit 1; }

now() { date +%s.%N; }
since() { awk -v a="$1" -v b="$(now)" 'BEGIN{printf "%.2f", b-a}'; }

digest_of() { [[ -s "$1" ]] && sha256sum "$1" | cut -d' ' -f1 || printf ''; }

. "$REPO/scripts/harness-steps.sh"
harness_reset

# The ordered steps of a --full stage. Declared before anything is checked so
# --list-steps works without a device, and so --resume-from can be validated
# before the confirmation gate rather than after it.
harness_steps_define \
    state key pattern plant photorec-before erase verify photorec-after \
    report livewipe recovery snapshot

# Resolved here, before the root check and the device gates. A typo in a step
# name must not cost the operator a confirmation prompt first.
if [[ -n "$RESUME_FROM" ]]; then
    harness_resume_from "$RESUME_FROM" || {
        note "steps, in order:"
        harness_steps_list | while read -r name; do note "  $name"; done
        die "unknown step '$RESUME_FROM'."
    }
fi

if [[ $LIST_STEPS -eq 1 ]]; then
    say "--full steps, in order"
    harness_steps_list | while read -r name; do note "$name"; done
    printf '\n'
    note "resume with: sudo $SELF --full --usb <dev> \\"
    note "               --i-understand-this-destroys-data --resume-from <step>"
    exit 0
fi


# core.report.sign refuses to write or read an unprotected signing key, so a
# passphrase has to exist before the first ledger append. A fixed default is
# right here for the same reason the ATA recovery password is fixed: this key
# signs demo reports on a scratch state directory, it protects nothing, and a
# reset that stopped on an interactive prompt would be useless. Override it in
# the environment for anything that is not a rehearsal.
#
# The server must be started with the SAME value, or the 3:15 report beat
# cannot open the key. See docs/demo/runbook.md.
export SANCTUM_KEY_PASSPHRASE="${SANCTUM_KEY_PASSPHRASE:-sanctum-demo}"

# ==========================================================================
# Check-only mode. Runs first and exits, so nothing below can write by
# accident on the run whose entire purpose is to write nothing.
# ==========================================================================

# One row of the pre-flight table.
#   check_row <label> <path> [expected sha256]
# MISSING: not there or zero bytes. STALE: there but the digest moved.
CHECK_BAD=0
check_row() {
    local label="$1" path="$2" want="${3:-}" got=""
    if [[ ! -s "$path" ]]; then
        printf '   %-34s \033[31mMISSING\033[0m  %s\n' "$label" "$path"
        CHECK_BAD=$((CHECK_BAD + 1))
        return 1
    fi
    if [[ -n "$want" ]]; then
        got="$(sha256sum "$path" | cut -d' ' -f1)"
        if [[ "$got" != "$want" ]]; then
            printf '   %-34s \033[31mSTALE\033[0m    %s\n' "$label" "$path"
            note "     recorded $want"
            note "     now      $got"
            CHECK_BAD=$((CHECK_BAD + 1))
            return 1
        fi
    fi
    printf '   %-34s \033[32mOK\033[0m\n' "$label"
    return 0
}

# A device row: present, and still the serial recorded at stage time.
check_device() {
    local label="$1" path="$2" want="$3"
    if [[ -z "$path" || "$path" == "null" ]]; then
        # Not a defect and not a warning. The only optional device is --usb-b,
        # and a one-stick setup will never stage one, so a yellow NOT STAGED
        # here made a correct rehearsal look half-ready and broke the runbook's
        # "every row must read OK".
        printf '   %-34s \033[32mOK\033[0m       not used - one-stick setup\n' "$label"
        return 0
    fi
    if [[ ! -b "$path" ]]; then
        printf '   %-34s \033[31mMISSING\033[0m  %s is not a block device\n' "$label" "$path"
        CHECK_BAD=$((CHECK_BAD + 1))
        return 1
    fi
    local got
    got="$(lsblk -ndo SERIAL "$path" 2>/dev/null | tr -d '[:space:]')"
    if [[ -n "$want" && "$want" != "null" && "$got" != "$want" ]]; then
        printf '   %-34s \033[31mSTALE\033[0m    serial is %s, staged %s\n' "$label" "${got:-unknown}" "$want"
        CHECK_BAD=$((CHECK_BAD + 1))
        return 1
    fi
    printf '   %-34s \033[32mOK\033[0m       %s  %s\n' "$label" "$path" "${got:-unknown}"
    return 0
}

state_field() {
    "$PY" - "$STATE_JSON" "$1" <<'PYTHON'
import json
import sys

try:
    document = json.loads(open(sys.argv[1]).read() or "{}")
except (OSError, ValueError):
    document = {}
node = document
for part in sys.argv[2].split("."):
    node = (node or {}).get(part) if isinstance(node, dict) else None
print("" if node is None else node)
PYTHON
}

if [[ $CHECK_ONLY -eq 1 ]]; then
    say "PRE-DEMO CHECK - nothing is written"
    [[ -x "$PY" ]] || die "no interpreter at $PY. Run ./scripts/devsetup.sh first."
    if [[ ! -s "$STATE_JSON" ]]; then
        die "no staged state at $STATE_JSON. Run the reset first."
    fi
    note "staged at $(state_field staged_at) by $(state_field staged_by)"
    note "state dir $STATE_DIR"
    printf '\n'

    check_device "0:00 devices - usb"        "$(state_field usb.path)"   "$(state_field usb.serial)"
    check_device "0:45 live wipe target"     "$(state_field usb_b.path)" "$(state_field usb_b.serial)"
    check_device "0:45 + 2:15 stage stick"   "$(state_field usb.path)"   "$(state_field usb.serial)"
    printf '\n'

    check_row "1:30 photorec before"   "$DEMO/photorec-before.json"      "$(state_field digests.photorec_before)"
    check_row "1:30 photorec after"    "$DEMO/photorec-after.json"       "$(state_field digests.photorec_after)"
    check_row "1:30 planted-match"     "$DEMO/planted-match.txt"         "$(state_field digests.planted_match)"
    check_row "2:15 recovery image"    "$DEMO/recovery-fat32.dd"             ""
    check_row "2:15 recovery manifest" "$DEMO/recovery-manifest-fat32.json"  "$(state_field digests.recovery_manifest)"
    check_row "3:15 signed report"     "$REPORTS/demo-erase.forensic.json" "$(state_field digests.report)"
    check_row "4:15 erase result"      "$DEMO/erase.json"                "$(state_field digests.erase)"
    check_row "4:15 verify result"     "$DEMO/verify.json"               "$(state_field digests.verify)"
    printf '\n'

    say "3:15 report verification, re-run now"
    if "$PY" -m core.report.cli verify-report \
            "$REPORTS/demo-erase.forensic.json" --ledger-root "$LEDGER"; then
        note "report verifies"
    else
        warn "report does NOT verify - the 3:15 beat runs from its fallback"
        CHECK_BAD=$((CHECK_BAD + 1))
    fi

    printf '\n'
    if [[ $CHECK_BAD -eq 0 ]]; then
        printf '\033[32m   READY - every row OK\033[0m\n\n'
        exit 0
    fi
    printf '\033[31m   %d row(s) not OK. Those beats run from their fallbacks.\033[0m\n\n' "$CHECK_BAD"
    exit 1
fi

# ==========================================================================
# Gates. Every one exists because getting it wrong destroys something that is
# not a test fixture.
# ==========================================================================

[[ $EUID -eq 0 ]] || die "this needs root: it partitions, formats and erases block devices."
[[ -x "$PY" ]] || die "no interpreter at $PY. Run ./scripts/devsetup.sh first."

# The device gates live in their own file so they can be tested without a
# device. See scripts/device-gate.sh: guard_device writes its banner to stderr
# and only the serial to stdout, because this caller captures it.
. "$REPO/scripts/device-gate.sh"

# ==========================================================================
# Snapshot. What --full leaves behind so --quick can put it back.
# ==========================================================================

#: The demo artefacts a rehearsal can mutate. recovery-fat32.dd is deliberately
#: absent: it is read by the carve and never written, and it is the one file
#: here large enough to make a snapshot cost real time.
SNAP_FILES=(
    "demo/demo-state.json"
    "demo/photorec-before.json"
    "demo/photorec-after.json"
    "demo/planted-match.txt"
    "demo/usb-manifest.json"
    "demo/recovery-manifest-fat32.json"
    "demo/erase.json"
    "demo/verify.json"
    "demo/report.json"
    "demo/key.json"
)

snapshot_take() {
    say "SNAPSHOT - so --quick has something to restore"
    rm -rf "$SNAP"
    mkdir -p "$SNAP/demo"
    # -a to keep the 0600 on the signing key. A snapshot that widened the mode
    # would make the next restore fail its own permission check.
    cp -a "$LEDGER" "$SNAP/ledger" 2>/dev/null || warn "no ledger to snapshot"
    cp -a "$KEYS" "$SNAP/keys" 2>/dev/null || warn "no keys to snapshot"
    cp -a "$REPORTS" "$SNAP/reports" 2>/dev/null || warn "no reports to snapshot"
    local relative
    for relative in "${SNAP_FILES[@]}"; do
        [[ -e "$STATE_DIR/$relative" ]] && cp -a "$STATE_DIR/$relative" "$SNAP/$relative"
    done
    date -u +%Y-%m-%dT%H:%M:%SZ > "$SNAP_STAMP"
    note "snapshot at $SNAP ($(du -sh "$SNAP" 2>/dev/null | cut -f1))"
    note "restore it between rehearsals with: sudo $SELF --quick"
}

# Roll the ledger, the key, the report and the demo JSONs back to what --full
# left. The archive is the point: this project's whole argument is that an
# audit log is append-only, so a reset that silently dropped entries would be
# the one place the tool did the thing it tells everyone else not to do.
snapshot_restore() {
    local stamp archive
    [[ -s "$SNAP_STAMP" ]] || die "no snapshot at $SNAP. Run --full first."
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    archive="$DEMO/rehearsals/$stamp"

    say "REHEARSAL LEDGER - archived, not deleted"
    mkdir -p "$archive"
    [[ -d "$LEDGER" ]] && cp -a "$LEDGER" "$archive/ledger"
    [[ -s "$REPORTS/demo-erase.forensic.json" ]] && \
        cp -a "$REPORTS/demo-erase.forensic.json" "$archive/"
    note "the ledger this rehearsal appended to is now at $archive/ledger"
    note "entries: $(wc -l < "$LEDGER/ledger/chain.jsonl" 2>/dev/null || echo 0)"

    say "RESTORE - from the snapshot taken $(cat "$SNAP_STAMP")"
    rm -rf "$LEDGER" "$KEYS" "$REPORTS"
    cp -a "$SNAP/ledger" "$LEDGER"
    cp -a "$SNAP/keys" "$KEYS"
    cp -a "$SNAP/reports" "$REPORTS"
    local relative
    for relative in "${SNAP_FILES[@]}"; do
        [[ -e "$SNAP/$relative" ]] && cp -a "$SNAP/$relative" "$STATE_DIR/$relative"
    done
    note "ledger back to $(wc -l < "$LEDGER/ledger/chain.jsonl" 2>/dev/null || echo 0) entries"
    note "report, signing key and demo JSONs restored"
}

# The table every mode ends on. Reads its device paths from the caller, so
# --quick can fill them from the snapshot rather than the command line.
print_check_table() {
    say "PRE-DEMO CHECK"
    check_device "0:00 devices - usb"        "$USB"   "$USB_SERIAL"
    check_device "0:45 live wipe target"     "$USB_B" "$USB_B_SERIAL"

    printf '\n'
    check_row "1:30 photorec before"   "$DEMO/photorec-before.json"
    check_row "1:30 photorec after"    "$DEMO/photorec-after.json"
    check_row "1:30 planted-match"     "$DEMO/planted-match.txt"
    [[ $SKIP_RECOVERY -eq 0 ]] && check_row "2:15 recovery image"    "$DEMO/recovery-fat32.dd"
    [[ $SKIP_RECOVERY -eq 0 ]] && check_row "2:15 recovery manifest" "$DEMO/recovery-manifest-fat32.json"
    check_row "3:15 signed report"     "$REPORTS/demo-erase.forensic.json"
    check_row "4:15 erase result"      "$DEMO/erase.json"
    check_row "4:15 verify result"     "$DEMO/verify.json"

    say "3:15 report verification"
    "$PY" -m core.report.cli verify-report \
        "$REPORTS/demo-erase.forensic.json" --ledger-root "$LEDGER" \
        || { warn "the report does not verify"; CHECK_BAD=$((CHECK_BAD + 1)); }
}

# ==========================================================================
# LIVE-WIPE STICK - a filesystem with content, so the 0:45 beat destroys
# something real. No full pattern pass: nothing verifies this device, and a
# pattern write would add sixteen minutes to every reset for no evidence.
# ==========================================================================

# Called by --full and again by --quick, because the 0:45 beat destroys this
# filesystem every rehearsal. Partition and mkfs only: nothing verifies this
# device, so a pattern pass would add sixteen minutes to every reset for no
# evidence at all.
stage_live_wipe_stick() {
    say "LIVE-WIPE STICK - FAT32 with content for the 0:45 beat"
    harness_clear_write_block "$USB_B" "usb-b write block"
    if ! parted -s "$USB_B" mklabel msdos mkpart primary fat32 1MiB 100% > "$DEMO/b-parted.out" 2>&1; then
        harness_fail "usb-b parted" "partitioning $USB_B failed"
        harness_dump_err "$DEMO/b-parted.out"
    fi
    sleep 1
    B_PART="${USB_B}1"
    [[ -b "$B_PART" ]] || B_PART="$USB_B"
    if ! mkfs.vfat -F 32 -n SANCTUMLIVE "$B_PART" > "$DEMO/b-mkfs.out" 2>&1; then
        harness_fail "usb-b mkfs" "mkfs.vfat on $B_PART failed"
        harness_dump_err "$DEMO/b-mkfs.out"
    fi
    BMNT="$WORK/mnt-b"; mkdir -p "$BMNT"
    if mount "$B_PART" "$BMNT" > "$DEMO/b-mount.out" 2>&1; then
        "$PY" - "$BMNT" <<'PLANTB'
import sys, io, random
from pathlib import Path
from PIL import Image
out = Path(sys.argv[1]); rng = random.Random(11)
for i in range(6):
    im = Image.new("RGB", (160, 160))
    im.putdata([(rng.randrange(256), rng.randrange(256), rng.randrange(256))
                for _ in range(160 * 160)])
    b = io.BytesIO(); im.save(b, "JPEG", quality=95)
    (out / f"live{i:02d}.jpg").write_bytes(b.getvalue())
PLANTB
        sync; umount "$BMNT"
        note "planted 6 files on $USB_B"
    else
        harness_fail "usb-b mount" "could not mount $B_PART"
        harness_dump_err "$DEMO/b-mount.out"
    fi
}

no_live_wipe_stick_note() {
    note "one stick: the 0:45 beat wipes $USB, which is holding the recovery"
    note "  volume. That is the right thing to destroy on stage - it is a real"
    note "  filesystem with real files - and nothing later in the six minutes"
    note "  needs the device: 1:30 reads JSON, 2:15 carves an image already on"
    note "  disk, 3:15 reads the ledger. Say out loud that the stick you carve"
    note "  against was imaged before the session."
}

# ==========================================================================
# RECOVERY VOLUME - populate, delete a subset, acquire, carve, compare
# ==========================================================================

CARD_ELAPSED=""

# Called by --full. --quick calls only restage_recovery_filesystem, unless
# --with-recovery is passed: the 2:15 beat carves the image acquired here, and
# acquisition is read-only, so a rehearsal never consumes the image.
# The recovery volume, staged on the SAME stick the erase just wiped.
#
# One stick serves both halves of the demo because neither the 1:30 beat nor
# the 2:15 beat touches a device: 1:30 reads the PhotoRec counts out of JSON,
# and 2:15 carves an image file. Only 0:45 opens the device at all. So the
# stick's staging order is the demo's own narrative - populated, scanned,
# wiped, scanned again, then repopulated for the recovery beat and wiped live
# on stage.
#
# FAT32 and exFAT on USB are structurally identical to the same filesystems on
# an SD card for every purpose this pipeline has: the same directory entries,
# the same 0xE5 deletion marker, the same cluster chains, and no TRIM on either
# path. See docs/demo/qa.md.
restage_recovery_filesystem() {
    local manifest_out="$1"
    harness_clear_write_block "$USB" "recovery write block"
    if ! parted -s "$USB" mklabel msdos mkpart primary fat32 1MiB 100% \
            > "$DEMO/rec-parted.out" 2>&1; then
        harness_fail "recovery parted" "partitioning $USB failed"
        harness_dump_err "$DEMO/rec-parted.out"
        return 1
    fi
    sleep 1
    REC_PART="${USB}1"
    [[ -b "$REC_PART" ]] || REC_PART="$USB"
    if ! mkfs.vfat -F 32 -n SANCTUMREC "$REC_PART" > "$DEMO/rec-mkfs.out" 2>&1; then
        harness_fail "recovery mkfs" "mkfs.vfat on $REC_PART failed"
        harness_dump_err "$DEMO/rec-mkfs.out"
        return 1
    fi
    RECMNT="$WORK/mnt-rec"; mkdir -p "$RECMNT"
    if ! mount "$REC_PART" "$RECMNT" > "$DEMO/rec-mount.out" 2>&1; then
        harness_fail "recovery mount" "could not mount $REC_PART"
        harness_dump_err "$DEMO/rec-mount.out"
        return 1
    fi
    # Deterministic: the same seed, the same ten files, the same bytes every
    # run. A --quick restage therefore reproduces exactly the volume the
    # --full acquisition imaged, so the image on disk and the stick in the
    # room still describe the same thing.
    "$PY" - "$RECMNT" <<'PLANTREC'
import sys, io, random
from pathlib import Path
from PIL import Image
out = Path(sys.argv[1]); rng = random.Random(7)
for i in range(10):
    n = 128 + i * 8
    im = Image.new("RGB", (n, n))
    im.putdata([(rng.randrange(256), rng.randrange(256), rng.randrange(256))
                for _ in range(n * n)])
    b = io.BytesIO(); im.save(b, "JPEG", quality=95)
    (out / f"img{i:02d}.jpg").write_bytes(b.getvalue())
PLANTREC
    sync
    harness_step "recovery hash-tree" "$DEMO/rec-plant.json" "$DEMO/rec-plant.err" \
        "$PY" "$REPO/scripts/hardware_validation.py" hash-tree \
        --root "$RECMNT" --out "$manifest_out"

    REC_DELETED=(img00.jpg img02.jpg img04.jpg img06.jpg img08.jpg)
    local name
    for name in "${REC_DELETED[@]}"; do rm -f "$RECMNT/$name"; done
    sync; umount "$RECMNT"
    harness_step "recovery mark-deleted" "$DEMO/rec-deleted.json" "$DEMO/rec-deleted.err" \
        "$PY" "$REPO/scripts/hardware_validation.py" mark-deleted \
        --manifest "$manifest_out" --names "${REC_DELETED[@]}"
    note "planted 10, deleted $(harness_json_field "$DEMO/rec-deleted.json" marked)"
    return 0
}

stage_recovery_volume() {
    say "RECOVERY 1/3 - FAT32 with ten files, five deleted"
    note "on $USB, the same stick the erase just wiped"
    restage_recovery_filesystem "$DEMO/recovery-manifest-fat32.json" || return 1

    say "RECOVERY 2/3 - acquire, read-only, with the write block applied"
    note "a full read of $USB at ~23.9 MiB/s: about $(awk -v b="$USB_BYTES" 'BEGIN{printf "%.0f", b/1048576/23.9}')s"
    harness_step "recovery acquire" "$DEMO/rec-acquire.json" "$DEMO/rec-acquire.err" \
        "$PY" "$REPO/scripts/hardware_validation.py" acquire --device "$USB" \
        --dest "$DEMO/recovery-fat32.dd" --fmt raw --ledger-root "$LEDGER" \
        --key-dir "$KEYS" --job-id "demo-acq-fat32"

    say "RECOVERY 3/3 - carve, and compare against the synthetic calibration"
    note "this is a demo staging run, not the Phase B measurement."
    note "for the measurement that fills docs/validation/hardware.md, run:"
    note "  sudo ./scripts/hardware-validation.sh --device $USB --phase b ..."
    REC_START="$(now)"
    harness_step "recovery carve" "$DEMO/rec-carve.json" "$DEMO/rec-carve.err" \
        "$PY" "$REPO/scripts/hardware_validation.py" carve \
        --image "$DEMO/recovery-fat32.dd" \
        --manifest "$DEMO/recovery-manifest-fat32.json" \
        --filesystem fat32 --damage delete \
        --out-dir "$DEMO/recovered-fat32"
    CARD_ELAPSED="$(since "$REC_START")"
    note "carve took ${CARD_ELAPSED}s - this is the 2:15 beat's real duration"

    harness_step "recovery compare" "$DEMO/rec-compare.json" "$DEMO/rec-compare.err" \
        "$PY" "$REPO/scripts/hardware_validation.py" compare \
        --carve-json "$DEMO/rec-carve.json" \
        --calibration-csv "$REPO/docs/performance/calibration-filesystems.csv"

    # The acquisition set BLKROSET and deliberately never clears it. The 0:45
    # beat has to write to this device, so clear it now rather than discovering
    # it on stage.
    harness_clear_write_block "$USB" "recovery write block, post-acquire"
}

# ==========================================================================
# --quick. Only what a rehearsal consumes.
# ==========================================================================

if [[ "$MODE" == "quick" ]]; then
    QUICK_START="$(now)"
    [[ -s "$STATE_JSON" ]] || die "no staged state at $STATE_JSON. Run --full first."
    [[ -s "$SNAP_STAMP" ]] || die "no snapshot at $SNAP. Run --full first - a --full from before this script grew --quick did not take one."

    # Device paths come from the snapshot, never from the command line. The
    # only device --quick writes to is the one recorded as the live-wipe stick,
    # and it re-checks the serial before touching it - so --quick cannot be
    # pointed at a device the operator did not already confirm during --full.
    USB="$(state_field usb.path)"
    USB_SERIAL="$(state_field usb.serial)"
    USB_B="$(state_field usb_b.path)"
    USB_B_SERIAL="$(state_field usb_b.serial)"

    say "QUICK RESET - staged $(state_field staged_at)"
    if [[ -n "$USB_B" ]]; then
        note "stage stick $USB is NOT touched: the 0:45 wipe goes to $USB_B"
    else
        note "one stick: $USB gets its recovery filesystem back, because the"
        note "  0:45 beat wiped it. Format and populate only - deterministic, so"
        note "  it reproduces the volume the --full acquisition imaged."
    fi
    note "recovery image is NOT re-acquired: the 2:15 beat carves the image from"
    note "  --full, and acquisition is read-only. Pass --with-recovery to redo it."

    # Before anything is formatted. A rehearsal that dies for want of disk
    # after it has already wiped the stick is worse than one that never ran.
    harness_workdir "$(harness_device_bytes "$USB")" \
        || die "no work directory that can hold this reset's output. See above."
    WORK="$HARNESS_WORKDIR"
    trap 'rm -rf "$WORK"' EXIT

    snapshot_restore

    say "CARVE OUTPUT - cleared"
    rm -rf "$DEMO"/recovered-*
    note "removed $DEMO/recovered-*"

    if [[ -n "$USB_B" ]]; then
        # The serial check is the gate. --full made the operator type a serial;
        # --quick will not silently follow a device path onto different hardware.
        QUICK_B_SERIAL="$(lsblk -ndo SERIAL "$USB_B" 2>/dev/null | tr -d '[:space:]')"
        if [[ ! -b "$USB_B" ]]; then
            harness_fail "usb-b" "$USB_B is not a block device; the 0:45 beat has no target"
        elif [[ -n "$USB_B_SERIAL" && "$QUICK_B_SERIAL" != "$USB_B_SERIAL" ]]; then
            harness_fail "usb-b" "$USB_B reports serial ${QUICK_B_SERIAL:-unknown}, snapshot recorded $USB_B_SERIAL. Refusing to format it."
        else
            guard_device "$USB_B" "live-wipe usb" > /dev/null
            stage_live_wipe_stick
        fi
    else
        no_live_wipe_stick_note
    fi

    if [[ $WITH_RECOVERY -eq 1 ]]; then
        USB_BYTES="$(blockdev --getsize64 "$USB" 2>/dev/null || echo 0)"
        guard_device "$USB" "stage usb" > /dev/null
        stage_recovery_volume
    elif [[ -z "$USB_B" && $SKIP_RECOVERY -eq 0 ]]; then
        # One stick, and the 0:45 beat wiped its filesystem. Put it back so the
        # Devices screen shows a volume and the next live wipe destroys
        # something real. No acquire: the 2:15 image is already on disk.
        say "RECOVERY FILESYSTEM - restaged on $USB"
        QUICK_SERIAL="$(lsblk -ndo SERIAL "$USB" 2>/dev/null | tr -d '[:space:]')"
        if [[ ! -b "$USB" ]]; then
            harness_fail "recovery restage" "$USB is not a block device"
        elif [[ -n "$USB_SERIAL" && "$QUICK_SERIAL" != "$USB_SERIAL" ]]; then
            harness_fail "recovery restage" "$USB reports serial ${QUICK_SERIAL:-unknown}, snapshot recorded $USB_SERIAL. Refusing to format it."
        else
            guard_device "$USB" "stage usb" > /dev/null
            restage_recovery_filesystem "$WORK/restage-manifest.json"
        fi
    fi

    if [[ -n "${SUDO_USER:-}" ]]; then
        # The API runs unprivileged (docs/demo/runbook.md, "Before the room
        # fills"), so every directory it writes into has to belong to the
        # operator, not to the root process that staged them. $LEDGER and $KEYS
        # were missing from this list, which left the unprivileged API unable to
        # append to the chain or open its own signing key.
        chown -R "$SUDO_USER" "$STATE_DIR"
    fi
    harness_write_failures "$DEMO/reset-failures.json"

    print_check_table

    printf '\n'
    note "quick reset took $(since "$QUICK_START")s"
    warn "RESTART THE SERVER. Job state lives in memory (api/jobs.py:JobRegistry),"
    warn "  so the only way to clear the previous rehearsal's jobs is to restart it."
    say "SUMMARY"
    harness_summary
    QUICK_RC=$?
    [[ $CHECK_BAD -ne 0 ]] && QUICK_RC=1
    exit $QUICK_RC
fi

# ==========================================================================
# --full. Everything, from a blank stick.
# ==========================================================================

[[ -n "$USB" ]] || { usage; die "no --usb given. For a between-rehearsals reset use --quick."; }


if [[ $CONFIRMED -ne 1 ]]; then
    die "this destroys every byte on $USB${USB_B:+ and $USB_B}. Pass --i-understand-this-destroys-data."
fi

say "DEVICE GATES"
USB_SERIAL="$(guard_device "$USB" "stage usb")"
USB_B_SERIAL=""
[[ -n "$USB_B" ]] && USB_B_SERIAL="$(guard_device "$USB_B" "live-wipe usb")"
if [[ -z "$USB_B" ]]; then
    note "one stick: $USB is the stage device, the recovery volume AND the"
    note "  0:45 live-wipe target. That works - see docs/demo/runbook.md."
fi

confirm_serial "$USB_SERIAL" "stage usb" "$USB"

USB_BYTES="$(blockdev --getsize64 "$USB")"

# Chosen here, before the first destructive step, and sized against the device
# rather than against a guess: PhotoRec's recup tree from a zeroed stick is
# roughly as large as the stick. harness_workdir refuses a memory-backed TMPDIR
# and refuses a volume too small to hold that, rather than warning about either.
harness_workdir "$USB_BYTES" \
    || die "no work directory that can hold a carve of $USB. See above."
WORK="$HARNESS_WORKDIR"

TOTAL_START="$(now)"

mkdir -p "$STATE_DIR"
harness_step_file "$STATE_DIR/.last-step"
if [[ -n "$RESUME_FROM" ]]; then
    say "RESUMING from '$RESUME_FROM' - every step before it is skipped"
    warn "Nothing re-checks that $USB still holds what those steps left behind."
    warn "  If the stick has been touched since, start again without --resume-from."
fi

# A run that stops early says where to pick up, rather than leaving the
# operator to work it out from the last banner that scrolled past.
resume_hint() {
    local next; next="$(harness_next_step)"
    [[ -n "$next" ]] || return 0
    printf '\n'
    note "to pick up where this stopped:"
    note "  sudo $SELF --full --usb $USB \\"
    note "      --i-understand-this-destroys-data --resume-from $next"
}
trap 'rm -rf "${WORK:-}"; resume_hint' EXIT

# ==========================================================================
# State. Cleared, then rebuilt.
# ==========================================================================

if harness_should_run state; then
    say "STATE - clearing $STATE_DIR"
    if [[ -e "$STATE_DIR" ]]; then
        note "removing the previous ledger, keys, reports and demo artefacts"
        rm -rf "$LEDGER" "$KEYS" "$REPORTS" "$DEMO"
    fi
else
    say "STATE - kept (resumed run)"
    note "the ledger, keys and artefacts from the interrupted run are reused"
fi
mkdir -p "$LEDGER" "$KEYS" "$REPORTS" "$DEMO"
chmod 700 "$KEYS"
note "ledger  $LEDGER"
note "keys    $KEYS"
note "reports $REPORTS"
note "demo    $DEMO"
harness_should_run state && harness_checkpoint state

# Defect 7: genesis records the signing key's fingerprint, so the key has to
# exist before the first ledger append. Creating it here rather than letting
# the first erase create it is what makes fingerprint_matches_genesis read OK
# instead of "no genesis entry was available".
if harness_should_run key; then
    say "KEY - created before the first ledger entry"
    # Fatal, unlike the device steps, which record a failure and carry on.
    # Every later step that appends to the ledger would start the chain with no
    # key fingerprint in genesis, and fingerprint_matches_genesis would then be
    # SKIP on every report that chain ever carries. No repair exists afterwards.
    harness_step "key" "$DEMO/key.json" "$DEMO/key.err" \
        "$PY" "$REPO/scripts/hardware_validation.py" keygen --key-dir "$KEYS" \
        || die "the signing key could not be created, and nothing may append to the ledger before it exists. Check SANCTUM_KEY_PASSPHRASE and $DEMO/key.err, then re-run."
    [[ -n "$(harness_json_field "$DEMO/key.json" fingerprint)" ]] \
        || die "keygen wrote no fingerprint to $DEMO/key.json; refusing to continue to steps that start the ledger."
    harness_checkpoint key
else
    say "KEY - skipped (resumed run)"
fi
# A resumed run skips the step above, so check the result rather than the step.
[[ -f "$KEYS/sanctum-signing.key.pem" ]] \
    || die "no signing key at $KEYS/sanctum-signing.key.pem. Re-run without --resume-from, or from --resume-from key; the ledger must not be started without one."
note "fingerprint $(harness_json_field "$DEMO/key.json" fingerprint)"

# ==========================================================================
# PhotoRec, run the same way the validation harness runs it, so the numbers in
# the demo and the numbers in docs/validation/hardware.md are comparable.
# ==========================================================================

run_photorec() {
    # Three statements, not one. Bash 5.3 declares every name in a `local`
    # before it assigns any of them, so `local label="$1" outdir="...$label"`
    # reads $label while it is still unset and `set -u` kills the run - which
    # is what happened 33 minutes into a --full stage, at USB 3/7:
    #   ./scripts/demo-reset.sh: line 716: label: unbound variable
    local label="$1" device="$2"
    local outdir="$WORK/photorec-$label"
    if [[ $SKIP_PHOTOREC -eq 1 ]]; then
        printf '{"skipped": "--skip-photorec"}\n' > "$DEMO/photorec-$label.json"
        warn "photorec $label skipped; the 1:30 beat has no live numbers"
        return 0
    fi
    if ! command -v photorec > /dev/null; then
        printf '{"skipped": "photorec is not installed"}\n' > "$DEMO/photorec-$label.json"
        warn "photorec is not installed - install testdisk. Recording the skip, not a zero:"
        warn "  a missing scan and a clean device must not produce the same number."
        return 0
    fi
    # The shared invocation, so this run and the validation harness's run stay
    # the same measurement. See harness_photorec in scripts/harness-steps.sh.
    harness_photorec "$label" "$device" "$outdir" "$DEMO/photorec-$label.json" || true
    # Kept for the hash comparison below; the recup tree is large. Written even
    # after a timeout: a partial tree still says how many planted files were
    # matched before the clock ran out, which beats no number at all.
    printf '%s' "$outdir" > "$WORK/photorec-$label.dir"
}

# How many planted files a scan actually recovered, by digest against the
# manifest. This is the number the demo quotes - the raw file count is
# dominated by a carver artefact in both directions and describes nothing.
planted_match() {
    local label="$1" manifest="$2" dir=""
    [[ -s "$WORK/photorec-$label.dir" ]] && dir="$(cat "$WORK/photorec-$label.dir")"
    "$PY" - "$manifest" "$dir" <<'MATCH'
import hashlib
import json
import sys
from pathlib import Path

manifest_path, scan_dir = sys.argv[1], sys.argv[2]
try:
    manifest = json.loads(Path(manifest_path).read_text() or "{}")
except (OSError, ValueError):
    manifest = {}
wanted = {
    entry.get("sha256") for entry in manifest.values() if isinstance(entry, dict)
}
wanted.discard(None)

found = set()
if scan_dir:
    for path in Path(scan_dir).rglob("*"):
        if not path.is_file() or path.name == "report.xml" or path.suffix == ".log":
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest in wanted:
            found.add(digest)
print(json.dumps({"planted_digests": len(wanted), "matched": len(found)}))
MATCH
}

# ==========================================================================
# STAGE USB - pattern, plant, scan, wipe, verify, scan, report
# ==========================================================================

if harness_should_run pattern; then
    say "USB 1/7 - known pattern across the whole device"
    note "0xA5, not 0x00: a wipe that leaves zeros over an already-zeroed device proves nothing"
    note "$(awk -v b="$USB_BYTES" 'BEGIN{printf "%.0f MiB at ~4 MiB/s is about %.1f minutes", b/1048576, b/1048576/4/60}')"
    harness_step "usb pattern" "$DEMO/pattern.json" "$DEMO/pattern.err" \
        "$PY" "$REPO/scripts/hardware_validation.py" pattern --device "$USB" --byte 0xA5
    sync
    note "pattern: $(harness_json_field "$DEMO/pattern.json" bytes_written) bytes at $(harness_json_field "$DEMO/pattern.json" throughput_mib_per_sec) MiB/s"
    harness_checkpoint pattern
else
    say "USB 1/7 - pattern skipped (resumed run)"
fi
# Re-read rather than carried in a variable, so a resumed run has it too.
MEASURED_WRITE="$(harness_json_field "$DEMO/pattern.json" throughput_mib_per_sec)"

if harness_should_run plant; then
# Body left unindented: it carries a quoted heredoc, whose terminator has
# to sit at column 0.
say "USB 2/7 - FAT32 and fourteen recognisable files"
harness_clear_write_block "$USB" "usb write block"
if ! parted -s "$USB" mklabel msdos mkpart primary fat32 1MiB 100% > "$DEMO/parted.out" 2>&1; then
    harness_fail "usb parted" "partitioning $USB failed"
    harness_dump_err "$DEMO/parted.out"
fi
sleep 1
USB_PART="${USB}1"
[[ -b "$USB_PART" ]] || USB_PART="$USB"
if ! mkfs.vfat -F 32 -n SANCTUMDEMO "$USB_PART" > "$DEMO/mkfs.out" 2>&1; then
    harness_fail "usb mkfs" "mkfs.vfat on $USB_PART failed"
    harness_dump_err "$DEMO/mkfs.out"
fi
MNT="$WORK/mnt"; mkdir -p "$MNT"
if ! mount "$USB_PART" "$MNT" > "$DEMO/mount.out" 2>&1; then
    harness_fail "usb mount" "could not mount $USB_PART; no files were planted"
    harness_dump_err "$DEMO/mount.out"
fi
if mountpoint -q "$MNT"; then
    # The same fourteen files the validation harness plants, from the same
    # seed, so the demo's before-count and the validation document's are the
    # same measurement. Three PDFs and two docx files are byte-identical to
    # each other on purpose: a digest-keyed manifest records 11 entries for 14
    # files, and any recall denominator taken from that count is 27% too small.
    "$PY" - "$MNT" > "$DEMO/plant-count.txt" <<'PLANT'
import sys, io, zipfile, random
from pathlib import Path
from PIL import Image
out = Path(sys.argv[1])
rng = random.Random(20260904)
def noisy(n):
    im = Image.new("RGB", (n, n))
    im.putdata([(rng.randrange(256), rng.randrange(256), rng.randrange(256))
                for _ in range(n * n)])
    return im
for i in range(6):
    b = io.BytesIO(); noisy(160).save(b, "JPEG", quality=95)
    (out / f"photo{i:02d}.jpg").write_bytes(b.getvalue())
for i in range(3):
    b = io.BytesIO(); noisy(96).save(b, "PNG")
    (out / f"shot{i:02d}.png").write_bytes(b.getvalue())
objs = [b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>\nendobj\n"]
for i in range(3):
    o = bytearray(b"%PDF-1.4\n"); offs = []
    for ob in objs:
        offs.append(len(o)); o += ob
    x = len(o); o += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for off in offs: o += b"%010d 00000 n \n" % off
    o += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, x)
    (out / f"doc{i:02d}.pdf").write_bytes(bytes(o))
for i in range(2):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        z.writestr("word/document.xml", '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>sanctum demo</w:t></w:r></w:p></w:body></w:document>')
        z.writestr("docProps/core.xml", "<coreProperties/>")
    (out / f"memo{i:02d}.docx").write_bytes(b.getvalue())
print(len(list(out.glob("*"))))
PLANT
    harness_step "usb hash-tree" "$DEMO/plant.json" "$DEMO/plant.err" \
        "$PY" "$REPO/scripts/hardware_validation.py" hash-tree \
        --root "$MNT" --out "$DEMO/usb-manifest.json"
    sync; umount "$MNT"
    note "planted $(harness_json_field "$DEMO/plant.json" files) files, $(harness_json_field "$DEMO/plant.json" unique_digests) distinct digests"
else
    harness_fail "usb plant" "not mounted; the before-count would be meaningless"
fi
harness_checkpoint plant
else
say "USB 2/7 - filesystem and planted files skipped (resumed run)"
fi

if harness_should_run photorec-before; then
    say "USB 3/7 - PhotoRec BEFORE"
    note "the number without which 'after' proves nothing"
    run_photorec before "$USB"
    # Persisted, because the recup tree it is derived from lives in $WORK and
    # is deleted at exit. A resumed run needs the number, not the tree.
    planted_match before "$DEMO/usb-manifest.json" > "$DEMO/match-before.json"
    harness_checkpoint photorec-before
else
    say "USB 3/7 - PhotoRec BEFORE skipped (resumed run)"
fi
BEFORE_MATCH="$(cat "$DEMO/match-before.json" 2>/dev/null || printf '{}')"
note "before, matched against the manifest: $BEFORE_MATCH"

if harness_should_run erase; then
    say "USB 4/7 - the real wipe"
    harness_step "usb erase" "$DEMO/erase.json" "$DEMO/erase.err" \
        "$PY" "$REPO/scripts/hardware_validation.py" erase --device "$USB" \
        --job-id "demo-erase" --ledger-root "$LEDGER" --key-dir "$KEYS"
    harness_report_erase "usb erase" "$DEMO/erase.json" "$USB_BYTES"
    harness_checkpoint erase
else
    say "USB 4/7 - wipe skipped (resumed run)"
fi
FILL="$(harness_erase_fill "$DEMO/erase.json")"
note "fill written: ${FILL:-unknown}"

if harness_should_run verify; then
    say "USB 5/7 - verification against the fill the erase actually wrote"
    if [[ -z "$FILL" ]]; then
        harness_fail "usb verify" "the erase plan named no fill byte; verifying against 0x00 would be wrong"
    else
        harness_step "usb verify" "$DEMO/verify.json" "$DEMO/verify.err" \
            "$PY" "$REPO/scripts/hardware_validation.py" verify \
            --device "$USB" --expect-fill "$FILL"
        harness_report_verification "usb verify" "$DEMO/verify.json"
        harness_checkpoint verify
    fi
else
    say "USB 5/7 - verification skipped (resumed run)"
fi

if harness_should_run photorec-after; then
    say "USB 6/7 - PhotoRec AFTER"
    run_photorec after "$USB"
    planted_match after "$DEMO/usb-manifest.json" > "$DEMO/match-after.json"
    harness_checkpoint photorec-after
else
    say "USB 6/7 - PhotoRec AFTER skipped (resumed run)"
fi
AFTER_MATCH="$(cat "$DEMO/match-after.json" 2>/dev/null || printf '{}')"
note "after, matched against the manifest: $AFTER_MATCH"

# The one line the 1:30 beat reads off the screen.
"$PY" - "$DEMO/usb-manifest.json" "$BEFORE_MATCH" "$AFTER_MATCH" \
    > "$DEMO/planted-match.txt" <<'SUMMARY'
import json
import sys
from pathlib import Path

try:
    manifest = json.loads(Path(sys.argv[1]).read_text() or "{}")
except (OSError, ValueError):
    manifest = {}
planted = len(manifest)
before = json.loads(sys.argv[2] or "{}")
after = json.loads(sys.argv[3] or "{}")
digests = before.get("planted_digests", 0)
print(
    f"planted files: {planted}   "
    f"recovered before: {before.get('matched', 0)}/{digests}   "
    f"recovered after: {after.get('matched', 0)}/{digests}"
)
SUMMARY
note "$(cat "$DEMO/planted-match.txt")"

if harness_should_run report; then
    say "USB 7/7 - signed report"
    harness_step "usb report" "$DEMO/report.json" "$DEMO/report.err" \
        "$PY" "$REPO/scripts/hardware_validation.py" report \
        --job-id "demo-erase" --ledger-root "$LEDGER" --key-dir "$KEYS" \
        --out-dir "$REPORTS" --case-id "DEMO" --operator "demo" \
        --erase-json "$DEMO/erase.json" --verify-json "$DEMO/verify.json"
    harness_checkpoint report
else
    say "USB 7/7 - report skipped (resumed run)"
fi

# The runbook's 3:15 beat names one fixed path. Normalise whatever the report
# step produced onto it, so the tamper commands never need editing.
REPORT_SRC="$(harness_json_field "$DEMO/report.json" json_path)"
if [[ -s "$REPORT_SRC" ]]; then
    [[ "$REPORT_SRC" == "$REPORTS/demo-erase.forensic.json" ]] || \
        cp "$REPORT_SRC" "$REPORTS/demo-erase.forensic.json"
    note "report at $REPORTS/demo-erase.forensic.json"
else
    harness_fail "usb report" "no report json path in $DEMO/report.json"
fi

if harness_should_run livewipe; then
    if [[ -n "$USB_B" ]]; then
        stage_live_wipe_stick
    else
        no_live_wipe_stick_note
    fi
    harness_checkpoint livewipe
else
    say "LIVE-WIPE STICK - skipped (resumed run)"
fi

if harness_should_run recovery; then
    [[ $SKIP_RECOVERY -eq 0 ]] && stage_recovery_volume
    harness_checkpoint recovery
else
    say "RECOVERY VOLUME - skipped (resumed run)"
fi

# ==========================================================================
# Record what was staged, so --check-only can tell OK from STALE.
# ==========================================================================

harness_checkpoint snapshot
say "STATE - recording what was staged"
"$PY" - > "$STATE_JSON" <<PYSTATE
import json
print(json.dumps({
    "staged_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "staged_by": "${SUDO_USER:-root}",
    "state_dir": "$STATE_DIR",
    "usb": {"path": "$USB", "serial": "$USB_SERIAL", "size_bytes": $USB_BYTES},
    "usb_b": {"path": "$USB_B", "serial": "$USB_B_SERIAL"},
    "measured": {
        "write_mib_per_sec": "$MEASURED_WRITE",
        "erase_fill": "$FILL",
        "carve_seconds": "$CARD_ELAPSED",
    },
    "digests": {
        "photorec_before": "$(digest_of "$DEMO/photorec-before.json")",
        "photorec_after": "$(digest_of "$DEMO/photorec-after.json")",
        "planted_match": "$(digest_of "$DEMO/planted-match.txt")",
        "recovery_manifest": "$(digest_of "$DEMO/recovery-manifest-fat32.json")",
        "report": "$(digest_of "$REPORTS/demo-erase.forensic.json")",
        "erase": "$(digest_of "$DEMO/erase.json")",
        "verify": "$(digest_of "$DEMO/verify.json")",
    },
}, indent=2))
PYSTATE
note "state at $STATE_JSON"

# The demo runs as the operator, not as root: only the helper daemon is
# privileged (docs/demo/runbook.md, "Before the room fills"). So every
# directory the API writes into has to belong to the operator.
#
# $LEDGER and $KEYS used to be held back here, with a note calling that "by
# design". It was not a design, it was an artefact of the API having been
# started under sudo: an unprivileged API cannot append to a root-owned 0600
# chain and cannot open a root-owned 0600 signing key, so the report beat failed
# on a permission error. The ledger's own file modes are still 0600 and the root
# helper still creates blobs during a wipe - see the chown step in the runbook's
# 0:45 beat, and FINDING 1 in BATCH4_REPORT.md.
if [[ -n "${SUDO_USER:-}" ]]; then
    chown -R "$SUDO_USER" "$STATE_DIR"
    note "handed $STATE_DIR to $SUDO_USER, including the ledger and the keys"
    note "a wipe's own blobs are written by the root helper; see the runbook"
fi

harness_write_failures "$DEMO/reset-failures.json"

# Taken after the state file is written, so the snapshot carries it and a
# --quick restore puts back a state file describing the same staging.
snapshot_take

print_check_table

say "MEASURED ON THIS HARDWARE - put these in the runbook"
note "write throughput      ${MEASURED_WRITE:-unknown} MiB/s   (docs assume 4.0)"
note "erase fill written    ${FILL:-unknown}"
note "device size           $USB_BYTES bytes"
note "$(awk -v b="$USB_BYTES" -v r="${MEASURED_WRITE:-4.0}" 'BEGIN{ if (r+0 <= 0) r = 4.0; printf "predicted write time  %.0f s (%.1f min) - the 0:45 beat shows the start, not the end", b/1048576/r, b/1048576/r/60 }')"
[[ -n "$CARD_ELAPSED" ]] && note "carve elapsed         ${CARD_ELAPSED}s - the 2:15 beat's real duration"

printf '\n'
note "total reset time $(since "$TOTAL_START")s"
say "SUMMARY"
harness_summary
RESET_RC=$?
if [[ $CHECK_BAD -ne 0 ]]; then
    warn "$CHECK_BAD pre-demo row(s) not OK"
    RESET_RC=1
fi
if [[ $RESET_RC -eq 0 ]]; then
    printf '\n\033[32m   READY.\033[0m\n'
    printf '\033[32m   Between rehearsals:  sudo %s --quick\033[0m\n' "$SELF"
    printf '\033[32m   Five minutes before: sudo %s --check-only\033[0m\n\n' "$SELF"
fi
exit $RESET_RC
