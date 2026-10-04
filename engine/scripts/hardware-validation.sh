#!/usr/bin/env bash
# First contact with real removable media.
#
# Everything Sanctum has been tested against so far is a loop device or an
# image file. Both are perfect media: no vendor firmware, no USB bridge, no
# wear levelling, no controller deciding on its own where a write lands. This
# script is the run that finds out which of the tool's assumptions survive
# contact with a real stick.
#
# It is deliberately destructive and it says so at every gate. Phase A ends
# with the target device holding nothing.
#
#   ./scripts/hardware-validation.sh --device /dev/sdX \
#       --i-understand-this-destroys-data --phase a
#
# Results land in docs/validation/results-<timestamp>/ as JSON, one file per
# step, written as each step finishes. A crash halfway through therefore still
# leaves everything measured up to that point - which matters, because the
# steps most likely to crash are the ones whose results are most interesting.
set -uo pipefail

# NOT set -e. A step that fails is a finding to record, not a reason to abandon
# the run: the whole point is to learn what real hardware does, and half of
# that is what it does when something goes wrong.

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$REPO/.venv/bin/python"

DEVICE=""
PHASE="a"
CONFIRMED=0
ALLOW_FIXED=0
ALLOW_LARGE=0
MAX_SANE_BYTES=$((137438953472))   # 128 GiB. A larger "USB stick" is probably a disk.
OUT_ROOT="$REPO/docs/validation"
FS_KIND="fat32"
# Phase B knobs. Defaults chosen so one pass finishes in minutes rather than
# hours on a 4 MiB/s controller, and so the deleted-file denominator lands in
# the same order of magnitude as the synthetic corpus it is compared against.
FS_SIZE_MIB=256
FILLER_KIB=256
DAMAGE="delete"
ACQUIRE_SCOPE="partition"
FRAG_PLANT=0

usage() {
    sed -n '3,19p' "${BASH_SOURCE[0]}" | sed -n 's/^#\( \|$\)//p'
    cat <<'USAGE'

Options:
  --device PATH                        Target block device, e.g. /dev/sdb.
  --i-understand-this-destroys-data    Required. Nothing runs without it.
  --phase a|b|all                      A: erase. B: recovery. Default: a.
  --filesystem fat32|exfat             Phase B filesystem. Default: fat32.
  --allow-fixed                        Permit a non-removable device.
  --allow-large                        Permit a device over 128 GiB.
  --out DIR                            Results directory root.

Phase B only:
  --fs-size MIB                        Test partition size. Default: 256.
                                       The whole device is not used: populating
                                       7 GiB at 4 MiB/s is half an hour per pass
                                       and buys no extra measurement.
  --filler-bytes KIB                   Filler file size. Default: 256, matching
                                       testkit/generate_corpus.py so the recall
                                       denominators are comparable.
  --damage delete|quickformat          What happens to the data before it is
                                       recovered. delete: remove half the
                                       fillers and half the named files.
                                       quickformat: mkfs over the whole volume,
                                       which destroys every directory entry and
                                       leaves signature carving as the only
                                       route. Default: delete.
  --acquire-scope partition|device     What to image. partition (default) reads
                                       only the test volume - fast, and directly
                                       comparable to the synthetic corpus, which
                                       is volume images. device reads the whole
                                       stick, which is what an investigator does
                                       and which exercises partition detection.
  --fragment-plant                     Opt in: after the populate, fill the
                                       volume, free two 64 KiB pads around a
                                       live one, and write one JPEG into both
                                       holes - exactly two runs the bifragment
                                       reassembler can reach. The pass is
                                       refused if the runs read back from the
                                       volume are anything else. Default off:
                                       without it Phase B plants exactly what
                                       runs 1-3 planted. Results are tagged
                                       <fs>-<damage>-frag and compare reports
                                       no baseline.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --device) DEVICE="$2"; shift 2 ;;
        --i-understand-this-destroys-data) CONFIRMED=1; shift ;;
        --phase) PHASE="$2"; shift 2 ;;
        --filesystem) FS_KIND="$2"; shift 2 ;;
        --fs-size) FS_SIZE_MIB="$2"; shift 2 ;;
        --filler-bytes) FILLER_KIB="$2"; shift 2 ;;
        --damage) DAMAGE="$2"; shift 2 ;;
        --acquire-scope) ACQUIRE_SCOPE="$2"; shift 2 ;;
        --fragment-plant) FRAG_PLANT=1; shift ;;
        --allow-fixed) ALLOW_FIXED=1; shift ;;
        --allow-large) ALLOW_LARGE=1; shift ;;
        --out) OUT_ROOT="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
    esac
done

# --------------------------------------------------------------------------
# Output plumbing
# --------------------------------------------------------------------------

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="$OUT_ROOT/results-$STAMP"
LOG=""

say()  { printf '\n\033[1m== %s\033[0m\n' "$*" | tee -a "${LOG:-/dev/null}"; }
note() { printf '   %s\n' "$*" | tee -a "${LOG:-/dev/null}"; }
warn() { printf '\033[33m   ! %s\033[0m\n' "$*" | tee -a "${LOG:-/dev/null}"; }
die()  { printf '\033[31m\nREFUSED: %s\033[0m\n' "$*" >&2; exit 1; }

now() { date +%s.%N; }
since() { awk -v a="$1" -v b="$(now)" 'BEGIN{printf "%.2f", b-a}'; }

# Step bookkeeping: exit-status checks, the failure list, and the reporters that
# print what a step actually concluded. Sourced rather than inlined so it can be
# tested without a device; see tests/scripts/test_harness_steps.py.
. "$REPO/scripts/harness-steps.sh"

# --------------------------------------------------------------------------
# Safety gates. Every one of these exists because getting it wrong destroys
# something that is not a test fixture.
# --------------------------------------------------------------------------

[[ -n "$DEVICE" ]] || { usage; die "no --device given"; }
[[ -b "$DEVICE" ]] || die "$DEVICE is not a block device"

if [[ $CONFIRMED -ne 1 ]]; then
    die "this script destroys every byte on $DEVICE. Pass --i-understand-this-destroys-data."
fi

KERNEL_NAME="$(basename "$(readlink -f "$DEVICE")")"
SYS="/sys/block/$KERNEL_NAME"
[[ -d "$SYS" ]] || die "$DEVICE has no /sys/block entry; is it a partition rather than a disk?"

# Gate 1: partitions, not disks. Erasing /dev/sdb1 leaves the partition table
# and half the operator's assumptions intact, which is worse than refusing.
if [[ "$DEVICE" =~ [0-9]$ ]] && [[ -e "/sys/class/block/$KERNEL_NAME/partition" ]]; then
    die "$DEVICE is a partition. Point this at the whole disk."
fi

# Gate 2: the running system. The tool refuses this itself; the harness refuses
# it earlier so a bug in the tool cannot be the only thing standing in the way.
ROOT_SRC="$(findmnt -n -o SOURCE / 2>/dev/null || true)"
ROOT_DISK="$(lsblk -no PKNAME "$ROOT_SRC" 2>/dev/null | head -1 || true)"
if [[ -n "$ROOT_DISK" && "$ROOT_DISK" == "$KERNEL_NAME" ]]; then
    die "$DEVICE holds the running root filesystem."
fi

# Gate 3: anything mounted. Not unmounted automatically: if the operator did
# not know it was mounted, they do not yet know what is on it.
MOUNTS="$(lsblk -nro MOUNTPOINTS "$DEVICE" | grep -v '^$' || true)"
if [[ -n "$MOUNTS" ]]; then
    echo "$MOUNTS" | while read -r point; do echo "   mounted at: $point"; done
    die "$DEVICE has mounted filesystems. Unmount them and confirm you know what they are."
fi

# Gate 4: removable. A fixed disk reached this far by mistake far more often
# than on purpose.
REMOVABLE="$(cat "$SYS/removable" 2>/dev/null || echo 0)"
if [[ "$REMOVABLE" != "1" && $ALLOW_FIXED -ne 1 ]]; then
    die "$DEVICE is not removable ($SYS/removable = $REMOVABLE). Pass --allow-fixed if you are certain."
fi

# Gate 5: size. A 2 TB "USB stick" is a disk somebody plugged in.
SIZE_BYTES="$(lsblk -bdno SIZE "$DEVICE")"
if [[ "$SIZE_BYTES" -gt "$MAX_SANE_BYTES" && $ALLOW_LARGE -ne 1 ]]; then
    die "$DEVICE is $((SIZE_BYTES / 1073741824)) GiB, above the 128 GiB sanity limit. Pass --allow-large if intended."
fi

# --------------------------------------------------------------------------
# Identity, and the second gate: type the serial.
#
# The same two-gate shape the tool itself enforces. The flag says "I meant to
# run a destructive script"; the serial says "I meant to run it against THIS
# device", and only the second one distinguishes the target from the drive
# beside it.
# --------------------------------------------------------------------------

MODEL="$(lsblk -dno MODEL "$DEVICE" | xargs || true)"
SERIAL="$(lsblk -dno SERIAL "$DEVICE" | xargs || true)"
[[ -n "$SERIAL" ]] || SERIAL="$(udevadm info --query=property --name="$DEVICE" 2>/dev/null | sed -n 's/^ID_SERIAL_SHORT=//p')"
TRANSPORT="$(lsblk -dno TRAN "$DEVICE" | xargs || true)"

cat <<IDENTITY

  ------------------------------------------------------------------
   TARGET       $DEVICE
   model        ${MODEL:-<unknown>}
   serial       ${SERIAL:-<unknown>}
   size         $((SIZE_BYTES / 1048576)) MiB ($SIZE_BYTES bytes)
   transport    ${TRANSPORT:-<unknown>}
   removable    $REMOVABLE
  ------------------------------------------------------------------

IDENTITY

# A loud look at what is about to be destroyed. Reported rather than refused:
# validating against a spare installer stick is a perfectly reasonable thing to
# do, and refusing it outright would be the harness overruling the operator.
# But nobody should discover afterwards that this is what it was.
CONTENT_WARN=""
for part in "$DEVICE"?*; do
    [[ -b "$part" ]] || continue
    LABEL="$(lsblk -dno LABEL "$part" 2>/dev/null | xargs || true)"
    FSTYPE="$(lsblk -dno FSTYPE "$part" 2>/dev/null | xargs || true)"
    [[ -n "$LABEL$FSTYPE" ]] && echo "   contains: $part  ${FSTYPE:-?}  ${LABEL:-<no label>}"
    case "$LABEL" in
        CCCOMA*|*Windows*|*WINPE*|*UBUNTU*|*FEDORA*|*DEBIAN*|*ARCH*|*MINT*)
            CONTENT_WARN="yes" ;;
    esac
done
if [[ -n "$CONTENT_WARN" ]]; then
    echo
    warn "This looks like OS installation media. Erasing it destroys the installer."
fi

# The same gate demo-reset.sh runs, from the same file, so there is one
# implementation and it is the tested one. It refuses an empty serial: this
# read compared "$TYPED" against "$SERIAL" and nothing else, so on a device the
# kernel could not identify both sides were "" and the Enter key passed a gate
# whose whole purpose is that a serial gets typed.
. "$REPO/scripts/device-gate.sh"
confirm_serial "$SERIAL" "target" "$DEVICE"

mkdir -p "$RUN_DIR"
LOG="$RUN_DIR/run.log"
: > "$LOG"

note "results -> $RUN_DIR"
{
    echo "device=$DEVICE"
    echo "model=$MODEL"
    echo "serial=$SERIAL"
    echo "size_bytes=$SIZE_BYTES"
    echo "transport=$TRANSPORT"
    echo "removable=$REMOVABLE"
    echo "started_utc=$STAMP"
    echo "kernel=$(uname -r)"
    echo "host=$(uname -n)"
} > "$RUN_DIR/target.env"

# The code this run measures. Before any phase touches the device: a results
# directory that cannot name its code is not evidence, so the run stops here
# rather than producing one.
harness_record_code "$REPO" "$RUN_DIR/00-code.json" \
    || die "this run cannot name the code it measured; not touching $DEVICE."
{
    echo "git_describe=$(harness_json_field "$RUN_DIR/00-code.json" git_describe)"
    echo "git_sha=$(harness_json_field "$RUN_DIR/00-code.json" git_sha)"
    echo "git_dirty=$(harness_json_field "$RUN_DIR/00-code.json" git_dirty)"
} >> "$RUN_DIR/target.env"

# --------------------------------------------------------------------------
# Tool availability. Recorded, never assumed: a missing PhotoRec turns step 6
# from "zero files recovered" into "nobody looked", and those are not the same
# result.
# --------------------------------------------------------------------------

TOOLS_JSON="$RUN_DIR/00-tools.json"
{
    echo '{'
    printf '  "photorec": "%s",\n' "$(command -v photorec || echo MISSING)"
    printf '  "ewfacquire": "%s",\n' "$(command -v ewfacquire || echo MISSING)"
    printf '  "ewfverify": "%s",\n' "$(command -v ewfverify || echo MISSING)"
    printf '  "hdparm": "%s",\n' "$(command -v hdparm || echo MISSING)"
    printf '  "mkfs_vfat": "%s",\n' "$(command -v mkfs.vfat || echo MISSING)"
    printf '  "mkfs_exfat": "%s",\n' "$(command -v mkfs.exfat || echo MISSING)"
    printf '  "sanctum_python": "%s",\n' "$PY"
    printf '  "euid": %s\n' "$(id -u)"
    echo '}'
} > "$TOOLS_JSON"

HAVE_PHOTOREC=1
command -v photorec >/dev/null || { HAVE_PHOTOREC=0; warn "photorec not installed: the before/after recovery counts cannot be measured"; }
[[ -x "$PY" ]] || die "no venv interpreter at $PY. Run 'make install' first."
[[ "$(id -u)" -eq 0 ]] || warn "not running as root: raw device access will fail"

LEDGER="$RUN_DIR/ledger"
KEYS="$RUN_DIR/keys"
REPORTS="$RUN_DIR/reports"
WORK="$RUN_DIR/work"
mkdir -p "$LEDGER" "$KEYS" "$REPORTS" "$WORK"
export SANCTUM_KEY_PASSPHRASE="${SANCTUM_KEY_PASSPHRASE:-hardware-validation}"

# --------------------------------------------------------------------------
# PhotoRec. Run identically before and after, so the two counts are comparable.
# --------------------------------------------------------------------------

# PhotoRec writes report.xml and its own log beside the recovered files, and
# neither is a recovered file: the counting rule that excludes them lives in
# harness_photorec, which both this script and demo-reset.sh now call. They used
# to have a copy each, which is how a difference in the one measurement whose
# whole value is comparability could arrive unnoticed.
run_photorec() {
    local label="$1"
    if [[ $HAVE_PHOTOREC -ne 1 ]]; then
        echo '{"skipped": "photorec is not installed"}' > "$RUN_DIR/photorec-$label.json"
        return 0
    fi
    harness_photorec "$label" "$DEVICE" \
        "$RUN_DIR/photorec-$label" "$RUN_DIR/photorec-$label.json"
}

hash_device() {
    # The whole device, so "the refused run wrote nothing" is a claim about
    # every byte rather than about a sample.
    dd if="$DEVICE" bs=4M status=none 2>/dev/null | sha256sum | cut -d' ' -f1
}

# The cluster size a volume was actually formatted with, read back from its boot
# sector. mkfs picks it from the volume size, and the choice is version- and
# size-dependent: FAT32 at the 256 MiB Phase B default gets 512-byte clusters,
# exFAT at the same size gets 4096. Bifragment reassembly searches 4096-byte
# boundaries (BATCH3 FINDINGS 4), so a pass that reassembles nothing has to be
# readable as "the geometry did not match" or "it did and nothing was
# fragmented" - never as a guess.
record_geometry() {
    local label="$1" part="$2" out="$3"
    harness_step "$label" "$out" "${out%.json}.err" \
        "$PY" "$REPO/scripts/hardware_validation.py" fs-geometry --device "$part" \
        || return 0
    note "$label: $(harness_json_field "$out" filesystem), cluster $(harness_json_field "$out" cluster_bytes) bytes, reassembly grid $(harness_json_field "$out" reassembly_grid_bytes) bytes from the $(harness_json_field "$out" reassembly_grid_source)"
}

# ==========================================================================
# PHASE A - erase
# ==========================================================================

phase_a() {
    say "PHASE A.1 - enumerate and cross-check"
    harness_step "A.1 enumerate" \
        "$RUN_DIR/a1-enumerate.json" "$RUN_DIR/a1-enumerate.err" \
        "$PY" "$REPO/scripts/hardware_validation.py" enumerate --device "$DEVICE"
    note "$(count_matches '"field"' "$RUN_DIR/a1-enumerate.json") disagreement(s) with lsblk/udev"
    lsblk -O "$DEVICE" > "$RUN_DIR/a1-lsblk-O.txt" 2>&1
    hdparm -I "$DEVICE" > "$RUN_DIR/a1-hdparm-I.txt" 2>&1

    say "PHASE A.2 - write a known pattern and recognisable files"
    local start; start="$(now)"
    # 0xA5 across the whole device first: a byte that is neither 0x00 nor 0xFF,
    # so "the wipe left zeros" cannot be confused with "the wipe did nothing to
    # a device that was already zeroed".
    #
    # Written by the harness rather than by `tr | dd`, which never assembled a
    # full block: dd reading a pipe takes whatever is buffered, so bs=4M bought
    # nothing and 7.76 GB took 1899.76s at 4.08 MB/s. The pattern writer uses
    # the erase path's own geometry and buffer, so this throughput and the
    # erase throughput describe the same device rather than two pipelines.
    harness_step "A.2 pattern" "$RUN_DIR/a2-pattern.json" "$RUN_DIR/a2-pattern.err" \
        "$PY" "$REPO/scripts/hardware_validation.py" pattern --device "$DEVICE" \
        --byte 0xA5
    sync
    note "pattern written in $(since "$start")s"
    note "pattern: $(harness_json_field "$RUN_DIR/a2-pattern.json" bytes_written) bytes at $(harness_json_field "$RUN_DIR/a2-pattern.json" throughput_mib_per_sec) MiB/s, buffer $(harness_json_field "$RUN_DIR/a2-pattern.json" buffer_bytes) bytes, O_DIRECT=$(harness_json_field "$RUN_DIR/a2-pattern.json" o_direct)"

    # Checked, not discarded: without the planted files A.3's before-count is
    # meaningless, and a run whose before-count is meaningless proves nothing
    # about its after-count.
    harness_clear_write_block "$DEVICE" "A.2 write block" || return 1
    if ! parted -s "$DEVICE" mklabel msdos mkpart primary fat32 1MiB 100% \
            > "$RUN_DIR/a2-parted.out" 2>&1; then
        harness_fail "A.2 parted" "partitioning $DEVICE failed"
        harness_dump_err "$RUN_DIR/a2-parted.out"
    fi
    sleep 1
    local part="${DEVICE}1"
    [[ -b "$part" ]] || part="$DEVICE"
    if ! mkfs.vfat -F 32 -n SANCTUMVAL "$part" > "$RUN_DIR/a2-mkfs.out" 2>&1; then
        harness_fail "A.2 mkfs" "mkfs.vfat on $part failed"
        harness_dump_err "$RUN_DIR/a2-mkfs.out"
    fi
    record_geometry "A.2 geometry" "$part" "$RUN_DIR/a2-geometry.json"

    local mnt="$WORK/mnt"; mkdir -p "$mnt"
    if ! mount "$part" "$mnt" > "$RUN_DIR/a2-mount.out" 2>&1; then
        harness_fail "A.2 mount" "could not mount $part; no files were planted"
        harness_dump_err "$RUN_DIR/a2-mount.out"
    fi
    if mountpoint -q "$mnt"; then
        "$PY" - "$mnt" > "$RUN_DIR/a2-plant-count.txt" <<'PLANT'
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
        z.writestr("word/document.xml", '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>sanctum validation</w:t></w:r></w:p></w:body></w:document>')
        z.writestr("docProps/core.xml", "<coreProperties/>")
    (out / f"memo{i:02d}.docx").write_bytes(b.getvalue())
print(len(list(out.glob("*"))))
PLANT
        harness_step "A.2 hash-tree" \
            "$RUN_DIR/a2-plant.json" "$RUN_DIR/a2-plant.err" \
            "$PY" "$REPO/scripts/hardware_validation.py" hash-tree \
            --root "$mnt" --out "$RUN_DIR/a2-manifest.json"
        sync; umount "$mnt"
        note "planted $(harness_json_field "$RUN_DIR/a2-plant.json" files) files"
        note "  $(harness_json_field "$RUN_DIR/a2-plant.json" unique_digests) distinct digests, $(harness_json_field "$RUN_DIR/a2-plant.json" duplicate_content_files) file(s) duplicating another's content"
    fi

    say "PHASE A.3 - PhotoRec BEFORE (the number without which 'after' proves nothing)"
    run_photorec before

    say "PHASE A.4 - a refused run first, then the real wipe"
    local before_hash; before_hash="$(hash_device)"
    note "device sha256 before the refused run: $before_hash"

    # A wrong confirmation must be refused before a byte is written. There is
    # no rehearsal mode to test instead: every run that passes the gates writes.
    # The step exits 0 and records the refusal in its JSON, read back below.
    harness_step "A.4 refused run" "$RUN_DIR/a4-refused.json" "$RUN_DIR/a4-refused.err" \
        "$PY" "$REPO/scripts/hardware_validation.py" erase --device "$DEVICE" \
        --job-id "hwval-refused" --ledger-root "$LEDGER" --key-dir "$KEYS" \
        --typed-serial "NOT-THE-SERIAL-OF-THIS-DEVICE"
    local refused_kind
    refused_kind="$(harness_json_field "$RUN_DIR/a4-refused.json" error_kind)"
    note "refused run answered: ${refused_kind:-no refusal recorded}"

    local after_refused_hash; after_refused_hash="$(hash_device)"
    note "device sha256 after the refused run:  $after_refused_hash"
    {
        printf '{"before": "%s", "after_refused_run": "%s", "unchanged": %s, "refusal": "%s"}\n' \
            "$before_hash" "$after_refused_hash" \
            "$([[ "$before_hash" == "$after_refused_hash" ]] && echo true || echo false)" \
            "$refused_kind"
    } > "$RUN_DIR/a4-refused-hashes.json"
    if [[ "$refused_kind" != "ConfirmationMismatch" ]]; then
        harness_fail "A.4 refusal" "a wrong typed serial was not refused"
    elif [[ "$before_hash" == "$after_refused_hash" ]]; then
        note "refused run wrote zero bytes: CONFIRMED"
    else
        harness_fail "A.4 refusal" "the refused run modified the device"
    fi

    local start; start="$(now)"
    harness_step "A.4 erase" "$RUN_DIR/a4-erase.json" "$RUN_DIR/a4-erase.err" \
        "$PY" "$REPO/scripts/hardware_validation.py" erase --device "$DEVICE" \
        --job-id "hwval-real" --ledger-root "$LEDGER" --key-dir "$KEYS"
    note "real wipe finished in $(since "$start")s"
    # What the engine concluded, not just that it returned. It had already
    # written "purge_achieved": false and 512 bytes written when the console
    # said "wipe finished" and the run went on to print COMPLETE.
    harness_report_erase "A.4 erase" "$RUN_DIR/a4-erase.json" "$SIZE_BYTES" || true

    say "PHASE A.5 - verify"
    # Against the byte the erase actually wrote, not the method's default. On a
    # controller that does not program zeros the erase writes 0xA5, and checking
    # 0x00 would fail a good wipe - while on such a controller 0x00 is also the
    # one value the flash translation layer answers for free.
    local expect_fill; expect_fill="$(harness_erase_fill "$RUN_DIR/a4-erase.json")"
    if [[ -n "$expect_fill" ]]; then
        note "verifying against $expect_fill, the fill the erase plan recorded"
        harness_step "A.5 verify" "$RUN_DIR/a5-verify.json" "$RUN_DIR/a5-verify.err" \
            "$PY" "$REPO/scripts/hardware_validation.py" verify --device "$DEVICE" \
            --expect-fill "$expect_fill"
    else
        warn "the erase plan named no fill byte; verifying against the method default"
        harness_step "A.5 verify" "$RUN_DIR/a5-verify.json" "$RUN_DIR/a5-verify.err" \
            "$PY" "$REPO/scripts/hardware_validation.py" verify --device "$DEVICE"
    fi
    harness_report_verification "A.5 verify" "$RUN_DIR/a5-verify.json" || true

    say "PHASE A.6 - PhotoRec AFTER (expect zero)"
    run_photorec after

    say "PHASE A.7 - report, tamper one byte, verify, restore"
    harness_step "A.7 report" "$RUN_DIR/a7-report.json" "$RUN_DIR/a7-report.err" \
        "$PY" "$REPO/scripts/hardware_validation.py" report \
        --job-id "hwval-real" --ledger-root "$LEDGER" --key-dir "$KEYS" \
        --out-dir "$REPORTS" --erase-json "$RUN_DIR/a4-erase.json" \
        --verify-json "$RUN_DIR/a5-verify.json" \
        && report_tamper_table "$RUN_DIR/a7-report.json"

    say "PHASE A - done"
}

# ==========================================================================
# PHASE B - recovery
# ==========================================================================

phase_b() {
    local tag="$FS_KIND-$DAMAGE"
    [[ $FRAG_PLANT -eq 1 ]] && tag="$tag-frag"
    say "PHASE B.1 - build a $FS_KIND volume of ${FS_SIZE_MIB} MiB and populate it"
    note "damage model: $DAMAGE   acquire scope: $ACQUIRE_SCOPE"

    # An earlier phase-B invocation acquires from this device, and acquisition
    # sets BLKROSET and leaves it set. parted and mkfs below both need a write
    # open, so clear it first, loudly, and stop if it will not clear.
    harness_clear_write_block "$DEVICE" "B.1 write block" || return 1

    # NOT the whole device. Populating 7 GiB at this controller's ~4 MiB/s is
    # half an hour per pass and measures nothing the first 256 MiB does not:
    # recall is a property of the filesystem's deletion mechanics, not of how
    # much unused space sits beyond the last cluster.
    local part="${DEVICE}1"
    if ! parted -s "$DEVICE" mklabel msdos \
            mkpart primary fat32 1MiB "${FS_SIZE_MIB}MiB" \
            > "$RUN_DIR/b1-parted.out" 2>&1; then
        harness_fail "B.1 parted" "partitioning $DEVICE failed"
        harness_dump_err "$RUN_DIR/b1-parted.out"
        return 1
    fi
    sleep 1
    [[ -b "$part" ]] || part="$DEVICE"
    local mkfs_rc=0
    if [[ "$FS_KIND" == "exfat" ]]; then
        mkfs.exfat -L SANCTUMVAL "$part" > "$RUN_DIR/b1-mkfs.out" 2>&1 || mkfs_rc=$?
    else
        mkfs.vfat -F 32 -n SANCTUMVAL "$part" > "$RUN_DIR/b1-mkfs.out" 2>&1 || mkfs_rc=$?
    fi
    if [[ $mkfs_rc -ne 0 ]]; then
        harness_fail "B.1 mkfs" "mkfs for $FS_KIND on $part failed"
        harness_dump_err "$RUN_DIR/b1-mkfs.out"
        return 1
    fi
    record_geometry "B.1 geometry" "$part" "$RUN_DIR/b1-geometry-$tag.json"

    local mnt="$WORK/mnt-b"; mkdir -p "$mnt"
    if ! mount "$part" "$mnt" > "$RUN_DIR/b1-mount.out" 2>&1; then
        harness_fail "B.1 mount" "could not mount $part for phase B"
        harness_dump_err "$RUN_DIR/b1-mount.out"
        return 1
    fi

    # Composition mirrors testkit/generate_corpus.py's FAT32 corpus, because
    # that corpus is what these numbers are compared against and a comparison
    # between differently-shaped populations is not a comparison. There, 244 of
    # 246 deleted files are 256 KiB fillers; here the same, at whatever count
    # fits --fs-size.
    #
    # One deliberate difference, stated rather than hidden: the synthetic
    # corpus fragments one file by writing it into holes left by deleted
    # fillers. This run does not. That makes this run marginally optimistic
    # against the synthetic row - by one file in a few hundred.
    local populate_start; populate_start="$(now)"
    "$PY" - "$mnt" "$FILLER_KIB" > "$RUN_DIR/b1-populate.json" 2>"$RUN_DIR/b1-populate.err" <<'PLANTB'
import io
import json
import os
import random
import sys
from pathlib import Path

from PIL import Image

out = Path(sys.argv[1])
filler_bytes = int(sys.argv[2]) * 1024
rng = random.Random(7)

# Ten named documents of the kinds the carver has signatures for. Small, so
# the fillers dominate the denominator exactly as they do in the synthetic
# corpus.
named = []
for index in range(10):
    side = 128 + index * 8
    image = Image.new("RGB", (side, side))
    image.putdata([
        (rng.randrange(256), rng.randrange(256), rng.randrange(256))
        for _ in range(side * side)
    ])
    buffer = io.BytesIO()
    image.save(buffer, "JPEG", quality=95)
    name = f"img{index:02d}.jpg"
    (out / name).write_bytes(buffer.getvalue())
    named.append(name)

# Fill to ~90% of free space. Not 100%: a full FAT volume behaves differently
# on write and the last file would be truncated, which would put a file in the
# manifest that was never fully written.
statvfs = os.statvfs(out)
budget = int(statvfs.f_bavail * statvfs.f_frsize * 0.90)
fillers = []
written = 0
index = 0
# Pseudo-random, never zeros: a zero-filled filler is trivially "recovered"
# from any zeroed region and would inflate recall for a reason that has
# nothing to do with the filesystem.
while written + filler_bytes <= budget:
    name = f"fill{index:05d}.bin"
    (out / name).write_bytes(rng.randbytes(filler_bytes))
    fillers.append(name)
    written += filler_bytes
    index += 1

os.sync()
print(json.dumps({
    "named": named,
    "fillers": fillers,
    "filler_bytes": filler_bytes,
    "bytes_written": written + sum((out / n).stat().st_size for n in named),
}))
PLANTB
    local populate_rc=$?
    sync
    local populate_elapsed; populate_elapsed="$(since "$populate_start")"
    if [[ $populate_rc -ne 0 || ! -s "$RUN_DIR/b1-populate.json" ]]; then
        harness_fail "B.1 populate" "exit $populate_rc"
        harness_dump_err "$RUN_DIR/b1-populate.err"
        umount "$mnt" 2>/dev/null
        return 1
    fi
    note "populated in ${populate_elapsed}s: $("$PY" - "$RUN_DIR/b1-populate.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
mib = d["bytes_written"] / 1048576
print(f'{len(d["named"])} named + {len(d["fillers"])} fillers, {mib:.1f} MiB')
PY
)"
    note "small-file write rate is NOT the sequential rate and was not predicted;"
    note "  this elapsed time is the measurement, not a check against one."

    # --fragment-plant: one JPEG in exactly two runs, laid down now, verified
    # against the volume after the manifest is taken. The plant's files stay
    # live under delete damage, so undelete cannot recover the JPEG ahead of the
    # carver and the reassembler is the only thing that can; a quick format
    # takes them with everything else.
    local plant_files=()
    if [[ $FRAG_PLANT -eq 1 ]]; then
        say "PHASE B.1f - fragmented plant: one JPEG, two runs, around a live pad"
        if ! harness_step "B.1f plant" \
                "$RUN_DIR/b1-fragplant-$tag.json" "$RUN_DIR/b1-fragplant.err" \
                "$PY" "$REPO/scripts/hardware_validation.py" plant-fragmented \
                --root "$mnt"; then
            note "FRAGMENTED PLANT NOT LAID DOWN: $(harness_json_field "$RUN_DIR/b1-fragplant-$tag.json" error)"
            note "  this pass would say nothing about reassembly, so it stops here"
            umount "$mnt" 2>/dev/null
            return 1
        fi
        mapfile -t plant_files < <("$PY" - "$RUN_DIR/b1-fragplant-$tag.json" <<'PY'
import json, sys
for name in json.load(open(sys.argv[1]))["files"]:
    print(name)
PY
)
        note "planted $(harness_json_field "$RUN_DIR/b1-fragplant-$tag.json" jpeg), $(harness_json_field "$RUN_DIR/b1-fragplant-$tag.json" jpeg_bytes) bytes, around live pad $(harness_json_field "$RUN_DIR/b1-fragplant-$tag.json" gap_file); ${#plant_files[@]} plant file(s) on the volume"
    fi

    # Whether any planted JPEG is actually fragmented on the medium, measured
    # before the damage while the files still have extents to map. Reassembly
    # has nothing to do on a contiguous population whatever the cluster size,
    # and this is what lets a zero in the carve say which of those it was.
    local named_jpegs=()
    mapfile -t named_jpegs < <("$PY" - "$RUN_DIR/b1-populate.json" <<'PY'
import json, sys
for name in json.load(open(sys.argv[1]))["named"]:
    print(name)
PY
)
    [[ $FRAG_PLANT -eq 1 ]] && named_jpegs+=("fragjpeg.jpg")
    # Runs come from the volume's own allocation structures (pytsk3), read after
    # sync: vfat and exfat both refuse FIEMAP, so asking the kernel would record
    # every file as unmeasured.
    sync
    if [[ ${#named_jpegs[@]} -gt 0 ]] && harness_step "B.1 extents" \
            "$RUN_DIR/b1-extents-$tag.json" "$RUN_DIR/b1-extents.err" \
            "$PY" "$REPO/scripts/hardware_validation.py" extents \
            --device "$part" --names "${named_jpegs[@]}"; then
        note "planted JPEGs: $(harness_json_field "$RUN_DIR/b1-extents-$tag.json" fragmented_files) fragmented, $(harness_json_field "$RUN_DIR/b1-extents-$tag.json" unmeasured_files) whose extents could not be read, of $(harness_json_field "$RUN_DIR/b1-extents-$tag.json" files)"
    fi

    harness_step "B.1 hash-tree" \
        "$RUN_DIR/b1-plant-$tag.json" "$RUN_DIR/b1-plant.err" \
        "$PY" "$REPO/scripts/hardware_validation.py" hash-tree \
        --root "$mnt" --out "$RUN_DIR/b1-manifest-$tag.json"

    if [[ $FRAG_PLANT -eq 1 ]]; then
        # Unmounted, so what is read is exactly what is on the medium.
        sync; umount "$mnt"
        if ! harness_step "B.1f verify" \
                "$RUN_DIR/b1-fragverify-$tag.json" "$RUN_DIR/b1-fragverify.err" \
                "$PY" "$REPO/scripts/hardware_validation.py" fragment-verify \
                --device "$part" --plant-json "$RUN_DIR/b1-fragplant-$tag.json" \
                --manifest "$RUN_DIR/b1-manifest-$tag.json"; then
            note "FRAGMENTED PLANT FAILED. The JPEG is not one object in exactly two runs:"
            "$PY" - "$RUN_DIR/b1-fragverify-$tag.json" <<'PY' | while IFS= read -r line; do note "  $line"; done
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except (OSError, ValueError):
    print("no verification output")
    raise SystemExit(0)
print(f'runs on the medium: {d.get("jpeg_runs")}')
for reason in (d.get("verdict") or {}).get("reasons") or []:
    print(f"- {reason}")
PY
            note "  A zero from this pass would be a failed plant, not a result about"
            note "  reassembly. The pass stops here."
            return 1
        fi
        if [[ "$(harness_json_field "$RUN_DIR/b1-fragverify-$tag.json" reachable)" != "True" ]]; then
            # A genuine two-run object the search cannot recover byte for byte.
            # Kept, not refused: this is the case where the reassembler can join
            # the real head to a partial tail and score the result HIGH, and
            # refusing the pass would hide it.
            warn "the planted JPEG is bifragmented but OUTSIDE what the reassembler can recover exactly:"
            "$PY" - "$RUN_DIR/b1-fragverify-$tag.json" <<'PY' | while IFS= read -r line; do warn "  $line"; done
import json, sys
for reason in json.load(open(sys.argv[1]))["verdict"]["reach_reasons"]:
    print(f"- {reason}")
PY
            warn "  this pass tests whether it FABRICATES: any reassembled candidate at the"
            warn "  JPEG's offset that matches nothing planted is the result to report."
        fi
        note "fragmented plant verified on the medium: $("$PY" - "$RUN_DIR/b1-fragverify-$tag.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
v = d["verdict"]
print(
    f'{d["filesystem"]}, cluster {d["cluster_bytes"]} bytes, runs {d["jpeg_runs"]}, '
    f'head {v["head_bytes"]} + gap {v["gap_bytes"]} + tail {v["tail_bytes"]}, '
    f'on the {v["grid_bytes"]}-byte grid, within the {v["max_search_window"]}-byte window, '
    f'on-disk digest matches: {v["on_disk_sha256_matches"]}'
)
PY
)"
        if ! mount "$part" "$mnt" > "$RUN_DIR/b1-remount.out" 2>&1; then
            harness_fail "B.1f remount" "could not remount $part after verifying the plant"
            harness_dump_err "$RUN_DIR/b1-remount.out"
            return 1
        fi
    fi

    say "PHASE B.2 - damage the volume ($DAMAGE)"
    local deleted_names=()
    if [[ "$DAMAGE" == "quickformat" ]]; then
        # Every file is gone from the directory tree, so every file is the
        # denominator. A quick format writes a fresh FAT and a fresh root
        # directory; the data clusters are untouched, so signature carving is
        # the only route left and undelete-from-metadata should recover
        # nothing. That contrast is the point of this pass.
        mapfile -t deleted_names < <("$PY" - "$RUN_DIR/b1-populate.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
for name in d["named"] + d["fillers"]:
    print(name)
PY
)
        [[ ${#plant_files[@]} -gt 0 ]] && deleted_names+=("${plant_files[@]}")
        sync; umount "$mnt"
        local qf_rc=0
        if [[ "$FS_KIND" == "exfat" ]]; then
            mkfs.exfat -L SANCTUMVAL "$part" > "$RUN_DIR/b2-quickformat.out" 2>&1 || qf_rc=$?
        else
            mkfs.vfat -F 32 -n SANCTUMVAL "$part" > "$RUN_DIR/b2-quickformat.out" 2>&1 || qf_rc=$?
        fi
        if [[ $qf_rc -ne 0 ]]; then
            harness_fail "B.2 quickformat" "mkfs over the populated volume failed"
            harness_dump_err "$RUN_DIR/b2-quickformat.out"
            return 1
        fi
        note "quick-formatted: ${#deleted_names[@]} files gone from the directory tree"
        record_geometry "B.2 geometry" "$part" "$RUN_DIR/b2-geometry-$tag.json"
        note "mkfs may issue discards. If this controller honours them the data is"
        note "  gone at the FTL and recall collapses - which is a finding, not a bug."
    else
        # Half the fillers and half the named files, so the deleted set is
        # dominated by fillers exactly as the synthetic corpus's is.
        mapfile -t deleted_names < <("$PY" - "$RUN_DIR/b1-populate.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
for name in d["named"][::2]:
    print(name)
for name in d["fillers"][::2]:
    print(name)
PY
)
        local name
        for name in "${deleted_names[@]}"; do rm -f "$mnt/$name"; done
        sync; umount "$mnt"
        note "deleted ${#deleted_names[@]} files"
    fi

    if [[ ${#deleted_names[@]} -eq 0 ]]; then
        harness_fail "B.2 damage" "nothing was marked deleted; recall would have a zero denominator"
        return 1
    fi
    harness_step "B.2 mark-deleted" \
        "$RUN_DIR/b2-deleted-$tag.json" "$RUN_DIR/b2-deleted.err" \
        "$PY" "$REPO/scripts/hardware_validation.py" mark-deleted \
        --manifest "$RUN_DIR/b1-manifest-$tag.json" --names "${deleted_names[@]}"

    say "PHASE B.3 - acquire to raw and to E01, verify both"
    # partition: only the test volume, which is what the synthetic corpus is
    # and is 30x less to read. device: the whole stick, which is what an
    # investigator images and which exercises partition detection.
    local acquire_target="$part"
    [[ "$ACQUIRE_SCOPE" == "device" ]] && acquire_target="$DEVICE"
    note "imaging $acquire_target ($ACQUIRE_SCOPE scope)"
    harness_step "B.3 acquire raw" \
        "$RUN_DIR/b3-acquire-raw-$tag.json" "$RUN_DIR/b3-acquire-raw.err" \
        "$PY" "$REPO/scripts/hardware_validation.py" acquire --device "$acquire_target" \
        --dest "$WORK/vol-$tag.dd" --fmt raw --ledger-root "$LEDGER" \
        --key-dir "$KEYS" \
        --job-id "hwval-acq-raw-$tag"
    harness_step "B.3 acquire e01" \
        "$RUN_DIR/b3-acquire-e01-$tag.json" "$RUN_DIR/b3-acquire-e01.err" \
        "$PY" "$REPO/scripts/hardware_validation.py" acquire --device "$acquire_target" \
        --dest "$WORK/vol-$tag" --fmt e01 --ledger-root "$LEDGER" \
        --key-dir "$KEYS" \
        --job-id "hwval-acq-e01-$tag"

    # Both acquisitions verify themselves against their own AcquisitionRecord
    # inside cmd_acquire. Print the verdict rather than leaving it in a file:
    # an integrity check nobody read is an integrity check nobody ran.
    local fmt
    for fmt in raw e01; do
        local verdict rc=0
        verdict="$("$PY" - "$RUN_DIR/b3-acquire-$fmt-$tag.json" <<'PY'
import json
import sys

try:
    document = json.load(open(sys.argv[1]))
except (OSError, ValueError):
    print("NO OUTPUT")
    raise SystemExit(2)
integrity = document.get("integrity") or {}
print(
    f'{document.get("bytes_read")} bytes read, '
    f'{document.get("on_disk_bytes")} on disk, '
    f'{document.get("throughput_mib_per_sec")} MiB/s, '
    f'integrity passed={integrity.get("passed")} '
    f'sha256={integrity.get("sha256_matches")} '
    f'blake3={integrity.get("blake3_matches")} '
    f'verified={integrity.get("bytes_verified")} bytes, '
    f'mismatched_chunks={len(integrity.get("mismatched_chunks") or [])}, '
    f'bad_sectors={document.get("bad_sectors")}'
)
raise SystemExit(0 if integrity.get("passed") else 1)
PY
)" || rc=$?
        note "$fmt: $verdict"
        # An image that does not match its own acquisition record is not
        # evidence, and carving it would produce numbers about a corrupt file.
        [[ $rc -ne 0 ]] && harness_fail "B.3 acquire $fmt" "integrity check did not pass"
    done

    say "PHASE B.4 - carve, and compare against the synthetic calibration"
    note "THIS is the number Phase B exists for. Every confidence figure the"
    note "  report prints is calibrated on synthetic images; if real-media recall"
    note "  diverges, the calibration describes something other than reality."
    harness_step "B.4 carve" \
        "$RUN_DIR/b4-carve-$tag.json" "$RUN_DIR/b4-carve.err" \
        "$PY" "$REPO/scripts/hardware_validation.py" carve \
        --image "$WORK/vol-$tag.dd" \
        --manifest "$RUN_DIR/b1-manifest-$tag.json" \
        --filesystem "$FS_KIND" --damage "$DAMAGE" \
        --population "$([[ $FRAG_PLANT -eq 1 ]] && echo fragment-plant || echo default)" \
        --out-dir "$WORK/recovered-$tag"

    harness_step "B.4 compare" \
        "$RUN_DIR/b4-compare-$tag.json" "$RUN_DIR/b4-compare.err" \
        "$PY" "$REPO/scripts/hardware_validation.py" compare \
        --carve-json "$RUN_DIR/b4-carve-$tag.json" \
        --calibration-csv "$REPO/docs/performance/calibration-filesystems.csv"

    note "$("$PY" - "$RUN_DIR/b4-carve-$tag.json" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except (OSError, ValueError):
    print("carve produced no output")
    raise SystemExit(0)
print(
    f'deleted planted {d.get("planted_deleted")}, '
    f'recovered exactly {d.get("recovered_deleted_exact")}, '
    f'recall {d.get("overall_recall_bp", 0) / 100:.2f}%, '
    f'candidates {d.get("candidates")}, carve {d.get("elapsed_seconds")}s'
)
high = d.get("high_true_positives") or {}
print(
    f'reassembled_from_fragments {d.get("reassembled_from_fragments")}; '
    f'HIGH {high.get("high_candidates")} candidates, '
    f'{high.get("true_positives_with_fragments")} true positives with fragments, '
    f'{high.get("true_positives_without_fragments")} without, '
    f'{high.get("false_positives_with_fragments")} reassembled false positives'
)
for row in d.get("fragment_candidates") or []:
    print(
        f'  reassembled @{row.get("offset")} {row.get("bucket")} '
        f'matches={row.get("matches")} {row.get("planted_names")}'
    )
# A correctly recovered live file is not a false positive. Printed apart
# from recall because it is not in recall's denominator and never was.
for name, row in sorted(d.get("per_filesystem", {}).items()):
    print(
        f'  {name}: precision {row.get("precision_bp", 0) / 100:.2f}% '
        f'({row.get("deleted_hit_candidates")} deleted + '
        f'{row.get("live_hit_candidates")} live correct, '
        f'{row.get("false_positive_candidates")} false positive '
        f'of {row.get("candidates")} candidates)'
    )
PY
)"

    note "$("$PY" - "$RUN_DIR/b4-compare-$tag.json" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except (OSError, ValueError):
    print("compare produced no output")
    raise SystemExit(0)
for row in d.get("rows", []):
    line = f'{row["filesystem"]}/{row["damage"]}: {row.get("status", "?")}'
    if row.get("compared_pipeline"):
        line += (
            f' (compared on the {row["compared_pipeline"]} pipeline: real '
            f'{row.get("compared_recall_bp", 0) / 100:.2f}% against '
            f'{row.get("synthetic_recall_bp", 0) / 100:.2f}%, '
            f'n={row.get("synthetic_deleted")})'
        )
    print(line)
    if row.get("note"):
        print(f'  {row["note"]}')
PY
)"

    # The images are the bulk of a run's disk footprint and the next pass needs
    # the space. Kept only if the carve failed, because then they are the
    # evidence for why.
    if [[ -s "$RUN_DIR/b4-carve-$tag.json" ]]; then
        rm -f "$WORK/vol-$tag.dd" "$WORK/vol-$tag".E* 2>/dev/null
        note "images removed; re-acquire if you need them"
    else
        warn "carve produced nothing: keeping $WORK/vol-$tag.* for diagnosis"
    fi

    say "PHASE B - done ($tag)"
}

TOTAL_START="$(now)"
case "$PHASE" in
    a)   phase_a ;;
    b)   phase_b ;;
    all) phase_a; phase_b ;;
    *)   die "unknown phase: $PHASE" ;;
esac

printf '{"total_seconds": %s, "phase": "%s"}\n' "$(since "$TOTAL_START")" "$PHASE" \
    > "$RUN_DIR/zz-timing.json"

harness_write_failures "$RUN_DIR/zz-failures.json"

# The exit status carries the findings. The previous run printed COMPLETE over a
# wipe that covered 512 bytes and a report step that crashed, and exited 0.
if harness_summary; then
    say "COMPLETE"
    note "results: $RUN_DIR"
    note "write them up in docs/validation/hardware.md"
    exit 0
fi

say "COMPLETE WITH FAILURES"
note "results: $RUN_DIR"
note "failures: $RUN_DIR/zz-failures.json"
note "write them up in docs/validation/hardware.md"
exit 1
