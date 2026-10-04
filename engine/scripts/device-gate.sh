# The two device gates the demo reset runs before it destroys anything.
# Sourced, never executed.
#
# Split out for the same reason harness-steps.sh is: so it can be tested
# without a device. It was not, and the --full gate was unpassable by
# construction. guard_device printed its identity banner and its return value
# to the same stream, the caller captured it with $(...), and the operator's
# correctly typed serial was compared against a string that had the whole
# banner glued to the front of it:
#
#   REFUSED: typed 'B103B9C19DE1CCC1BD535ACB', device reports '   stage usb
#   /dev/sda  TransMemory  serial B103B9C19DE1CCC1BD535ACB  7759462400 bytes
#   B103B9C19DE1CCC1BD535ACB'. Nothing was written.
#
# No input could ever match that. --quick never hit it because its two call
# sites redirect stdout to /dev/null, which discarded the banner and the serial
# together - so the bug was invisible in the only mode that had ever been run.
#
# The rule this file now keeps, and that gate_identity exists to make testable:
# **a function whose value is captured writes nothing to stdout but that value.**
# Everything an operator reads goes to stderr.
#
# The caller defines say/note/warn/die. Fallbacks are defined here only so the
# file can be sourced on its own by the test suite.

declare -F note >/dev/null || note() { printf '   %s\n' "$*"; }
declare -F warn >/dev/null || warn() { printf '   ! %s\n' "$*"; }
declare -F die  >/dev/null || die()  { printf '\nREFUSED: %s\n' "$*" >&2; exit 1; }

#: Set by the caller. Repeated here so this file can be sourced standalone.
ALLOW_FIXED="${ALLOW_FIXED:-0}"
MAX_SANE_BYTES="${MAX_SANE_BYTES:-137438953472}"

# Print the identity banner and return the serial.
#
#   gate_identity <role> <device> <model> <serial> <size-bytes>
#
# The banner goes to stderr and the serial to stdout, so that
# `serial="$(gate_identity ...)"` puts the serial in the variable and the
# banner on the operator's terminal. Reversing that is the defect this
# function was extracted to make a test able to see.
gate_identity() {
    local role="$1" dev="$2" model="$3" serial="$4" size="$5"
    note "$role  $dev  $model  serial ${serial:-unknown}  $size bytes" >&2
    printf '%s' "$serial"
}

# Guard one device. Same shape as the two gates the tool itself enforces, run
# here as well so a bug in the tool is not the only thing standing in the way.
#
# Writes its banner to stderr and the device serial to stdout. Capture it with
# $(...) and the operator still sees the banner.
guard_device() {
    local dev="$1" role="$2"
    [[ -b "$dev" ]] || die "$dev ($role) is not a block device"

    local kernel_name sys
    kernel_name="$(basename "$(readlink -f "$dev")")"
    sys="/sys/block/$kernel_name"
    [[ -d "$sys" ]] || die "$dev has no /sys/block entry; is it a partition rather than a disk?"

    if [[ "$dev" =~ [0-9]$ ]] && [[ -e "/sys/class/block/$kernel_name/partition" ]]; then
        die "$dev is a partition. Point this at the whole disk."
    fi

    local root_src root_disk
    root_src="$(findmnt -n -o SOURCE / 2>/dev/null || true)"
    root_disk="$(lsblk -no PKNAME "$root_src" 2>/dev/null | head -1 || true)"
    if [[ -n "$root_disk" && "$root_disk" == "$kernel_name" ]]; then
        die "$dev holds the running root filesystem."
    fi

    local mounts
    mounts="$(lsblk -nro MOUNTPOINTS "$dev" | grep -v '^$' || true)"
    if [[ -n "$mounts" ]]; then
        die "$dev has mounted filesystems: $(echo "$mounts" | tr '\n' ' '). Unmount them yourself - if you did not know it was mounted, you do not yet know what is on it."
    fi

    local removable size serial model
    removable="$(cat "$sys/removable" 2>/dev/null || echo 0)"
    if [[ "$removable" != "1" && $ALLOW_FIXED -ne 1 ]]; then
        die "$dev is not removable. Pass --allow-fixed if you are certain."
    fi

    size="$(blockdev --getsize64 "$dev")"
    if [[ "$size" -gt "$MAX_SANE_BYTES" ]]; then
        die "$dev is $size bytes, over the 128 GiB sanity limit. That is not a demo stick."
    fi

    serial="$(lsblk -ndo SERIAL "$dev" 2>/dev/null | tr -d '[:space:]')"
    model="$(lsblk -ndo MODEL "$dev" 2>/dev/null | sed 's/ *$//')"
    gate_identity "$role" "$dev" "$model" "$serial" "$size"
}

# The second gate: the serial has to be typed. A reset that skipped it would
# train the operator to click through the one on stage.
#
#   confirm_serial <expected-serial> <role> <device>
#
# Reads one line from stdin. Returns 0 only on an exact match; dies otherwise.
#
# The prompt names the *format* rather than the value, because the point of the
# gate is that the operator reads it off the device banner. It says so
# explicitly: the banner above shows the device path more prominently than the
# serial, and the first person to meet this gate typed the path.
confirm_serial() {
    local expected="$1" role="$2" dev="$3" typed=""

    # An empty expected serial would make every empty answer a match, which
    # turns the second gate into the Enter key. A device that reports no serial
    # cannot be confirmed and must not be guessed at.
    if [[ -z "$expected" ]]; then
        die "$dev ($role) reports no serial, so the confirmation gate cannot be answered. Refusing to write to a device that cannot be identified."
    fi

    printf '\n' >&2
    note "Confirm the $role by typing its SERIAL - not the device path." >&2
    note "  ${#expected} characters, shown in the banner above as 'serial <value>'." >&2
    read -r -p "   serial: " typed

    # A pasted serial often arrives with a trailing space or newline. The
    # comparison stays exact on content; only surrounding whitespace is
    # forgiven.
    typed="${typed//[[:space:]]/}"

    if [[ "$typed" != "$expected" ]]; then
        if [[ "$typed" == "$dev" ]]; then
            die "that is the device path, not the serial. Type the serial shown in the banner. Nothing was written."
        fi
        die "typed '$typed', device reports '$expected'. Nothing was written."
    fi
}
