"""Stage an offline demonstration in a fresh, separate state directory.

What it builds, all inside ``--state-dir`` and nowhere else:

* a **signing key**, created before the first ledger entry so the chain's
  genesis records its fingerprint and ``fingerprint_matches_genesis`` passes;
* a **demo source image** under ``<state>/demo-source/``: the eight-seed-0
  calibration corpus (real encoders, known SHA-256 for every object), plus one
  baseline JPEG laid out in exactly two runs with a 32 KiB gap, so the
  bifragment reassembly path has something real to reconstruct;
* a **demo case**, ``DEMO-CASE-001``, opened in the case index and in the
  ledger, with the source image registered as its exhibit and its SHA-256
  computed here, from the bytes, not typed;
* a **designated erase target**, ``<state>/demo-erase-target/``, a directory of
  throwaway files the File eraser screen may be pointed at. It is the only
  thing this script creates for the purpose of being destroyed.

What it refuses to do:

* use a state directory that already holds anything - a demo must never share
  a ledger, a key or an evidence tree with real casework;
* touch a block device. Whole-device sanitization needs root and a real or
  loop device, and is staged by ``scripts/demo-reset.sh`` with its own
  explicit ``--i-understand-this-destroys-data`` flag. This script never
  creates, opens or writes a device.

Then start the API against it::

    SANCTUM_KEY_PASSPHRASE=... python scripts/demo_setup.py --state-dir ~/sanctum-demo
    SANCTUM_STATE_DIR=~/sanctum-demo SANCTUM_KEY_PASSPHRASE=... make run

Everything works with the network unplugged; nothing here fetches anything.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

DEMO_CASE = "DEMO-CASE-001"
DEMO_EXHIBIT = "EX-DEMO-1"
#: Bytes between the two runs of the fragmented JPEG. Well inside the 2 MiB the
#: reassembler searches, and on the 4 KiB grid a real allocator would use.
GAP_BYTES = 32 * 1024
HEAD_BYTES = 8192


def _fragmented_jpeg(rng: random.Random) -> tuple[bytes, str]:
    """A baseline JPEG split into two runs, and the digest of the whole file."""
    from testkit.generate_corpus import make_jpeg

    payload = make_jpeg(rng, 384)
    filler = bytes((index * 7 + 3) & 0xFF for index in range(GAP_BYTES))
    laid = payload[:HEAD_BYTES] + filler + payload[HEAD_BYTES:]
    return laid, hashlib.sha256(payload).hexdigest()


def build_source(state: Path) -> tuple[Path, str, str]:
    """Write the demo image. Returns its path, its SHA-256 and the JPEG's."""
    from testkit.generate_corpus import generate_corpus

    source_dir = state / "demo-source"
    manifest = generate_corpus(source_dir / "corpus", seed=0, first_offset=4096)
    base = (source_dir / "corpus" / manifest.image).read_bytes()

    laid, jpeg_digest = _fragmented_jpeg(random.Random(2026))
    # Appended on a 4 KiB boundary, after 64 KiB of zeros, so it neither
    # overlaps a planted object nor sits adjacent to one.
    pad = (-len(base)) % 4096 + 64 * 1024
    image_bytes = base + b"\x00" * pad + laid + b"\x00" * 8192
    image = source_dir / "demo-evidence.dd"
    image.write_bytes(image_bytes)
    return image, hashlib.sha256(image_bytes).hexdigest(), jpeg_digest


def build_erase_target(state: Path) -> Path:
    """Throwaway files for the File eraser screen. Nothing else is erasable."""
    target = state / "demo-erase-target"
    target.mkdir(parents=True, exist_ok=True)
    rng = random.Random(7)
    for index in range(3):
        (target / f"scratch-{index}.bin").write_bytes(rng.randbytes(64 * 1024))
    (target / "DESIGNATED-TEST-MEDIA.txt").write_text(
        "Created by scripts/demo_setup.py for demonstration erasure only.\n",
        encoding="utf-8",
    )
    return target


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--state-dir", type=Path, required=True)
    args = parser.parse_args()

    state = args.state_dir.expanduser().resolve()
    if state.exists() and any(state.iterdir()):
        print(  # noqa: T201 - a CLI
            f"refusing: {state} is not empty. A demo must not share a ledger, a "
            "key or an evidence tree with real casework. Pick a new directory.",
            file=sys.stderr,
        )
        return 2
    if not os.environ.get("SANCTUM_KEY_PASSPHRASE"):
        print(  # noqa: T201
            "refusing: set SANCTUM_KEY_PASSPHRASE. The signing key is created "
            "encrypted, before the first ledger entry, so the chain records "
            "its fingerprint.",
            file=sys.stderr,
        )
        return 2

    from api.deps import AppServices
    from api.identity import resolve
    from api.jobs import JobRegistry
    from core.cases import attach_evidence, create_case
    from core.report.sign import fingerprint, load_or_create_key, public_key_of
    from helper.daemon import InProcessHelper

    services = AppServices(
        registry=JobRegistry(), helper=InProcessHelper(), state_dir=state
    )
    services.prepare()

    # Key first: the genesis entry the first append writes records whichever
    # fingerprint exists at that moment, and it can never be changed after.
    key = load_or_create_key(state / "keys")
    finger = fingerprint(public_key_of(key))

    image, image_digest, jpeg_digest = build_source(state)
    erase_target = build_erase_target(state)
    identity = resolve(services)

    create_case(
        services.cases_dir,
        case_id=DEMO_CASE,
        title="Demonstration case",
        description=(
            "Staged by scripts/demo_setup.py. Synthetic evidence with a known "
            "SHA-256 for every planted object; nothing here is real casework."
        ),
        created_by=identity.actor,
    )
    ledger = services.ledger()
    ledger.append(
        actor=identity.actor,
        operation="case.opened",
        params={"case_id": DEMO_CASE, "created_by": identity.actor, "demo": True},
        result={},
    )
    record = attach_evidence(
        services.cases_dir,
        case_id=DEMO_CASE,
        evidence_id=DEMO_EXHIBIT,
        source=str(image),
        media_type="raw image (synthetic)",
        source_hash=image_digest,
        state="registered",
        detail={"registered_by": identity.actor, "demo": True},
    )
    ledger.append(
        actor=identity.actor,
        operation="case.evidence.registered",
        params={"case_id": DEMO_CASE, **record},
        result={},
    )

    notes = state / "DEMO.md"
    notes.write_text(
        "\n".join(
            [
                "# Demo state",
                "",
                f"- Case: `{DEMO_CASE}`",
                f"- Evidence image: `{image}`",
                f"- Evidence SHA-256: `{image_digest}`",
                f"- Bifragmented JPEG SHA-256 (whole file): `{jpeg_digest}`",
                f"- Signing key fingerprint: `{finger}`",
                f"- Designated erase target: `{erase_target}`",
                "",
                "Recovery: carve the evidence image with output directory "
                "`demo-run`. The reassembled JPEG's digest must equal the one "
                "above.",
                "",
            ]
        ),
        encoding="utf-8",
    )
    print(notes.read_text(encoding="utf-8"))  # noqa: T201
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
