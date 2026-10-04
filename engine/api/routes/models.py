"""Request and response bodies for the API.

Separate from :mod:`core.models` on purpose. These describe *what a browser is
allowed to ask for*, which is a narrower thing than what the core layers can
represent: a request body cannot name an erase method, cannot supply a
capability set, and cannot set a flag that would let a wipe run without a typed
serial. Reusing the core models here would widen the attack surface of every
endpoint to the full expressiveness of the domain.

**There is no simulation switch.** Every destructive body describes a real
operation against the selected target, and each one is gated by what a body
cannot forge: a typed serial or identifier checked against a fresh read, and -
for a device - a server-issued, human-approved, single-use authorization.

**A body that still carries ``dry_run``, ``simulation`` or ``simulate`` is
refused (422).** Those keys once asked for a rehearsal. Silently dropping one
would run for real a request whose sender expected nothing to be written, so
every request model rejects them, and every destructive model also rejects any
other key it does not declare.
"""

from __future__ import annotations

from typing import Any, Literal

from core.device.guard import REMOVED_MODE_KEYS
from core.models import DestructionRecord
from pydantic import BaseModel, ConfigDict, Field, model_validator

__all__ = [
    "DestructiveRequest",
    "Request",
    "ApproveHiddenAreaRequest",
    "ExecuteHiddenAreaRequest",
    "OpenHiddenAreaRequest",
    "ApproveFormatRequest",
    "ExecuteFormatRequest",
    "OpenFormatRequest",
    "ApproveRestoreRequest",
    "CreateBackupRequest",
    "ExecuteRestoreRequest",
    "OpenRestoreRequest",
    "CaseCreateRequest",
    "EvidenceAttachRequest",
    "TamperDemoRequest",
    "ResumeEraseRequest",
    "EraseDriveRequest",
    "EraseFilesRequest",
    "PlanFreeSpaceRequest",
    "WipeFreeSpaceRequest",
    "AcquireRequest",
    "CarveRequest",
    "ReportRequest",
    "JobAccepted",
]


def _refuse_removed_modes(data: Any) -> Any:
    """Reject a body that asks for the simulation mode that no longer exists."""
    if isinstance(data, dict):
        present = [key for key in REMOVED_MODE_KEYS if key in data]
        if present:
            raise ValueError(
                f"{', '.join(present)} is not accepted: there is no simulation "
                "or dry-run mode. Every destructive request runs against the "
                "real device. Remove the field."
            )
    return data


class Request(BaseModel):
    """Every request body. Refuses the removed simulation switches by name."""

    @model_validator(mode="before")
    @classmethod
    def _no_removed_modes(cls, data: Any) -> Any:
        return _refuse_removed_modes(data)


class DestructiveRequest(Request):
    """A body that starts or authorizes a write. Undeclared keys are refused."""

    model_config = ConfigDict(extra="forbid")



class CaseCreateRequest(Request):
    """Body for ``POST /cases``.

    There is no ``created_by``. The author is the trusted local identity the
    helper resolves, and a field here would be a second, spoofable source for
    the one value a chain of custody exists to record.
    """

    case_id: str = Field(min_length=1, max_length=64)
    title: str = Field(default="", max_length=200)
    description: str = Field(default="", max_length=4000)


class EvidenceAttachRequest(Request):
    """Body for ``POST /cases/{case_id}/evidence``.

    Registration only: this records that an exhibit exists and what its hashes
    are. Nothing here opens a device or reads an image - acquisition is a job,
    with its own read-only path and its own chain entries.
    """

    evidence_id: str = Field(min_length=1, max_length=64)
    #: Free text describing where the exhibit came from.
    source: str = Field(default="", max_length=500)
    media_type: str = Field(default="image", max_length=64)
    acquired_at: str = Field(default="", max_length=64)
    #: The hash recorded at acquisition, if there is one.
    source_hash: str = Field(default="", max_length=128)
    #: The hash a later read-back produced, if one was done.
    verification_hash: str = Field(default="", max_length=128)
    state: str = Field(default="registered", max_length=32)


class TamperDemoRequest(Request):
    """Body for ``POST /ledger/tamper-demo``.

    ``seq`` names the entry to alter **in the scratch copy**. The production
    chain is never opened for writing by this endpoint; see
    :func:`api.routes.audit.tamper_demo`.
    """

    #: Which entry to corrupt in the copy. Defaults to the middle of the chain,
    #: which is the interesting case: it shows both the intact prefix and the
    #: unverifiable suffix.
    seq: int | None = None


class EraseDriveRequest(DestructiveRequest):
    """Body for ``POST /jobs/erase-drive``. Always a real erase of ``path``."""

    #: Device path or by-id link. Resolved and re-read by the helper, so a
    #: stale value fails the serial check rather than erasing the wrong disk.
    path: str
    level: Literal["CLEAR", "PURGE"] = "CLEAR"
    #: The operator types the device serial; the helper compares it against
    #: the serial it reads itself, not against anything the UI sent.
    typed_serial: str = ""
    #: Required: the id of an approved workflow record from
    #: ``/workflow/erase-drive``. See api.authorization.
    authorization_id: str = ""
    case_id: str = ""
    operator: str = "sanctum"


class OpenEraseWorkflowRequest(Request):
    """Body for ``POST /workflow/erase-drive``."""

    path: str
    level: Literal["CLEAR", "PURGE"] = "CLEAR"
    #: A backup image under the evidence directory, verified read-only.
    backup_image: str


class ApproveEraseRequest(DestructiveRequest):
    """Body for ``POST /workflow/erase-drive/{id}/approve``."""

    typed_serial: str = ""
    #: Must be sent true, deliberately. The typed serial alone is not approval.
    acknowledge_data_destruction: bool = False


class EraseFilesRequest(DestructiveRequest):
    """Body for ``POST /jobs/erase-files``. Always a real erase of ``paths``."""

    paths: list[str] = Field(min_length=1)
    #: File erasure has no serial to type, so an explicit confirm takes its
    #: place. Refused unless sent true.
    confirm: bool = False
    cleanse_metadata: bool = True
    #: Overwriting a file with more than one hard link destroys data reachable
    #: under names the operator did not give. Off by default; the finding is
    #: reported either way.
    break_hardlinks: bool = False
    recursive: bool = True
    #: After the erase, find the thumbnails, recent-files entries and Trash or
    #: Recycle Bin copies the desktop kept of these files, and remove the ones
    #: tied to an erased path on evidence. On by default because the problem
    #: this answers is the operator's. Only a trace tied to an erased path on
    #: evidence is removed; every other one is reported and left alone.
    sweep_traces: bool = True
    case_id: str = ""
    operator: str = "sanctum"


class DestroyRecordRequest(DestructionRecord):
    """Body for ``POST /jobs/record-destroy``: the attestation, and where to file it.

    Nothing is erased or opened. The record is chained and signed as what the
    named people attest; see :mod:`core.destroy`.
    """

    case_id: str = ""
    operator: str = "sanctum"


class PlanFreeSpaceRequest(Request):
    """Body for ``POST /workflow/wipe-free-space``: resolve a volume, write nothing."""

    #: The volume's mount point, exactly. A folder inside a volume is refused.
    mount_point: str


class WipeFreeSpaceRequest(DestructiveRequest):
    """Body for ``POST /jobs/wipe-free-space``. Always a real fill."""

    #: The volume's mount point, exactly. A folder inside a volume is refused.
    mount_point: str
    #: Required: the volume identifier ``POST /workflow/wipe-free-space``
    #: reports (the filesystem UUID, or the mount point when the volume has
    #: none).
    typed_identifier: str = ""
    operator: str = "sanctum"


class AcquireRequest(Request):
    """Body for ``POST /jobs/acquire``. Read-only: nothing is destroyed."""

    source: str
    dest: str
    fmt: Literal["raw", "e01"] = "raw"
    compression: Literal["none", "fast", "best"] = "fast"
    case_id: str = ""
    operator: str = "sanctum"
    #: For a raw device on Windows or macOS: the serial of the disk the operator
    #: selected. Not trusted - the reader binds its handle to it and refuses a
    #: disk that answers differently.
    expected_serial: str = Field(default="", max_length=128)


class CarveRequest(Request):
    """Body for ``POST /jobs/carve``. Read-only by construction."""

    image: str
    #: Walk filesystem metadata for deleted entries before carving. The undelete
    #: pass also returns the allocated/unallocated map, which is reported but
    #: deliberately does not bound the carve: bounding was measured and loses
    #: recall. It does supply each volume's cluster size to bifragment
    #: reassembly; with this off, reassembly walks 512-byte sectors instead,
    #: which is slower and reaches less. See :mod:`api.carve_job`.
    undelete: bool = True
    #: Run the signature and structure carvers over the whole image. Both, from
    #: one pass: the structure carver runs the signature scan itself and then
    #: derives each object's length from its own format where a parser exists.
    #: A baseline JPEG split into exactly two runs, with a gap of at most 2 MiB,
    #: is reassembled and scored MEDIUM at most; nothing else is. See
    #: :mod:`api.carve_job` for the exact scope.
    carve_signatures: bool = True
    #: Count Aadhaar, PAN, IFSC, mobile, card and email identifiers in each
    #: document, database or unclassified object. Kinds and counts only: no
    #: matched value is stored, logged or returned. See :mod:`core.carve.pii`.
    pii_triage: bool = True
    #: Map the image first: each region classed as zero, fill, text, structured
    #: or high-entropy from its byte statistics, with the file headers found on
    #: sector boundaries. Read-only, and sampled within a fixed budget on a
    #: large image. See :mod:`core.carve.mediamap`.
    media_map: bool = True
    #: Where recovered objects are written. None means nothing is written and
    #: only the candidate list is returned.
    out_dir: str | None = None
    case_id: str = ""
    operator: str = "sanctum"


class ResumeEraseRequest(DestructiveRequest):
    """Body for ``POST /jobs/{job_id}/resume``.

    Every gate again. A resume writes to the medium and is not a lesser
    operation than the run it continues.
    """

    typed_serial: str = ""
    #: Required. See api.authorization.
    authorization_id: str = ""
    operator: str = "sanctum"


class ReportRequest(Request):
    """Body for ``POST /reports/{job_id}``."""

    case_id: str = ""
    operator: str = "sanctum"
    #: The signing-key passphrase, for the desktop app, which has no terminal
    #: and no environment the operator set. Used to open the key for this one
    #: request; never logged, never stored, never echoed into the report.
    key_passphrase: str = Field(default="", repr=False)


class JobAccepted(BaseModel):
    """What every job endpoint returns: an id to stream, not a result."""

    job_id: str
    kind: str
    state: str
    #: Where to attach for live progress.
    stream_url: str


class CreateBackupRequest(Request):
    """Body for ``POST /workflow/backup``: record an image as a backup of a device."""

    #: A raw image under the evidence directory. Hashed read-only.
    backup_image: str
    #: The device the image is a backup of. Its identity is re-read by the helper.
    source_path: str
    #: Set when the image is the product of ``POST /jobs/acquire`` of this device:
    #: the acquisition's own hashes are reused and its job id is recorded.
    acquisition_job_id: str = ""
    case_id: str = ""
    operator: str = "sanctum"


class OpenRestoreRequest(Request):
    """Body for ``POST /workflow/restore``: plan a restore, write nothing."""

    backup_id: str
    target_path: str


class ApproveRestoreRequest(DestructiveRequest):
    """Body for ``POST /workflow/restore/{id}/approve``."""

    typed_serial: str = ""
    #: Must be sent true, deliberately. The typed serial alone is not approval.
    acknowledge_data_overwrite: bool = False


class ExecuteRestoreRequest(DestructiveRequest):
    """Body for ``POST /workflow/restore/{id}/execute``. Always a real restore."""

    #: Required. Re-checked by the helper against the serial it reads itself.
    typed_serial: str = ""
    case_id: str = ""
    operator: str = "sanctum"


class OpenHiddenAreaRequest(Request):
    """Body for ``POST /workflow/hidden-area``: discover, analyze, plan. No write."""

    path: str
    #: A recorded backup of the device (``POST /workflow/backup``). It must be
    #: verified, and cover the accessible range, before approval.
    backup_id: str = ""
    #: True (the default): the change lasts until the next power cycle. False
    #: asks for a permanent SET MAX, which approval must acknowledge separately.
    volatile: bool = True


class ApproveHiddenAreaRequest(DestructiveRequest):
    """Body for ``POST /workflow/hidden-area/{id}/approve``."""

    typed_serial: str = ""
    #: Must be sent true, deliberately. The typed serial alone is not approval.
    acknowledge_configuration_change: bool = False
    #: Must also be true when the plan is permanent (``volatile`` false).
    acknowledge_permanent: bool = False


class ExecuteHiddenAreaRequest(DestructiveRequest):
    """Body for ``POST /workflow/hidden-area/{id}/execute``. Always a real change."""

    #: Required. Re-checked by the helper against the serial it reads itself.
    typed_serial: str = ""
    case_id: str = ""
    operator: str = "sanctum"


class OpenFormatRequest(Request):
    """Body for ``POST /workflow/format``: plan one format. Writes nothing."""

    path: str
    filesystem: str = "exfat"
    label: str = "USB"


class ApproveFormatRequest(DestructiveRequest):
    """Body for ``POST /workflow/format/{id}/approve``."""

    typed_serial: str = ""
    #: Must be sent true, deliberately. The typed serial alone is not approval.
    acknowledge_format: bool = False


class ExecuteFormatRequest(DestructiveRequest):
    """Body for ``POST /workflow/format/{id}/execute``. Always a real format."""

    #: Required. Re-checked by the helper against the serial it reads itself.
    typed_serial: str = ""
    case_id: str = ""
    operator: str = "sanctum"
