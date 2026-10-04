"""There is no non-writing execution mode, and the read-only plan never writes.

The erase engine once had a ``dry_run`` switch that ran every phase except the
write. That mode is gone: :func:`core.erase.drive.execute` always executes.
What an operator reads before committing is :func:`core.erase.drive.preview`,
which is a separate, read-only function, not a flag on the executor.

Two properties are pinned here:

* every option model and request dataclass that once carried the switch now
  refuses it, rather than silently dropping it and running for real;
* ``preview`` reaches no write-capable seam: each one is a tripwire.
"""

from __future__ import annotations

import sys
from typing import Any
from unittest import mock

import pytest
from core.models import EraseJob, FileEraseOptions, FreeSpaceWipeOptions
from pydantic import ValidationError

from .conftest import make_caps, make_device, make_job


@pytest.mark.parametrize("key", ["dry_run", "simulation", "simulate"])
def test_an_erase_job_refuses_a_simulation_switch(key: str) -> None:
    job = make_job(make_device())
    with pytest.raises(ValidationError):
        EraseJob.model_validate({**job.model_dump(), key: True})


@pytest.mark.parametrize("model", [FileEraseOptions, FreeSpaceWipeOptions])
@pytest.mark.parametrize("key", ["dry_run", "simulation", "simulate"])
def test_option_models_refuse_a_simulation_switch(model: Any, key: str) -> None:
    with pytest.raises(ValidationError):
        model.model_validate({key: True})


def test_the_engine_requests_have_no_simulation_field() -> None:
    from core.erase.blockclear import ClearRequest
    from core.erase.devicesanitize import SanitizeRequest

    for request in (ClearRequest, SanitizeRequest):
        fields = set(request.__dataclass_fields__)
        assert not fields & {"dry_run", "simulation", "simulate"}, request


def _tripwire(name: str) -> Any:
    def hit(*_a: Any, **_k: Any) -> Any:
        raise AssertionError(f"the read-only preview reached {name}")

    return hit


@pytest.mark.skipif(
    sys.platform != "linux", reason="core.erase.drive is Linux-only by design"
)
def test_the_read_only_preview_never_reaches_a_write_seam() -> None:
    from core.erase import drive

    with (
        mock.patch.object(drive, "_open_for_write", _tripwire("_open_for_write")),
        mock.patch.object(drive, "_dispatch", _tripwire("_dispatch")),
        mock.patch.object(
            drive.calibrate_mod, "calibrate_write", _tripwire("calibrate_write")
        ),
        mock.patch.object(drive.verify_mod, "verify", _tripwire("verify")),
    ):
        answer = drive.preview(make_device(), make_caps())

    assert answer.plans, "the preview names a decision for every level"
