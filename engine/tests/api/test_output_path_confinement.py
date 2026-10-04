"""``POST /jobs/acquire`` and ``POST /jobs/carve`` may only write where told.

The API has no authentication of any kind. ``dest`` used to be passed through
verbatim, so any local process that could open ``127.0.0.1:8787`` could name any
path the API process can write and have a disk image written over it. The demo
runbook made the blast radius *root* by starting the API under ``sudo``; the
runbook is fixed separately, but a path check that only holds when the
deployment is configured correctly is not a check.

What is asserted here is the shape of the confinement, including the two ways
out of a naive one: an absolute path elsewhere, and a symlink planted inside the
directory that points out of it.
"""

from __future__ import annotations

from pathlib import Path

from api.deps import AppServices
from fastapi.testclient import TestClient


def make_source(tmp_path: Path) -> Path:
    source = tmp_path / "source.dd"
    source.write_bytes(b"E" * 4096)
    return source


def test_a_relative_dest_lands_in_the_evidence_directory(
    client: TestClient, services: AppServices, tmp_path: Path
) -> None:
    """The ordinary case needs no absolute path at all."""
    source = make_source(tmp_path)

    accepted = client.post(
        "/jobs/acquire", json={"source": str(source), "dest": "case-01.dd"}
    )

    assert accepted.status_code == 200, accepted.text
    status = client.get(f"/jobs/{accepted.json()['job_id']}").json()
    assert status["params"]["dest"] == str(services.evidence_dir / "case-01.dd")


def test_an_absolute_dest_outside_the_evidence_directory_is_refused(
    client: TestClient, tmp_path: Path
) -> None:
    """The arbitrary-write primitive, and it must be gone before anything opens."""
    source = make_source(tmp_path)
    escape = tmp_path / "elsewhere" / "planted.dd"

    refused = client.post(
        "/jobs/acquire", json={"source": str(source), "dest": str(escape)}
    )

    assert refused.status_code == 400, refused.text
    detail = refused.json()["detail"]
    assert detail["kind"] == "OutputPathRefused"
    assert "outside the configured output directory" in detail["error"]
    assert not escape.exists(), "the refusal must happen before anything is created"
    assert not escape.parent.exists()


def test_a_traversal_dest_is_refused(client: TestClient, tmp_path: Path) -> None:
    """``..`` is resolved, not string-matched."""
    source = make_source(tmp_path)

    refused = client.post(
        "/jobs/acquire",
        json={"source": str(source), "dest": "../../../../tmp/traversed.dd"},
    )

    assert refused.status_code == 400, refused.text
    assert refused.json()["detail"]["kind"] == "OutputPathRefused"


def test_a_symlink_planted_inside_the_directory_cannot_lead_out_of_it(
    client: TestClient, services: AppServices, tmp_path: Path
) -> None:
    """The check that makes this a boundary rather than a prefix test.

    A prefix comparison on the requested string would accept this: the path
    *starts with* the evidence directory. It resolves somewhere else entirely,
    and resolving before comparing is what notices.
    """
    source = make_source(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (services.evidence_dir / "escape").symlink_to(outside)

    refused = client.post(
        "/jobs/acquire",
        json={"source": str(source), "dest": "escape/planted.dd"},
    )

    assert refused.status_code == 400, refused.text
    assert refused.json()["detail"]["kind"] == "OutputPathRefused"
    assert not (outside / "planted.dd").exists()


def test_the_refusal_names_the_directory_the_operator_may_use(
    client: TestClient, services: AppServices, tmp_path: Path
) -> None:
    """A refusal an operator cannot act on is an outage, not a safety property."""
    source = make_source(tmp_path)

    refused = client.post(
        "/jobs/acquire", json={"source": str(source), "dest": "/etc/planted.dd"}
    )

    detail = refused.json()["detail"]
    assert str(services.evidence_dir.resolve()) in detail["remediation"]
    assert "relative" in detail["remediation"]


# --------------------------------------------------------------------------
# The same treatment for POST /jobs/carve's out_dir
# --------------------------------------------------------------------------
#
# Left alone in Batch 4 because that batch was scoped away from carving, and
# recorded as FINDING 4. It is the same defect with a different field name: an
# unauthenticated endpoint taking an output path from a request body.
#
# The directory differs, and the difference is deliberate. Recovered objects go
# to `recovered/`, not `evidence/`: evidence is read-only input, recovered
# objects are derived output, and a recovery that wrote into the tree holding
# the image it is reading is the one thing a carve path must never do.


def make_image(tmp_path: Path) -> Path:
    """A file that exists, so the route reaches the path check."""
    image = tmp_path / "evidence.dd"
    image.write_bytes(b"\x00" * 4096)
    return image


def test_a_relative_out_dir_lands_in_the_recovered_directory(
    client: TestClient, services: AppServices, tmp_path: Path
) -> None:
    image = make_image(tmp_path)

    accepted = client.post(
        "/jobs/carve",
        json={"image": str(image), "out_dir": "case-01", "undelete": False},
    )

    assert accepted.status_code == 200, accepted.text
    status = client.get(f"/jobs/{accepted.json()['job_id']}").json()
    assert status["params"]["out_dir"] == str(services.recovered_dir / "case-01")


def test_recovered_objects_do_not_go_to_the_evidence_directory(
    client: TestClient, services: AppServices, tmp_path: Path
) -> None:
    """Derived output must not be written into the read-only input tree."""
    image = make_image(tmp_path)

    accepted = client.post(
        "/jobs/carve",
        json={"image": str(image), "out_dir": str(services.evidence_dir / "out")},
    )

    assert accepted.status_code == 400, accepted.text
    assert accepted.json()["detail"]["kind"] == "OutputPathRefused"


def test_an_absolute_out_dir_outside_the_recovered_directory_is_refused(
    client: TestClient, tmp_path: Path
) -> None:
    image = make_image(tmp_path)
    escape = tmp_path / "elsewhere" / "recovered"

    refused = client.post(
        "/jobs/carve", json={"image": str(image), "out_dir": str(escape)}
    )

    assert refused.status_code == 400, refused.text
    detail = refused.json()["detail"]
    assert detail["kind"] == "OutputPathRefused"
    assert "outside the configured output directory" in detail["error"]
    assert not escape.exists(), "the refusal must happen before anything is created"


def test_a_traversal_out_dir_is_refused(client: TestClient, tmp_path: Path) -> None:
    image = make_image(tmp_path)

    refused = client.post(
        "/jobs/carve",
        json={"image": str(image), "out_dir": "../../../../tmp/traversed"},
    )

    assert refused.status_code == 400, refused.text
    assert refused.json()["detail"]["kind"] == "OutputPathRefused"


def test_a_symlinked_out_dir_cannot_lead_out_of_the_recovered_directory(
    client: TestClient, services: AppServices, tmp_path: Path
) -> None:
    image = make_image(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (services.recovered_dir / "escape").symlink_to(outside)

    refused = client.post(
        "/jobs/carve", json={"image": str(image), "out_dir": "escape/objects"}
    )

    assert refused.status_code == 400, refused.text
    assert refused.json()["detail"]["kind"] == "OutputPathRefused"
    assert not (outside / "objects").exists()


def test_the_out_dir_refusal_names_the_directory_the_operator_may_use(
    client: TestClient, services: AppServices, tmp_path: Path
) -> None:
    image = make_image(tmp_path)

    refused = client.post(
        "/jobs/carve", json={"image": str(image), "out_dir": "/etc/recovered"}
    )

    detail = refused.json()["detail"]
    assert str(services.recovered_dir.resolve()) in detail["remediation"]
    assert "relative" in detail["remediation"]


def test_omitting_out_dir_still_means_write_nothing(
    client: TestClient, tmp_path: Path
) -> None:
    """The confinement must not turn "no output" into "output somewhere"."""
    image = make_image(tmp_path)

    accepted = client.post("/jobs/carve", json={"image": str(image)})

    assert accepted.status_code == 200, accepted.text
    status = client.get(f"/jobs/{accepted.json()['job_id']}").json()
    assert status["params"]["out_dir"] is None
