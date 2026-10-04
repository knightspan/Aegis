"""``/artifacts`` serves two directories and nothing else.

The interesting tests here are the refusals. A recovered object is
attacker-controlled bytes under an attacker-influenced name, pulled off a disk
somebody else filled, and the endpoint that hands it to a browser is one
mistake away from being an arbitrary-file-read with a forensic label on it. So
each refusal has its own test naming the attack it closes, rather than one
parametrised test that would pass with half the checks removed.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from api.artifacts import MAX_INLINE_BYTES, content_type_for, disposition_for
from api.deps import AppServices
from fastapi.testclient import TestClient

# A real JPEG header, so nothing here depends on the server guessing.
JPEG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"\x00" * 64 + b"\xff\xd9"


def _recovered(services: AppServices, name: str, payload: bytes) -> Path:
    target = services.recovered_dir / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(payload)
    return target


# --------------------------------------------------------------------------
# Serving
# --------------------------------------------------------------------------


def test_a_recovered_image_is_served_with_its_type_and_renders_inline(
    client: TestClient, services: AppServices
) -> None:
    _recovered(services, "000000001024_09300_recovered.jpg", JPEG)

    answer = client.get("/artifacts/recovered/000000001024_09300_recovered.jpg")

    assert answer.status_code == 200
    assert answer.content == JPEG
    assert answer.headers["content-type"] == "image/jpeg"
    assert answer.headers["content-disposition"].startswith("inline")
    # Evidence-derived bytes do not belong in a shared cache.
    assert answer.headers["cache-control"] == "no-store"
    assert answer.headers["x-content-type-options"] == "nosniff"


def test_a_listing_names_every_artifact_and_no_host_path(
    client: TestClient, services: AppServices
) -> None:
    _recovered(services, "a.jpg", JPEG)
    _recovered(services, "nested/b.png", b"\x89PNG\r\n\x1a\n")

    answer = client.get("/artifacts/recovered")

    assert answer.status_code == 200
    body = answer.json()
    names = {item["name"] for item in body["artifacts"]}
    assert names == {"a.jpg", "nested/b.png"}
    # The absolute path of the output directory is not in the response at all.
    assert str(services.recovered_dir) not in answer.text


def test_download_forces_an_attachment_even_for_a_renderable_type(
    client: TestClient, services: AppServices
) -> None:
    _recovered(services, "a.jpg", JPEG)

    answer = client.get("/artifacts/recovered/a.jpg?download=true")

    assert answer.status_code == 200
    assert answer.headers["content-disposition"].startswith("attachment")


# --------------------------------------------------------------------------
# Refusals
# --------------------------------------------------------------------------


def test_a_traversal_out_of_the_root_is_refused(client: TestClient) -> None:
    answer = client.get("/artifacts/recovered/../../../../etc/passwd")

    # Starlette normalises some of these before routing; either the route
    # refuses it or it never matches. What must not happen is a 200 with a
    # file in it.
    assert answer.status_code in {400, 404}
    assert b"root:" not in answer.content


def test_an_encoded_traversal_is_refused(client: TestClient) -> None:
    answer = client.get("/artifacts/recovered/%2e%2e%2f%2e%2e%2fetc%2fpasswd")

    assert answer.status_code in {400, 404}
    assert b"root:" not in answer.content


def test_an_absolute_path_is_refused_rather_than_joined(client: TestClient) -> None:
    """``Path("/a") / "/etc/passwd"`` is ``/etc/passwd``.

    Joining is not a containment strategy, which is why the absolute case is
    rejected before any join happens.
    """
    answer = client.get("/artifacts/recovered//etc/passwd")

    assert answer.status_code in {400, 404}
    assert b"root:" not in answer.content


@pytest.mark.skipif(os.name == "nt", reason="symlink creation needs privilege on NT")
def test_a_symlink_pointing_out_of_the_root_is_refused(
    client: TestClient, services: AppServices, tmp_path: Path
) -> None:
    """The check that makes this a boundary and not a string-prefix test.

    A link planted *inside* the output directory has a name that is entirely
    inside the root. Only resolving it before the comparison catches it.
    """
    secret = tmp_path / "outside.txt"
    secret.write_text("not for the browser", encoding="utf-8")
    link = services.recovered_dir / "escape.txt"
    link.symlink_to(secret)

    answer = client.get("/artifacts/recovered/escape.txt")

    assert answer.status_code == 400, answer.text
    assert "not for the browser" not in answer.text
    assert answer.json()["detail"]["kind"] == "ArtifactRefused"


@pytest.mark.skipif(os.name == "nt", reason="symlink creation needs privilege on NT")
def test_an_escaping_symlink_is_left_out_of_the_listing(
    client: TestClient, services: AppServices, tmp_path: Path
) -> None:
    secret = tmp_path / "outside.txt"
    secret.write_text("x", encoding="utf-8")
    (services.recovered_dir / "escape.txt").symlink_to(secret)
    _recovered(services, "real.jpg", JPEG)

    body = client.get("/artifacts/recovered").json()

    assert {item["name"] for item in body["artifacts"]} == {"real.jpg"}


def test_an_unlisted_root_is_refused(client: TestClient) -> None:
    """A client names one of two words, never a directory."""
    answer = client.get("/artifacts/evidence/case.dd")

    assert answer.status_code == 404
    assert answer.json()["detail"]["kind"] == "ArtifactRefused"


def test_a_missing_artifact_is_a_404_and_not_an_exception(
    client: TestClient,
) -> None:
    answer = client.get("/artifacts/recovered/nothing-here.jpg")

    assert answer.status_code == 404
    assert answer.json()["detail"]["remediation"]


def test_a_directory_is_not_served_as_a_file(
    client: TestClient, services: AppServices
) -> None:
    (services.recovered_dir / "subdir").mkdir()

    answer = client.get("/artifacts/recovered/subdir")

    assert answer.status_code == 404


# --------------------------------------------------------------------------
# Typing: no sniffing, and nothing that executes in this origin
# --------------------------------------------------------------------------


def test_a_recovered_html_file_never_gets_a_renderable_type(
    client: TestClient, services: AppServices
) -> None:
    """The one that matters most.

    ``text/html`` served from this origin runs script in the page that holds
    the ledger view. A recovered ``.html`` is bytes off a seized disk, so it
    downloads as an opaque blob and is never rendered.
    """
    _recovered(services, "page.html", b"<script>alert(1)</script>")

    answer = client.get("/artifacts/recovered/page.html")

    assert answer.status_code == 200
    assert answer.headers["content-type"] == "application/octet-stream"
    assert answer.headers["content-disposition"].startswith("attachment")


def test_a_recovered_svg_never_gets_a_renderable_type(
    client: TestClient, services: AppServices
) -> None:
    _recovered(services, "vector.svg", b"<svg onload='alert(1)'/>")

    answer = client.get("/artifacts/recovered/vector.svg")

    assert answer.headers["content-type"] == "application/octet-stream"
    assert answer.headers["content-disposition"].startswith("attachment")


def test_a_recovered_pdf_downloads_rather_than_opening_in_a_viewer() -> None:
    """A PDF viewer is a scripting engine and the file came off the evidence."""
    assert disposition_for("recovered", "application/pdf", 1024) == "attachment"


def test_a_generated_report_pdf_may_render_because_this_tool_wrote_it() -> None:
    assert disposition_for("reports", "application/pdf", 1024) == "inline"


def test_a_large_image_is_offered_as_a_download_instead_of_inline() -> None:
    assert disposition_for("recovered", "image/jpeg", MAX_INLINE_BYTES + 1) == (
        "attachment"
    )


def test_an_unknown_extension_is_opaque() -> None:
    assert content_type_for(Path("x.weirdext")) == "application/octet-stream"


def test_a_filename_with_a_header_break_cannot_reach_the_header(
    client: TestClient, services: AppServices
) -> None:
    """A recovered name can carry a quote or a newline. It is replaced, not escaped.

    A header that needs escaping to be safe is one change away from not being.
    """
    from api.artifacts import safe_download_name

    assert "\n" not in safe_download_name('evil"\r\nSet-Cookie: a=b.jpg')
    assert '"' not in safe_download_name('evil"name.jpg')

    _recovered(services, "plain.jpg", JPEG)
    answer = client.get("/artifacts/recovered/plain.jpg")
    assert "\n" not in answer.headers["content-disposition"]
