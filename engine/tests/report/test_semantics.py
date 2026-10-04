"""Certificates name exactly what was done, and never claim more."""

from __future__ import annotations

import pytest
from core.models import EraseMethod
from core.report.semantics import CATEGORIES, describe, describe_kind


@pytest.mark.parametrize(
    ("method", "category", "protocol"),
    [
        ("SINGLE_PASS_OVERWRITE", "ADDRESSABLE WHOLE-DRIVE CLEAR", "block"),
        ("ATA_SANITIZE_BLOCK_ERASE", "DEVICE SANITIZE", "ATA"),
        ("NVME_SANITIZE_BLOCK", "DEVICE SANITIZE", "NVMe"),
        ("NVME_FORMAT_SES1", "DEVICE SANITIZE", "NVMe"),
        ("ATA_SECURITY_ERASE_ENHANCED", "DEVICE SANITIZE", "ATA"),
        ("ATA_SANITIZE_CRYPTO_SCRAMBLE", "CRYPTO ERASE", "ATA"),
        ("NVME_SANITIZE_CRYPTO", "CRYPTO ERASE", "NVMe"),
        ("SED_CRYPTO_ERASE", "CRYPTO ERASE", "TCG Opal"),
    ],
)
def test_each_method_has_one_category_and_protocol(
    method: str, category: str, protocol: str
) -> None:
    words = describe(method, verification={"strategy": "full_read"})
    assert words["category"] == category
    assert words["protocol"] == protocol


def test_every_erase_method_is_classified() -> None:
    from core.report.semantics import _METHODS

    for method in EraseMethod:
        assert method.value in _METHODS, method
        assert describe(method.value)["category"] in CATEGORIES


def test_no_category_claims_unrecoverable_or_secure_erase() -> None:
    texts = [describe(m.value, verification={}) for m in EraseMethod]
    texts += [describe_kind("files"), describe_kind("destroy")]
    for words in texts:
        blob = " ".join(str(value) for value in words.values()).lower()
        assert "unrecoverable" not in blob
        assert "secure erase" not in blob
        assert "military" not in blob


def test_an_overwrite_is_never_called_a_purge_or_nand_destruction() -> None:
    words = describe("SINGLE_PASS_OVERWRITE", verification={"strategy": "sampled"})
    assert "Not a Purge" in words["assurance"]
    assert "Not NAND-level destruction" in words["assurance"]
    assert "probability" in words["verification"]


def test_crypto_erase_says_the_ciphertext_remains() -> None:
    words = describe("NVME_SANITIZE_CRYPTO", verification={"strategy": "hw_attested"})
    assert "ciphertext remains" in words["assurance"]
    assert "changed" in words["verification"]


def test_a_run_with_no_read_back_is_not_verified() -> None:
    assert describe("SINGLE_PASS_OVERWRITE")["verification"].startswith("not verified")


def test_destruction_is_an_attestation_not_an_observation() -> None:
    words = describe_kind("destroy")
    assert words["category"] == "PHYSICAL DESTRUCTION ATTESTATION"
    assert "did not observe" in words["assurance"]
    assert describe_kind("carve") == {}
