# Compliance

What the standards and regulations say, what this tool does against them, and —
the part that matters — where it does not, and where nobody has checked.

Nothing here claims certification or conformance. No product is "NIST
certified"; SP 800-88 is a guideline. The claims below are of three kinds, and
each row says which:

* **Implemented** — the code does the thing, and the row names the code.
* **Supports** — the tool produces a record or evidence an organisation can use
  towards an obligation. The obligation stays the organisation's.
* **Not verified** — the tool's behaviour has not been checked against the
  standard's text, usually because that text has not been available to this
  project.

Every external fact on this page was checked against the source listed in
[Sources](#sources) on 2026-09-14.

---

## Status of the standards this tool used to cite

**NIST SP 800-88 Revision 1 (December 2014) was withdrawn on 2025-09-26.** It
is superseded by **NIST SP 800-88r2**, *Guidelines for Media Sanitization*
(Ramaswamy Chandramouli and Eric A. Hibbard, September 2025,
doi:10.6028/NIST.SP.800-88r2). Until 2026-09-14 this project's code, UI,
reports and documents cited Rev.1. They now cite r2, with every claim restated
against r2's text.

Per r2's own change log (Appendix D) and NIST's announcement, r2:

* shifts focus from hands-on sanitization decisions to establishing an agency or
  enterprise media sanitization **program**;
* aligns media sanitization with SP 800-53 and ISO/IEC 27040;
* apart from cryptographic erase, **replaces all sanitization technique and tool
  detail with recommendations to comply with IEEE 2883, NSA specifications, or
  an organizationally approved standard** — Rev.1's per-media tables (its
  Appendix A) are gone;
* addresses the issue of trusting a vendor's implementation of sanitization
  techniques for clear and purge;
* removes almost all verification language, and states that full or
  representative sampling is not needed unless the organisation requires it;
* introduces sanitization **assurance**: verification (did the technique
  complete) and validation (does the organisation accept the outcome).

---

## NIST SP 800-88r2 — *Guidelines for Media Sanitization*

### Sec. 3.1 — the three sanitization methods. Unchanged.

r2 keeps clear, purge and destroy, and its definitions (Sec. 3.1.1–3.1.3 and
Appendix A) say what Rev.1's definitions said in all but wording:

| Method | r2's definition | Where in this tool |
|---|---|---|
| **Clear** | logical techniques applied to all user-addressable storage locations, protecting against simple, non-invasive recovery through the same interface available to the user | **Implemented.** `SINGLE_PASS_OVERWRITE`, `DOD_5220_22_M_3PASS` (`core/erase/patterns.py`); `core/erase/drive.py` on Linux, `core/erase/blockclear.py` on Windows and macOS |
| **Purge** | physical or logical techniques that make recovery infeasible using state-of-the-art laboratory techniques | **Implemented, per media type and per platform** — see below. On Linux `ATA_SANITIZE_*`, `NVME_SANITIZE_BLOCK`, `NVME_FORMAT_SES1`, `SED_CRYPTO_ERASE`; `ATA_SECURITY_ERASE_ENHANCED` and `ATA_SANITIZE_OVERWRITE` on magnetic media only. On Windows ATA SANITIZE (block erase, crypto scramble) and NVMe Sanitize (block, crypto) through `core/erase/devicesanitize.py`. On macOS none: PLATFORM-LIMITED. **No Purge method has run on a physical drive on any platform.** |
| **Destroy** | recovery infeasible using state-of-the-art laboratory techniques, and the medium can no longer store data | **Never returned.** No software can perform it. |

`SanitizationLevel` in `core/models.py` has exactly these three members.
Because the vocabulary and the definitions did not move, **r2 itself required
no change to the engine's decision logic.** What did change is where the
*technique* rules come from. Reading the withdrawn r1 tables against the code
exposed one classification r1 did not support, and it was corrected on
2026-09-15 (below).

### Which techniques reach purge: what r2 supports, and what rests on Rev.1 alone

`core/device/capabilities.py:_purge_candidates` is the one place that decides;
`_achievable_levels`, `recommend_method` and the level written to the report
(`core/erase/drive.py:_achieved_level`) all read it. It takes the probed
capability and whether `core/device/media.py:is_flash` determines the device to
be flash. r2 defers technique acceptability to IEEE 2883, which has not been
read, so **the per-media rule is taken from the withdrawn r1 Appendix A tables,
used here as the organisationally approved standard until IEEE 2883 is
checked.** Against r2's text:

| Technique | Counted as | What r2's text says | Status |
|---|---|---|---|
| Host overwrite of every LBA | Clear | Sec. 3.1.1: overwrite through standard read and write commands is a clear technique; on flash with spare cells and wear levelling it cannot sanitize all previous data | Supported by r2 |
| ATA SANITIZE (block erase, crypto scramble, overwrite); NVMe sanitize | Purge | Sec. 3.1.2: logical purge techniques "can include overwrite, block erase, and cryptographic erase using dedicated, standardized device sanitize commands"; IEEE 2883 should be consulted for which are acceptable | Supported by r2 in general terms; **per-technique acceptability not verified against IEEE 2883** |
| Cryptographic erase (Opal, NVMe Format with crypto erase, ATA crypto scramble) | Purge | Sec. 3.2: CE is a purge technique, subject to conditions on key sanitization, cryptographic strength, implementation quality and the absence of prior plaintext (Sec. 3.2.1–3.2.4) | Classification supported; **the conditions are not checked** (see the trust table) |
| **ATA SECURITY ERASE UNIT, enhanced** | **Purge on magnetic media; Clear on flash** | **Not named in r2.** It is not a sanitize command. | **Rests on withdrawn r1 alone.** See the quotations below. Until 2026-09-15 this tool counted it as purge on any media, contradicting r1 on flash. |
| ATA SANITIZE overwrite | Purge on magnetic media; not counted on flash | As for ATA SANITIZE above | r1 Table A-5 lists it for ATA hard disk drives; r1 Table A-8 does not list it for ATA SSDs |

#### The r1 text the enhanced-erase rule rests on

NIST SP 800-88r1 (December 2014, withdrawn 2025-09-26), Appendix A, quoted
verbatim. Page numbers are the printed ones.

**Table A-5: Magnetic Media Sanitization — "ATA Hard Disk Drives This includes
PATA, SATA, eSATA, etc"**, Purge, pp. 32–33:

> Four options are available:
> 1. Use one of the ATA Sanitize Device feature set commands, if supported, to perform a Sanitize operation. One or both of the following options may be available: a. The overwrite EXT command. […] b. If the device supports encryption and the technical specifications described in this document have been satisfied, the Cryptographic Erase (also known as CRYPTO SCRAMBLE EXT) command. […]
> 2. Use the ATA Security feature set's SECURE ERASE UNIT command, if support, in Enhanced Erase mode. The ATA Sanitize Device feature set commands are preferred over the over the ATA Security feature set SECURITY ERASE UNIT command when supported by the ATA device.
>
> […options 3, TCG Opal or Enterprise SSC Cryptographic Erase, and 4, degaussing, follow.]

and in its Notes, p. 33:

> Given the variability in implementation of the ATA Security feature set SECURITY ERASE UNIT command, use of this command is not recommended without first consulting with the manufacturer to verify that the storage device's model-specific implementation meets the needs of the organization.
> This guidance applies to Legacy Magnetic media only, and it is critical to verify the media type prior to sanitization. Note that emerging media types, such as HAMR media or hybrid drives may not be easily identifiable by the label.

**Table A-8: Flash Memory-Based Storage Device Sanitization — "ATA Solid State
Drives (SSDs) This includes PATA, SATA, eSATA, etc."**, p. 36:

> Clear: 1. Overwrite media by using organizationally approved and tested overwriting technologies/methods/tools. […] 2. Use the ATA Security feature set's SECURITY ERASE UNIT command, if supported.
>
> Purge: Three options are available: 1. Apply the ATA sanitize command, if supported. One or both of the following options may be available: a. The block erase command. […] b. If the device supports encryption, the Cryptographic Erase (also known as sanitize crypto scramble) command. […] 2. Cryptographic Erase through the TCG Opal SSC or Enterprise SSC interface by issuing commands as necessary to cause all MEKs to be changed. […]

and in its Notes, p. 37:

> Given the variability in implementation of the Enhanced Secure Erase feature, use of this command is not recommended without first referring the manufacturer to identify that the storage device's model-specific implementation meets the needs of the organization.
> Whereas ATA Secure Erase was a Purge mechanism for magnetic media, it is only a Clear mechanism for flash memory due to variability in implementation and the possibility that sensitive data may remain in areas such as spare cells that have been rotated out of use.

(The "[…]" marks omitted optional follow-up steps; "if support" and "over the
over the" are r1's own text. Table A-8's third Purge option is not in the ATA
SSD entry's text as extracted; the entry says "Three options" and lists two.)

**r2** (September 2025) does not mention SECURITY ERASE UNIT, enhanced erase or
secure erase in any section. It delegates: Sec. 3.1 (p. 8), "the latest version
of standards (e.g., IEEE 2883 [13]) should be consulted"; Sec. 3.1.2 (p. 10),
"IEEE 2883 [13] should be consulted to determine acceptable purge sanitization
techniques, which can include overwrite, block erase, and cryptographic erase
using dedicated, standardized device sanitize commands"; Sec. 4.4 (p. 23),
sanitization should be performed "in a manner that complies with IEEE 2883 [13]
[…] or a standard that is identified as acceptable by organizational policy";
Appendix D (p. 38), "all sanitization technique and tool details have been
replaced with recommendations to comply with IEEE 2883, NSA specifications, or
an organizationally approved standard."

**Decision.** With r1 restricting enhanced erase to Clear on flash, r2 silent,
and IEEE 2883 unread, nothing supports a Purge claim for enhanced erase on flash.
On a device `is_flash` determines to be flash, enhanced erase and ATA SANITIZE
overwrite are not Purge mechanisms; Purge comes from ATA SANITIZE block erase or
crypto scramble, NVMe sanitize, NVMe Format with cryptographic erase, or an Opal
cryptographic erase. The capability record says why, quoting Table A-8, and a
report that somehow carries an enhanced erase on flash records it as Clear with a
residual-risk factor. On magnetic media enhanced erase stays Purge on r1 Table
A-5, and the capability record says that basis is withdrawn.

**Not validated on hardware.** No SATA SSD has been available, so the flash
half cannot be validated on real media, and no ATA firmware erase path of this
tool has run on hardware (Sec. 4.5 below). The mapping is covered, per
device class and capability profile, by `tests/device/test_purge_by_device_class.py`
and `tests/erase/test_enhanced_erase_on_flash.py`. Those tests are the only
evidence for it. The flash determination itself is a heuristic
(`docs/limitations.md`, "`queue/rotational` is not a flash test"): a hybrid drive
or an SSD whose kernel flag and model string both look magnetic would be treated
as magnetic.

### Sec. 4.3 — the decision framework

r2 bases the sanitization decision on the confidentiality categorisation of the
information (FIPS 199 for federal systems) and on whether the medium is to be
reused. The media type then decides the technique. This tool implements only
the technique half: the method is derived from probed device capability, never
chosen by the operator (`core/erase/drive.py:select_method` on Linux; on Windows
the options the capability resolver, `core/platform/capability.py`, derives from
the controller's own IDENTIFY answer). The categorisation, the reuse decision and
the policy are organisational inputs this tool does not have and does not guess
at.

A request for Purge on a device that cannot reach it raises
`UnsupportedCapability`; it is never quietly delivered as Clear.

### Sec. 4.2 — partial sanitization, and what a file erasure is

r2 distinguishes *selective* sanitization (the sensitive data wherever it
resides) from *partial* sanitization (a region of the medium), and notes that
partial sanitization carries the risk that sensitive data spilled into other
areas. A per-file erasure (`core/erase/files.py`) overwrites only the named
files' extents. **It is not reported as a clear, a purge or a destroy of
anything**, and the file-erasure report says so in its `scope.standards` field.
The residual findings (`core/erase/residual.py`) name the other areas the tool
knows of.

A free-space wipe (`core/erase/freespace.py`) overwrites the blocks a FAT32, exFAT
or ext4 volume reports as free, and so reaches the content of files deleted before
it ran. It is also partial sanitization in r2's sense: file slack, deleted
directory entries, journals, metadata, root-reserved blocks and remapped flash pages
are outside it. **It is not reported as a clear, a purge or a destroy.** Its result
lists what it did not reach and sets `verified` to `null`, because it reads nothing
back.

### Sec. 4.5 — sanitization assurance

| r2 | This tool |
|---|---|
| **4.5.1 Verification.** Clear and logical purge can be verified by checking the tool's completion status, errors, anomalies and the health of the medium. Full or representative sampling is not necessary unless organisational policy requires it. | **Implemented, beyond r2's minimum.** Completion is reconciled byte by byte; `EIO` ranges are recorded (`core/erase/drive.py`). The medium is read back — every block at or below 64 GiB, seeded sampling above, with the seed and detection-probability formula recorded (`core/erase/verify.py`). After a firmware sanitize the drive's status log is read, and the medium is read too. **Not done:** medium health (no SMART is read). The firmware-sanitize path has never run on hardware. |
| **4.5.2 Validation.** The organisation decides whether to accept the outcome, weighing errors, inaccessible regions, an inappropriate technique, unqualified personnel or uncalibrated tools, and a scope that was too narrow (r2's example: clear on an over-provisioned device). | **Supports, does not perform.** The report's residual-risk section names inputs to that decision: unwritable ranges, uncovered HPA/DCO, flash with a host overwrite, detected write elision. Accepting or rejecting is not the tool's decision, and the certificate says so in `method.standards.verification_and_validation`. |

### Sec. 4.6 and Appendix C — the certificate of sanitization

r2 lists what a completed certificate should record. The signed report
(`core/report/render.py:build_report`) against that list:

| r2 Sec. 4.6 field | In the report |
|---|---|
| Manufacturer | **Not a separate field.** Only the model string is recorded. |
| Model, serial number | 2. Device Identity (`model`, `serial`, `by_id_path`) |
| Organizationally assigned media or property number | **Not recorded** |
| Media type | 2. Device Identity (`transport`, block sizes); the flash determination is in the residual-risk factors |
| Media source | **Not recorded** |
| Pre-sanitization confidentiality categorization (optional) | **Not recorded** |
| Sanitization method (clear, purge, destroy) | 3. Method (`level_requested`, `level_achieved`) |
| Sanitization technique | 3. Method (`method`, `justification`, `capability_evidence`) |
| Tool used, including version | 1. Case Identity (`tool_version`) |
| Verification method | 5. Verification (`strategy`, `bytes_checked`, `sample_seed`, `probability_note`) |
| Individuals performing verification and validation: name, title, date, location, contact, signature | **Partly.** `operator` is a free-text name supplied with the request (default `sanctum`) and `generated_at` is the date. No title, location, contact, validating person or personal signature is recorded. The Ed25519 signature attests to the bytes, not to a person. |

Appendix C's sample form also has a *concurrence* signature and a *media
destination* block. **Neither exists here**; there is no second-person approval
anywhere in the tool.

The fields the report does not record are listed inside every drive
certificate, under `method.standards.nist_sp_800_88r2_sec_4_6_fields_not_recorded`,
so the gap travels with the document.

The certificate is issued as two artifacts: a canonical JSON that is
authoritative and carries the Ed25519 detached signature, and a PDF that states
on its own face that it is a rendering and not the authoritative artifact.

### The five certificate categories, against r2's methods

Every certificate names one category of what was done
(`core/report/semantics.py`), with the method, protocol, scope, verification and
assurance words it prints. The categories are never merged, and none of them
produces the words "unrecoverable" or an undifferentiated "secure erase".

| Category | What was done | r2 method it maps to | Physically run here |
|---|---|---|---|
| **FILE ERASE** | A file's current blocks overwritten through the filesystem | None. Partial sanitization in r2 Sec. 4.2; not a clear, purge or destroy of anything | Windows NTFS on the host's system disk, 2026-09-27 (device class not recorded) |
| **ADDRESSABLE WHOLE-DRIVE CLEAR** | Every LBA the operating system exposes overwritten by the host and read back | **Clear** only. Never Purge, and on flash never NAND-level destruction: remapped and over-provisioned blocks are not addressable | Linux, one USB flash stick, 2026-09-05. Windows and macOS: IMPLEMENTED / UNVALIDATED |
| **DEVICE SANITIZE** | The drive's own firmware command (ATA SANITIZE, ATA SECURITY ERASE, NVMe Sanitize, NVMe Format) | **Purge**, only when the drive's firmware performs the command as its specification requires; completion is the drive's or driver's own claim, and the medium is also read back | None, on any platform. DEVICE-DEPENDENT on Linux and Windows; PLATFORM-LIMITED on macOS |
| **CRYPTO ERASE** | The media encryption key replaced | **Purge** by cryptographic erase (r2 Sec. 3.2), with the r2 Sec. 3.2.4 caveat that it rests on key management the host cannot inspect; the ciphertext remains | None, on any platform |
| **PHYSICAL DESTRUCTION ATTESTATION** | A person's signed statement about a destruction | **Destroy**, as attested. The tool neither performs nor observes it | n/a: nothing is observed |

What is implemented on which platform, and which device classes have a recorded
physical run, is generated from the resolver:
[`validation/capability-completion-2026-09-28/capability-matrix.md`](validation/capability-completion-2026-09-28/capability-matrix.md).
A mapping row here is not a claim that the path has run on hardware.

### Trust establishment — what r2 asks, mapped against what this tool built

r2's change log says the revision "addressed" the issue of trusting a vendor's
implementation of clear and purge. It has no single section by that name. The
passages that address it, as this project reads r2, are:

* **Sec. 3.1.1** — dedicated sanitize commands "require trust and assurance from
  the ISM vendor that the commands have been implemented as expected";
* **Appendix B** — no assumption should be made about what a command does; "it
  is also important to verify the functionality of commands as the command name
  might imply a certain capability but not actually meet minimum requirements";
  it "may be difficult or impossible for users to know for sure how the
  sanitization action is being implemented"; vendors should be asked for the
  supported commands, the areas each does not address, the time each takes,
  results of any validation testing, and compliance with IEEE 2883;
* **Sec. 4.1** — policy should state what assurances (guarantees, assessment
  results, formal certifications) the vendor should provide, and cover tool
  calibration, testing and maintenance;
* **Sec. 3.2.4** — for cryptographic erase, seek independent validation of, or
  vendor statements on, entropy, algorithm strength, key sanitization and key
  wrapping (FIPS 140-3 validated modules for federal agencies); **Sec. 3.2.5**
  lists ten items of CE traceability;
* **Sec. 4.5** — verification and validation, above.

Against those passages, conservatively:

| What this tool does | What r2 asks that it bears on | What it establishes | What it does **not** do |
|---|---|---|---|
| **Probes capability instead of assuming it** — `hdparm -I`, NVMe Identify Controller SANICAP, `sedutil-cli`; a probe that fails is reported as unknown, never as absent (`core/device/capabilities.py`) | App. B: find out which sanitize commands the device supports | Which commands the device *advertises* through its interface, and the raw evidence, recorded in the certificate | It does not establish that an advertised command is implemented as named, which is App. B's warning. No vendor statement, statement of volatility, list of unaddressed areas or validation result is sought or recorded. |
| **Write calibration** — times a 64 MiB non-zero fill against a 64 MiB zero fill; a ratio of 2.0 or more records `CONTROLLER_WRITE_ELISION` and switches the fill to `0xA5` (`core/erase/calibrate.py`, `core/erase/patterns.py`) | App. B: verify what the device actually does; Sec. 4.5.2: an outcome can complete and still not be effective | A behavioural test of whether this controller programs a zero write, independent of what it reports. Measured on one USB stick (ratio 3.25–3.62) | It tests host writes only, not any sanitize command. The threshold is a heuristic measured on one device. It cannot detect remapped or over-provisioned data, which r2 Sec. 3.1.1 says a host overwrite cannot reach on flash. |
| **Post-wipe read-back** of the medium, and the drive's own sanitize status after a firmware method (`core/erase/verify.py`) | Sec. 4.5.1 verification | That every addressable block the device serves returns the expected pattern. Measured over 7,759,462,400 bytes, twice. | On flash every read is answered by the translation layer, so it cannot establish physical removal. The status log is the drive's claim about itself. Medium health is not checked. The firmware path has not run on hardware. |
| **Tri-state per-file verification** — exactly one function can construct `passed=True`, and only after a raw read of the original extents (`core/erase/verify.py:verify_file_erase`) | Sec. 4.5.1: determine the outcome | That a pass is never reported without a physical read, and that "could not check" is recorded as such | Most file erasures come back `not_possible`, including every one on FAT32 and exFAT. It is not a validation. |
| **Residual-risk findings** — unwritable ranges, HPA/DCO coverage, flash with host overwrite, detected elision (`core/erase/verify.py:assess_residual_risk`) | Sec. 4.5.2: inputs to validation | The conditions r2 lists as calling effectiveness into question, where the tool can detect them | The acceptance decision. Personnel qualification and tool calibration records. |
| **Hash-chained ledger** — entry N carries SHA-256 of N-1 (`core/ledger/chain.py`) | Sec. 4.6: documentation, electronic records | That recorded entries were not altered afterwards without detection | r2 does not ask for tamper evidence. The operator owns the chain, so it is evidence of sequence, not of custody (`docs/privilege-boundary.md`). |
| **Signed certificate** — Ed25519 over canonical JSON (`core/report/sign.py`) | Sec. 4.6 and App. C | That the certificate's bytes are those the key holder signed | It does not prove who signed; the fingerprint must be checked out-of-band. It is not the personal signature or concurrence App. C shows. |
| **Third-party verification** — `sanctum verify-report`, five independent checks (`core/report/verify_report.py`) | Nothing in r2 asks for this | That a recipient can check the record's integrity without the tool's cooperation | It verifies the record, not the sanitization. |
| **Not built** | Sec. 3.2.2–3.2.5 (CE preconditions, implementation quality, the ten traceability items); Sec. 4.1 vendor assurances; a program, policy, roles and media tracking (Sec. 4, 4.7) | — | None of these. Opal cryptographic erase is also unreachable in this build: no PSID can be supplied. |

---

## IEEE 2883-2022 — *IEEE Standard for Sanitizing Storage*

**This project does not have the text of IEEE 2883-2022.** It is an active
standard, published 2022-08-17, sold by IEEE. Nothing in this repository has
been checked against its clauses.

What can be stated, because it is a fact about NIST SP 800-88r2 and not about
IEEE 2883:

* r2 Sec. 4.4 says sanitization should be performed "in a manner that complies
  with IEEE 2883" or with a standard identified as acceptable by organisational
  policy (its examples are NSA/CSS Policy 6-22 and Policy Manual 9-12);
* r2 Sec. 3.1 and 3.1.2 say the latest version of IEEE 2883 should be consulted
  for technology-specific techniques, and to determine acceptable purge
  techniques;
* r2 Sec. 4.3 and 4.3.6 point to IEEE 2883.1, *Recommended Practice for Use of
  Storage Sanitization Methods*, for further guidance. It has not been read
  either.

In its own terms, the tool: selects a method from probed device capability;
prefers a device-implemented sanitize command over host overwrite; treats flash
as its own case for host overwrite; reads the medium back after every erase;
and records the evidence for each of those decisions in a signed certificate.

**Conformance of this tool to IEEE 2883-2022 has not been verified against the
document text, and no conformance is claimed.** Every certificate says the same
thing in `method.standards.technique_standard`.

---

## ISO/IEC 27040:2024, and IS/ISO/IEC 27040:2024

ISO/IEC 27040:2024, *Information technology — Security techniques — Storage
security*, is the second edition, replacing the 2015 edition. The Bureau of
Indian Standards lists **IS/ISO/IEC 27040:2024** with the same title as an
active Indian Standard (committee LITD 17). **The text of neither has been
read**, so no clause number is cited here.

What NIST SP 800-88r2 attributes to ISO/IEC 27040, which is checkable against
r2:

* storage sanitization should be part of data governance, with at minimum:
  policies, scope and decision criteria, performing sanitization, determining
  its adequacy, and the records needed to meet compliance obligations (r2
  Sec. 4);
* verifying the adequacy or effectiveness of sanitization outcomes (r2 Sec. 4.5);
* for cryptographic erase: at least 128-bit cryptographic strength; entropy at
  least the key length; no sensitive data previously stored in plaintext; all
  copies of the target keys able to be sanitized; independent validation or
  vendor statements on implementation quality (r2 Sec. 3.2.1–3.2.4).

| Requirement as r2 relays it | This tool |
|---|---|
| Performing sanitization and determining its adequacy | **Supports**: sanitization, read-back and residual risk, in a signed record |
| Records to meet compliance obligations | **Supports**: the certificate and ledger. Fields it lacks are listed above. |
| Policy, scope, decision criteria, governance | **Not done** — organisational |
| CE preconditions and implementation validation | **Not done** |

---

## Indian instruments

For each: what it requires, whether Sanctum's output helps, and what it does not
cover. **An instrument with no specific media-sanitization requirement is
listed as such.** No obligation has been added that the source does not create.

| Instrument | What it requires, as relevant here | Does Sanctum's output help? | What it does not cover |
|---|---|---|---|
| **MeitY guidance on media sanitization or e-waste disposal** | **None located.** A search of meity.gov.in found no MeitY publication prescribing media sanitization before disposal. Commercial sites describing "MeitY advisories" on data sanitization cite no document, and none is relied on here. | — | — |
| **CERT-In, *Guidelines on Information Security Practices for Government Entities*** (issued June 2023; applies to Central Government ministries, departments, their offices and PSUs, per its Sec. 2) | **No media disposal or sanitization section.** Two passages touch media: Part 1 Sec. 11.2.2 requires security awareness and training to include "Classifying, marking, controlling, storing and sanitizing media"; Part 2 (guidelines for government employees) Sec. 7.2, under *Removable media security*: "Perform a secure wipe to delete the contents of the removable media." It defines no technique, level, verification or record for a "secure wipe". | **Supports** Part 2 Sec. 7.2 for removable media: M1 performs a whole-device Clear with read-back and a signed record. Because the guideline defines no standard for "secure wipe", the tool cannot be said to satisfy a defined requirement. | Training (Sec. 11.2.2). Classification, marking and control of media. Any disposal decision. |
| **IT Act 2000, s. 43A**, with the **IT (Reasonable Security Practices and Procedures and Sensitive Personal Data or Information) Rules, 2011** (G.S.R. 313(E)), rule 8 | s. 43A: a body corporate handling sensitive personal data that is negligent in implementing and maintaining reasonable security practices, causing wrongful loss or gain, is liable to pay compensation. Rule 8: reasonable security practices are a documented information security programme and policies; IS/ISO/IEC 27001 is named as one such standard; compliance is certified or audited by an independent auditor approved by the Central Government. **No specific media-sanitization requirement.** **s. 43A will be omitted** when s. 44(2)(a) of the DPDP Act 2023 comes into force, eighteen months after G.S.R. 843(E) of 13 November 2025. | **Supports only as documentary evidence** of one control an ISMS may contain. | The programme, the policies, ISO/IEC 27001 implementation and the independent audit. A signed certificate is not evidence of "reasonable security practices" on its own. |
| **Digital Personal Data Protection Act, 2023, s. 8(7)** | A Data Fiduciary shall, unless retention is necessary for compliance with any law, (a) erase personal data when the Data Principal withdraws consent or as soon as it is reasonable to assume the specified purpose is no longer served, and (b) cause its Data Processor to erase personal data made available to it. s. 8(5) requires reasonable security safeguards to prevent a personal data breach. **Not yet in force:** G.S.R. 843(E) brings ss. 3–17 into force eighteen months after its publication on 13 November 2025. | **Supports s. 8(7)(a) for data on a device or in files the tool erases.** The artifact that discharges the *act* is the signed certificate: it names the device (model, serial, by-id path) or the paths, the method, and the verification result, and binds them to a hash-chained ledger entry. For a file erasure it also names what the filesystem retained. | Deciding that the purpose is served or consent was withdrawn; checking that no law requires retention; finding every other copy (backups, cloud, replicas); erasure by a Data Processor under s. 8(7)(b); and, for a file erasure, the residual copies the report itself names. **The certificate records these as requiring a person**, under `regulatory_references`. |
| **Digital Personal Data Protection Rules, 2025** (G.S.R. 846(E), 13 November 2025), rules 6 and 8 | Rule 8(1): for the classes of Data Fiduciary and purposes in the Third Schedule, erase personal data after the specified period of inactivity unless law requires retention. Rule 8(2): inform the Data Principal at least 48 hours before that erasure. Rule 8(3), and rule 6(1)(e): retain personal data, associated traffic data and processing logs for at least one year. **Not yet in force:** rules 3 and 5–16 come into force eighteen months after publication. | **Supports rule 8(1)** in the same way as s. 8(7). | The 48-hour notice. The one-year retention of rule 8(3) — an erasure that destroys those logs would itself breach the rules, and the tool cannot tell which data is a log that must be kept. |
| **IS/ISO/IEC 27040:2024** (BIS) and **ISO/IEC 27040:2024** | See the section above. Text not read; requirements known only as NIST SP 800-88r2 relays them. | **Supports** performing, verifying and recording sanitization | Governance, policy, CE preconditions; any clause-level claim |

### Conclusion: no Indian instrument located specifies a sanitization technique

Each instrument read for this section requires something about media or
erasure. None of them specifies how media is to be sanitized: no technique, no
distinction between clear, purge and destroy, no verification step and no
record.

* **MeitY:** no publication prescribing media sanitization, before disposal or
  otherwise, was located on meity.gov.in.
* **CERT-In, *Guidelines on Information Security Practices for Government
  Entities* (June 2023):** requires government employees to "Perform a secure
  wipe to delete the contents of the removable media" (Part 2 Sec. 7.2), and
  requires security training to cover sanitizing media (Part 1 Sec. 11.2.2). It
  does not define "secure wipe".
* **IT Act 2000 s. 43A and SPDI Rules 2011 rule 8:** require reasonable security
  practices and procedures, and name IS/ISO/IEC 27001 as one standard that
  satisfies them. They contain no media-sanitization requirement. s. 43A is
  omitted by DPDP Act s. 44(2)(a) when that provision comes into force.
* **DPDP Act 2023 s. 8(7), and DPDP Rules 2025 rule 8:** require personal data to
  be erased in the circumstances they set out. They do not say how erasure is to
  be performed or evidenced.
* **IS/ISO/IEC 27040:2024** is listed by BIS as an active Indian Standard, but its
  text has not been read, so whether it specifies sanitization techniques is not
  stated here.

In that space this tool uses **NIST SP 800-88r2** for the sanitization methods
(clear, purge, destroy; Sec. 3.1) and, for per-media techniques, the tables of
the withdrawn **SP 800-88r1** Appendix A, as set out under NIST SP 800-88r2
above. The reasons: no Indian instrument located fills the gap; r2 is the
current revision of the guideline, and NIST's announcement of it describes it
as aligned with ISO/IEC 27040; r2 defers technique detail to IEEE 2883, whose
text has not been read, so r1's tables are the most recent per-media technique
text this project has read. SP 800-88 is a United States federal guideline, not an
Indian instrument and not an ISO or IEC standard. Using it does not create
compliance with any instrument listed above.

**Dated note (2026-09-15).** DPDP Act ss. 3–17 and s. 44(2) come into force
eighteen months after G.S.R. 843(E) was published on 13 November 2025, and DPDP
Rules 3 and 5–16 eighteen months after their publication on the same date. On
this date those erasure duties, and the omission of IT Act s. 43A, are not yet in
force. This note must be revised when they commence.

### What changed on the certificate

Drive-erasure and file-erasure certificates now carry two fields inside the
signed JSON:

* `standards` — the method vocabulary (NIST SP 800-88r2 Sec. 3.1), the
  technique standard (IEEE 2883, conformance not verified), the
  verification/validation split, and, for a drive, the r2 Sec. 4.6 fields the
  report does not record. A file erasure's block says no sanitization method is
  claimed.
* `regulatory_references` — one entry, DPDP Act 2023 s. 8(7), with its
  commencement status, what the record evidences, and what requires a person.

They sit in the existing `method` section (drive) and `scope` section (file
erasure). No section was added or reordered, the canonical serialisation is
unchanged, and `verify_report` does not read either field, so **every report
signed before this change still verifies exactly as it did**
(`tests/report/test_verify_report.py`). The recovery report carries neither:
recovery is not erasure.

No field names CERT-In, IT Act s. 43A or ISO/IEC 27040. None of them creates an
obligation a single erasure record discharges, and a field naming them would
read as a compliance claim.

---

## DoD 5220.22-M — legacy status

Offered, labelled `LEGACY`, and argued against in the interface itself.

`DOD_5220_22_M_3PASS` exists because operators are sometimes contractually
required to name it. NIST SP 800-88r2 states that multi-pass overwrite is not
needed for clear and calls DoD 5220.22-M's pass-count language obsolete
(Appendix D). For SSDs with over-provisioning it says such practices should be
avoided, as very little confidentiality protection is achieved (Sec. 3.1.1).
r2 also records (Sec. 3.1.1, footnote 5) that DoD removed overwriting
specifications from the NISPOM in 2006.

`docs/limitations.md` records that the third pass is a fixed character here and
not random, and why that is not a security-relevant difference.

---

## What this tool does not claim, in one place

* No certification, and no conformance to IEEE 2883-2022 or ISO/IEC 27040:2024.
  Neither text has been read.
* No compliance with any Indian instrument. The tool produces records that
  support specific obligations, named above.
* No "military-grade". No Gutmann. No unrecoverability guarantee on flash.
* **Destroy is never achieved in software** and is never returned.
* No validation: accepting a sanitization outcome is the organisation's decision.
* A signature proves the bytes did not change; it does not prove identity. The
  report carries that caveat and the verification screen prints it.
* Verification above 64 GiB is a detection probability, not a proof of absence.
* A per-file erasure is not a clear, is usually unverifiable, and is reported as
  unverifiable rather than as a pass.
* A free-space wipe is not a clear of the volume. It reads nothing back, and every
  result lists the residue it does not reach. It has run only on loop volumes, never
  on real media.
* An ordinary erase never unlocks an HPA/DCO. A hidden region is not erased
  unless the separate, approved HPA/DCO workflow exposed it first, and the report
  says so. DCO RESTORE is never issued.
* An addressable whole-drive clear is a Clear on every platform, never a Purge.
  Device sanitize and crypto erase are Purge only when the device performs them,
  and no Purge has run on a physical drive here. Windows ATA SECURITY ERASE is not
  implemented; Windows NVMe Format and every macOS firmware command are
  platform-limited.
* ATA enhanced SECURITY ERASE is counted as purge on magnetic media only, on the
  withdrawn r1 Table A-5; r2 does not name it. On flash it is a Clear. Neither
  case has been run on real media.

---

## Sources

Checked on 2026-09-14. "Read" means the text was retrieved and read.

* NIST SP 800-88r2, publication record (authors, date, DOI, supersedes r1):
  <https://csrc.nist.gov/pubs/sp/800/88/r2/final>
* NIST SP 800-88r2, full text (read):
  <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r2.pdf>
* NIST announcement of r2, 26 September 2025:
  <https://www.nist.gov/news-events/news/2025/09/guidelines-media-sanitization-nist-publishes-sp-800-88r2>
* NIST SP 800-88r1, record showing withdrawal on 2025-09-26:
  <https://csrc.nist.gov/pubs/sp/800/88/r1/final>
* NIST SP 800-88r1, full text (read, for the ATA SECURITY ERASE and verification
  comparisons): <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r1.pdf>
* IEEE 2883-2022 record (active; purchase required):
  <https://standards.ieee.org/ieee/2883/10277/>
* ISO/IEC 27040:2024 record: <https://www.iso.org/standard/80194.html> (the page
  refused automated retrieval; edition and replacement of the 2015 edition were
  confirmed from iso.org search results)
* BIS listing of IS/ISO/IEC 27040:2024:
  <https://standardsbis.bsbedge.com/BIS_SearchStandard.aspx?Standard_Number=IS/ISO/IEC+27040&id=51187>
* CERT-In, *Guidelines on Information Security Practices for Government
  Entities*, full text (read): <https://www.cert-in.org.in/PDF/guidelinesgovtentities.pdf>.
  Issue in June 2023 per the PIB release
  <https://www.pib.gov.in/PressReleaseIframePage.aspx?PRID=1936470&reg=48&lang=2>
  (title and date confirmed from search results; the page refused automated
  retrieval)
* Digital Personal Data Protection Act, 2023, Gazette text (read: ss. 8(5),
  8(7), 44(2)): <https://www.meity.gov.in/static/uploads/2024/06/2bf1f0e9f04e6fb4f8fef35e82c42aa5.pdf>
* Digital Personal Data Protection Rules, 2025, G.S.R. 846(E) (read: rules 1, 6,
  8): <https://www.meity.gov.in/static/uploads/2025/11/53450e6e5dc0bfa85ebd78686cadad39.pdf>
* G.S.R. 843(E), commencement of the DPDP Act (read):
  <https://www.meity.gov.in/static/uploads/2025/11/c56ceae6c383460ca69577428d36828b.pdf>
* IT Act 2000, s. 43A: <https://indiankanoon.org/doc/76191164/> (India Code's
  section page, <https://www.indiacode.nic.in/show-data?actid=AC_CEN_45_76_00001_200021_1517807324077&orderno=49>,
  could not be retrieved from this host)
* SPDI Rules 2011, rule 8: <https://indiankanoon.org/doc/19568873/> (India
  Code's copy of G.S.R. 313(E) timed out from this host; this is a secondary
  source)
