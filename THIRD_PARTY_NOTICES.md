# Third-party notices

AEGIS is proprietary software: Copyright (c) 2026 knightspan. All rights reserved. AEGIS is built
on, and distributed together with, the third-party components listed below. Each remains under its
own licence. Nothing in the AEGIS licence restricts the rights those licences grant, and these
notices must accompany every copy of AEGIS.

## Desktop platform

| Component | Licence | Notes |
|---|---|---|
| Autopsy 4.23.1 (Basis Technology and contributors) | Apache License 2.0 | AEGIS's desktop is built on a modified Autopsy 4.23.1. Licence text: `third-party/autopsy/LICENSE-2.0.txt` in the package; https://www.apache.org/licenses/LICENSE-2.0. Modified files carry their original copyright headers. "Autopsy" is a name of Basis Technology; AEGIS is not affiliated with or endorsed by Basis Technology. |
| The Sleuth Kit 4.15.0 | IBM Public License 1.0, Common Public License 1.0, and others (https://sleuthkit.org/sleuthkit/licenses.php) | Filesystem and image access through its JNI bindings. |
| Apache NetBeans Platform | Apache License 2.0 | Application platform. |
| Java runtime (Microsoft Build of OpenJDK 17.0.20.1) | GPL-2.0 with Classpath Exception | `jre/` with its own `legal/` notices. |
| Libraries bundled with Autopsy | As listed by Autopsy: Apache Solr/Lucene/Tika (Apache-2.0), GStreamer and gst1-java-core (LGPL), Jericho HTML (LGPL), Metadata Extractor (Apache-2.0), Reflections (WTFPL), Sigar, 7-Zip-JBinding (LGPL), ImgScalr (Apache-2.0), ControlsFX (BSD-3-Clause), JFXtras, Mustache.java (Apache-2.0), Joda-Time (Apache-2.0), TwelveMonkeys ImageIO (BSD-3-Clause), RegRipper and Pasco2 (GPL, separate executables) | Upstream list: Autopsy `README.txt` (packaged under `third-party/autopsy/`). |
| Icons from Autopsy | FAMFAMFAM Silk 1.3, Fugue 3.5.6, WebHostingHub Glyphs (CC BY 3.0); Splashy icons | Attribution as required by CC BY 3.0. |
| Tabler Icons | MIT | AEGIS interface icons. |

## AEGIS engine runtime

| Component | Licence | Notes |
|---|---|---|
| CPython 3.11.15 (python-build-standalone) | PSF License | `aegis-engine/runtime/python311/LICENSE.txt` |
| libewf 20130416 (E01 writing) | LGPL-3.0 | Dynamically loaded. `aegis-engine/runtime/libewf/LICENSE.libewf.txt`; zlib licence for `zlib.dll`. |
| libewf-python / pyewf 20240506 (E01 reading) | LGPL-3.0 | Unmodified wheel. |
| pytsk3 | Apache-2.0 | |
| blake3, pyahocorasick, construct, pydantic, cryptography, reportlab, Pillow, olefile, piexif, mutagen, structlog, typer, PyYAML | MIT / BSD / Apache-2.0 / PSF, per package | Pinned versions in the engine's `pyproject.toml`. |
| pikepdf | MPL-2.0 | |
| opencv-contrib-python-headless 4.12.0.88, numpy 2.2.6 | Apache-2.0, BSD-3-Clause | AI enhancement only. |
| EDSR super-resolution models (`EDSR_x2/x3/x4.pb`, repository Saafke/EDSR_Tensorflow) | Apache-2.0 | SHA-256 pinned in `docs/INTEGRATION_PROVENANCE.md`; recorded in every enhancement ledger entry. |

Source for the LGPL components is available from their upstream projects; AEGIS loads them as
separate dynamic libraries and they can be replaced by the user.
