"""Platform adapters: one sanitization service, one adapter per OS.

::

    UI -> API -> helper (privilege boundary) -> PlatformAdapter
                                                  |- LinuxAdapter
                                                  |- WindowsAdapter
                                                  `- MacOSAdapter

* Linux: lsblk/sysfs discovery, hdparm/nvme/sedutil probes, the validated
  whole-drive engine (Clear and firmware Purge), file erase, free space.
* Windows: Storage-module discovery and safety facts, file erase with the
  NTFS-aware backend; no whole-drive engine, and it says so.
* macOS: diskutil discovery with APFS-aware protection, file erase; no
  whole-drive engine, and it says so.

The adapter is selected from ``sys.platform`` exactly once per process, but
nothing it reports is inferred from the platform name: every capability row
names the probe or code path that established it. See :mod:`core.platform.base`.
"""

from __future__ import annotations

from core.platform.base import BaseAdapter, PlatformAdapter
from core.platform.host import family
from core.platform.model import PlatformFamily, PlatformStatus

__all__ = [
    "BaseAdapter",
    "PlatformAdapter",
    "adapter_for",
    "current_adapter",
    "platform_status",
]


def adapter_for(
    platform_family: PlatformFamily,
    *,
    helper: str = "in-process",
    helper_basis: str = "",
) -> BaseAdapter:
    """A fresh adapter for ``platform_family``.

    Only :func:`current_adapter` should be used to *act*; this exists so the
    adapter table can be exercised on any host from fixtures.
    """
    if platform_family == "linux":
        from core.platform.linux import LinuxAdapter

        return LinuxAdapter(helper=helper, helper_basis=helper_basis)
    if platform_family == "windows":
        from core.platform.windows import WindowsAdapter

        return WindowsAdapter(helper=helper, helper_basis=helper_basis)
    if platform_family == "macos":
        from core.platform.macos import MacOSAdapter

        return MacOSAdapter(helper=helper, helper_basis=helper_basis)
    return BaseAdapter(helper=helper, helper_basis=helper_basis)


def current_adapter(
    *, helper: str = "in-process", helper_basis: str = ""
) -> BaseAdapter:
    """The adapter for the OS this process runs on."""
    return adapter_for(family(), helper=helper, helper_basis=helper_basis)


def platform_status(adapter: BaseAdapter) -> PlatformStatus:
    """The ``/platform`` answer, computed now from ``adapter``'s probes."""
    from core.platform.filesystems import registry

    operations = adapter.operation_capabilities()
    privilege = adapter.privilege_state()
    return PlatformStatus(
        platform=adapter.platform_info(),
        privilege=privilege,
        operations=operations,
        media_classes=adapter.media_classes(),
        filesystems=registry(),
        restrictions=adapter.restrictions(),
        adapter=adapter.name,
        capabilities=adapter.platform_capabilities(privilege),
    )
