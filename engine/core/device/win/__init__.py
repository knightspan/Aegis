"""Windows physical-disk access: raw handles, IOCTLs, ATA and NVMe commands.

Every structure is packed and parsed by pure functions in :mod:`.ioctl`, so the
byte layouts are tested on every host. The only module that calls into
``kernel32`` is :mod:`.native`; everything above it takes a
:class:`~core.device.win.native.NativeApi`, which the test suite replaces with
the adapter double in :mod:`testkit.fake_windows`.

Nothing here decides *whether* to act. Identity binding, the safety policy and
the authorization gates live in :mod:`core.platform.windows` and the helper;
this package only does exactly what it is asked, and reports what the device
answered.
"""
