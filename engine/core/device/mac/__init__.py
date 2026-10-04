"""macOS raw-disk access through ``/dev/rdiskN``.

The raw character device is used rather than ``/dev/diskN``: the block device
goes through the buffer cache, and a read from it may be answered from memory
rather than the medium. The raw device requires every offset and length to be
a multiple of the device block size, which :mod:`.rawdisk` enforces before
the kernel sees the request.
"""
