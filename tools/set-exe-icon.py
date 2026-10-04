"""Replaces every icon in a Windows .exe with the icons of one .ico file (Win32 UpdateResource).

    python tools/set-exe-icon.py <exe> <ico>

Used for bin\\aegis64.exe, the NetBeans platform launcher, whose embedded icon is the upstream
one. The executable is otherwise unchanged; run it on a copy, never on a running binary.
"""
from __future__ import annotations

import ctypes
import struct
import sys
from ctypes import wintypes

RT_ICON, RT_GROUP_ICON = 3, 14
LOAD_LIBRARY_AS_DATAFILE = 0x2
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
ENUMRESNAMEPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HMODULE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
ENUMRESLANGPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HMODULE, ctypes.c_void_p, ctypes.c_void_p, wintypes.WORD,
                                     ctypes.c_void_p)
k32.LoadLibraryExW.restype = wintypes.HMODULE
k32.LoadLibraryExW.argtypes = [wintypes.LPCWSTR, wintypes.HANDLE, wintypes.DWORD]
k32.EnumResourceNamesW.argtypes = [wintypes.HMODULE, ctypes.c_void_p, ENUMRESNAMEPROC, ctypes.c_void_p]
k32.EnumResourceLanguagesW.argtypes = [wintypes.HMODULE, ctypes.c_void_p, ctypes.c_void_p, ENUMRESLANGPROC, ctypes.c_void_p]
k32.FreeLibrary.argtypes = [wintypes.HMODULE]
k32.BeginUpdateResourceW.restype = wintypes.HANDLE
k32.BeginUpdateResourceW.argtypes = [wintypes.LPCWSTR, wintypes.BOOL]
k32.UpdateResourceW.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, wintypes.WORD, ctypes.c_void_p, wintypes.DWORD]
k32.EndUpdateResourceW.argtypes = [wintypes.HANDLE, wintypes.BOOL]


def existing(exe: str, rtype: int) -> list[tuple[object, int]]:
    """(name, language) of every resource of one type."""
    module = k32.LoadLibraryExW(exe, None, LOAD_LIBRARY_AS_DATAFILE)
    if not module:
        raise ctypes.WinError(ctypes.get_last_error())
    names: list = []

    def collect(_module, _type, name, _param):
        value = name or 0
        # IS_INTRESOURCE: integer ids are below 0x10000, otherwise a wide string pointer.
        names.append(value if value < 0x10000 else ctypes.wstring_at(value))
        return True

    k32.EnumResourceNamesW(module, ctypes.c_void_p(rtype), ENUMRESNAMEPROC(collect), None)
    found: list[tuple[object, int]] = []
    for name in names:
        def lang_of(_m, _t, _n, language, _p, name=name):
            found.append((name, language))
            return True

        k32.EnumResourceLanguagesW(module, ctypes.c_void_p(rtype), as_res_name(name), ENUMRESLANGPROC(lang_of), None)
    k32.FreeLibrary(module)
    return found


def as_res_name(name):
    return ctypes.c_void_p(name) if isinstance(name, int) else ctypes.c_wchar_p(name)


def main(exe: str, ico: str) -> None:
    data = open(ico, "rb").read()
    reserved, kind, count = struct.unpack_from("<HHH", data, 0)
    if reserved != 0 or kind != 1 or count == 0:
        raise SystemExit(f"{ico} is not an .ico file")
    entries = [struct.unpack_from("<BBBBHHII", data, 6 + 16 * i) for i in range(count)]
    old_groups = existing(exe, RT_GROUP_ICON)
    old_icons = existing(exe, RT_ICON)
    groups = sorted({name for name, _ in old_groups}, key=str) or [1]

    handle = k32.BeginUpdateResourceW(exe, False)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    lang = 0x0409
    for name, language in old_icons:
        k32.UpdateResourceW(handle, ctypes.c_void_p(RT_ICON), as_res_name(name), language, None, 0)
    for name, language in old_groups:
        k32.UpdateResourceW(handle, ctypes.c_void_p(RT_GROUP_ICON), as_res_name(name), language, None, 0)
    group = struct.pack("<HHH", 0, 1, count)
    for index, (w, h, colors, res, planes, bits, size, offset) in enumerate(entries, start=1):
        image = data[offset: offset + size]
        buf = ctypes.create_string_buffer(image, len(image))
        if not k32.UpdateResourceW(handle, ctypes.c_void_p(RT_ICON), ctypes.c_void_p(index), lang, buf, len(image)):
            raise ctypes.WinError(ctypes.get_last_error())
        group += struct.pack("<BBBBHHIH", w, h, colors, res, planes, bits, size, index)
    gbuf = ctypes.create_string_buffer(group, len(group))
    for name in groups:
        if not k32.UpdateResourceW(handle, ctypes.c_void_p(RT_GROUP_ICON), as_res_name(name), lang, gbuf, len(group)):
            raise ctypes.WinError(ctypes.get_last_error())
    if not k32.EndUpdateResourceW(handle, False):
        raise ctypes.WinError(ctypes.get_last_error())
    print(f"{exe}: {count} icon image(s) written to group(s) {groups}; {len(old_icons)} old image(s) removed")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
