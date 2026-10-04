"""Frozen entry point for every packaged build.

    Sanctum                 open the app (API on a private loopback port + window)
    Sanctum helper ...      Linux only: run the privileged helper daemon, e.g.
                            sudo ./Sanctum.AppImage helper --operator-uid 1000 \\
                                --state-dir /var/lib/sanctum

``multiprocessing.freeze_support()`` must run before anything else in a frozen
Windows build: the file eraser uses a process pool under spawn, and without it
each worker would start another copy of the app.
"""

import multiprocessing
import sys

if __name__ == "__main__":
    multiprocessing.freeze_support()
    if len(sys.argv) > 1 and sys.argv[1] == "helper":
        from helper.__main__ import main as helper_main

        raise SystemExit(helper_main(sys.argv[2:]))
    from api.desktop import main

    raise SystemExit(main())
