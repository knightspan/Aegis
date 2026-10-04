package org.sleuthkit.autopsy.aegis.recovery.carve;

import java.io.IOException;

/** Read-only random access over evidence bytes. Implementations must not write the source. */
public interface ByteSource extends AutoCloseable {

    long size() throws IOException;

    /**
     * Reads up to {@code len} bytes at {@code offset} into {@code dst}.
     * Returns the count read, or -1 at EOF.
     */
    int read(long offset, byte[] dst, int dstOff, int len) throws IOException;

    @Override
    void close() throws IOException;
}
