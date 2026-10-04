package org.sleuthkit.autopsy.aegis.recovery.carve;

import java.util.Arrays;

/** In-memory evidence used by tests and small windows. */
public final class ArrayByteSource implements ByteSource {

    private final byte[] data;

    public ArrayByteSource(byte[] data) {
        this.data = Arrays.copyOf(data, data.length);
    }

    @Override
    public long size() {
        return data.length;
    }

    @Override
    public int read(long offset, byte[] dst, int dstOff, int len) {
        if (offset >= data.length || len <= 0) {
            return -1;
        }
        int start = (int) offset;
        int n = Math.min(len, data.length - start);
        System.arraycopy(data, start, dst, dstOff, n);
        return n;
    }

    @Override
    public void close() {
        // nothing to release
    }
}
