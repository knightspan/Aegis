package org.sleuthkit.autopsy.aegis.recovery.carve;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Path;

/** Read-only file or raw image. Opened with mode {@code "r"}. */
public final class FileByteSource implements ByteSource {

    private final RandomAccessFile file;
    private final long size;

    public FileByteSource(Path path) throws IOException {
        this.file = new RandomAccessFile(path.toFile(), "r");
        this.size = file.length();
    }

    @Override
    public long size() {
        return size;
    }

    @Override
    public int read(long offset, byte[] dst, int dstOff, int len) throws IOException {
        if (offset >= size || len <= 0) {
            return -1;
        }
        file.seek(offset);
        return file.read(dst, dstOff, len);
    }

    @Override
    public void close() throws IOException {
        file.close();
    }
}
