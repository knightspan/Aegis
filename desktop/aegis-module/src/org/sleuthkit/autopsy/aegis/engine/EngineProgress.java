package org.sleuthkit.autopsy.aegis.engine;

/** One PROGRESS event from the engine. Values are the engine's; nothing is interpolated. */
public final class EngineProgress {

    public final String phase;
    public final double pct;
    public final long bytesDone;
    public final long bytesTotal;
    public final long throughput;
    public final long etaSeconds;
    public final String message;

    public EngineProgress(String phase, double pct, long bytesDone, long bytesTotal, long throughput,
            long etaSeconds, String message) {
        this.phase = phase == null ? "" : phase;
        this.pct = pct;
        this.bytesDone = bytesDone;
        this.bytesTotal = bytesTotal;
        this.throughput = throughput;
        this.etaSeconds = etaSeconds;
        this.message = message == null ? "" : message;
    }

    /** Listener for streamed engine events. Called on the bridge reader thread, never the EDT. */
    public interface Listener {

        void progress(EngineProgress progress);

        default void log(String level, String message) {
        }
    }
}
