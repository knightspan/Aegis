package org.sleuthkit.autopsy.aegis.recovery;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;
import org.sleuthkit.autopsy.aegis.audit.AuditLedgerService;
import org.sleuthkit.autopsy.aegis.evidence.EvidenceHandle;
import org.sleuthkit.autopsy.aegis.recovery.carve.ArrayByteSource;
import org.sleuthkit.autopsy.aegis.recovery.carve.ByteSource;
import org.sleuthkit.autopsy.aegis.recovery.carve.CarveCandidate;
import org.sleuthkit.autopsy.aegis.recovery.carve.CarveReport;
import org.sleuthkit.autopsy.aegis.recovery.carve.CarvingEngine;
import org.sleuthkit.autopsy.aegis.recovery.carve.FileByteSource;

/**
 * Filesystem-aware recovery stays in Sleuth Kit. This service runs the AEGIS
 * structure-validated carver over a read-only evidence file or image.
 */
public final class RecoveryService {

    private final AuditLedgerService ledger;
    private final CarvingEngine engine = new CarvingEngine();

    public RecoveryService(AuditLedgerService ledger) {
        this.ledger = Objects.requireNonNull(ledger);
    }

    public List<CarvingEngine.FormatRow> formatMatrix() {
        return engine.formatMatrix();
    }

    public CarveReport carve(EvidenceHandle evidence, long maxBytes, Consumer<CarvingEngine.Progress> progress) throws IOException {
        if (evidence == null || evidence.path().isEmpty()) {
            throw new IOException("Evidence path is required.");
        }
        if (!evidence.readOnlySource()) {
            throw new IOException("Recovery refused a handle that is not marked read-only.");
        }
        Path path = evidence.path().get();
        try (ByteSource source = new FileByteSource(path)) {
            CarveReport report = engine.scan(source, maxBytes, progress);
            ledger.append(evidence.caseId().orElse(""), "recovery.carve",
                    path + " accepted=" + report.accepted + " reassembled=" + report.reassembled
                            + " rejected=" + report.rejected + " bytes=" + report.bytesScanned);
            return report;
        }
    }

    public CarveReport carveBytes(byte[] data, Consumer<CarvingEngine.Progress> progress) throws IOException {
        try (ByteSource source = new ArrayByteSource(data)) {
            return engine.scan(source, data.length, progress);
        }
    }

    public int export(CarveReport report, ByteSource source, Path outputDir) throws IOException {
        Files.createDirectories(outputDir);
        int written = 0;
        for (CarveCandidate candidate : report.candidates) {
            if (candidate.disposition != CarveCandidate.Disposition.ACCEPTED
                    && candidate.disposition != CarveCandidate.Disposition.REASSEMBLED) {
                continue;
            }
            if (candidate.length <= 0 && (candidate.derivative == null || candidate.derivative.length == 0)) {
                continue;
            }
            String prefix = candidate.disposition == CarveCandidate.Disposition.REASSEMBLED ? "hypothesis-" : "";
            Path out = outputDir.resolve(prefix + candidate.offset + "-" + candidate.format + "." + candidate.extension);
            if (candidate.derivative != null && candidate.derivative.length > 0) {
                Files.write(out, candidate.derivative);
            } else {
                byte[] bytes = CarvingEngine.readUpTo(source, candidate.offset, (int) Math.min(candidate.length, Integer.MAX_VALUE));
                if (bytes.length == 0) {
                    continue;
                }
                Files.write(out, bytes);
                if (candidate.sha256 == null || candidate.sha256.isBlank()) {
                    candidate.sha256 = CarvingEngine.sha256(bytes);
                }
            }
            written++;
        }
        return written;
    }
}
