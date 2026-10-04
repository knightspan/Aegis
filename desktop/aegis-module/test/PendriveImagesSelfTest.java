import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.sleuthkit.autopsy.aegis.engine.EngineBridge;
import org.sleuthkit.autopsy.aegis.engine.EngineResult;
import org.sleuthkit.autopsy.aegis.util.AegisJson.AegisJsonObject;

/**
 * Real-media test over existing pendrive images supplied by the operator.
 * Every image is only read: it is acquired to a verified copy elsewhere, recovered
 * from directly (read-only), and its size and modification time are checked unchanged
 * at the end. No device is opened.
 *
 * Run: java -Daegis.engine.home=... -cp ... PendriveImagesSelfTest <work dir> <image> [<image> ...]
 * Options (system properties): -Dpendrive.writeLimitBytes=N  images larger than N are
 * recovered in list-only mode (no recovered copies written); -Dpendrive.deleteCopies=true
 * removes the acquired copies after they verified.
 */
public final class PendriveImagesSelfTest {

    private static int passed;
    private static final List<String> failures = new ArrayList<>();

    public static void main(String[] args) throws Exception {
        Path work = Path.of(args[0]);
        Files.createDirectories(work);
        long writeLimit = Long.getLong("pendrive.writeLimitBytes", 12L * 1024 * 1024 * 1024);
        boolean deleteCopies = Boolean.getBoolean("pendrive.deleteCopies");
        Path state = work.resolve("state");
        EngineBridge bridge = EngineBridge.get();
        for (int i = 1; i < args.length; i++) {
            Path image = Path.of(args[i]);
            String tag = image.getFileName().toString();
            long size = Files.size(image);
            var mtime = Files.getLastModifiedTime(image);
            System.out.println("=== " + image + " (" + size + " bytes)");

            // 1. Acquire the image file to a verified E01 copy (SHA-256 + BLAKE3 in one pass).
            Path dest = work.resolve(tag.replaceAll("[^A-Za-z0-9._-]", "_") + ".copy.E01");
            Files.deleteIfExists(dest);
            AtomicInteger progress = new AtomicInteger();
            long t0 = System.nanoTime();
            EngineResult a = bridge.run("acquire", List.of("--case-id", "PENDRIVE-TEST", "--source", image.toString(),
                    "--dest", dest.toString(), "--format", "e01", "--evidence-number", tag), state, p -> progress.incrementAndGet(), null, 0);
            double secs = (System.nanoTime() - t0) / 1e9;
            AegisJsonObject rec = a.result.object("record");
            check(tag + ": acquisition to E01 succeeds", a.succeeded(), a.summary());
            check(tag + ": read-back verification passed (SHA-256 + BLAKE3 + chunks)", a.result.object("verification").optBoolean("passed", false),
                    a.result.object("verification").toString());
            check(tag + ": bytes read equals source size", rec.optLong("bytes_read", -1) == size, rec.optLong("bytes_read", -1) + " vs " + size);
            check(tag + ": no unreadable sectors in an image file", a.result.optLong("bad_sector_count", -1) == 0, "" + a.result.optLong("bad_sector_count", -1));
            System.out.printf("    sha256=%s blake3=%s  %.0f s  %.1f MB/s  progress events=%d%n", rec.optString("sha256"),
                    rec.optString("blake3"), secs, size / 1e6 / secs, progress.get());
            if (a.succeeded()) {
                EngineResult rep = bridge.run("report", List.of("--case-id", "PENDRIVE-TEST", "--job-id", a.operationId), state, null, null, 600);
                check(tag + ": signed acquisition report", rep.succeeded(), rep.summary());
                EngineResult ver = bridge.run("verify-report", List.of("--report", rep.result.optString("json")), state, null, null, 600);
                check(tag + ": acquisition report verifies", ver.succeeded(), ver.summary());
                if (deleteCopies) {
                    // libewf splits large images into .E01, .E02, ... segments.
                    String base = dest.getFileName().toString().replaceAll("\\.E01$", "");
                    try (var segs = Files.newDirectoryStream(dest.getParent(), base + ".E[0-9][0-9]")) {
                        for (Path seg : segs) {
                            Files.deleteIfExists(seg);
                        }
                    }
                }
            }

            // 2. Recover directly from the original image (read-only evidence path).
            List<String> rargs = new ArrayList<>(List.of("--case-id", "PENDRIVE-TEST", "--image", image.toString()));
            boolean listOnly = size > writeLimit;
            if (listOnly) {
                rargs.add("--no-write");
            }
            t0 = System.nanoTime();
            EngineResult r = bridge.run("recover", rargs, state, null, null, 0);
            secs = (System.nanoTime() - t0) / 1e9;
            check(tag + ": recovery succeeds", r.succeeded(), r.summary());
            AegisJsonObject full = r.fullResult();
            Map<String, Integer> bySource = new LinkedHashMap<>();
            Map<String, Integer> byBucket = new LinkedHashMap<>();
            Map<String, Integer> byExt = new LinkedHashMap<>();
            int frags = 0;
            int checkedCopies = 0;
            int badCopies = 0;
            for (AegisJsonObject c : full.array("candidates").objects()) {
                bySource.merge(c.optString("source"), 1, Integer::sum);
                byBucket.merge(c.optString("bucket"), 1, Integer::sum);
                byExt.merge(c.optString("ext"), 1, Integer::sum);
                frags += c.array("fragments").length() > 0 ? 1 : 0;
                String out = c.optString("output_path");
                if (!out.isBlank() && checkedCopies < 300) {
                    checkedCopies++;
                    byte[] bytes = Files.readAllBytes(Path.of(out));
                    String h = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
                    if (!h.equals(c.optString("sha256"))) {
                        badCopies++;
                    }
                }
            }
            int total = full.array("candidates").length();
            System.out.printf("    recovery: %d candidates in %.0f s; by source %s; by score %s; reassembled %d; types %s%n",
                    total, secs, bySource, byBucket, frags, byExt);
            check(tag + ": recovery found candidates", total > 0, "candidates=" + total);
            check(tag + ": media map produced", full.optJSONObject("media_map") != null, "");
            check(tag + ": filesystem recognised by the undelete pass", full.array("partitions").objects().stream()
                    .anyMatch(p -> !p.optString("fs_type").isBlank()), full.array("partitions").toString());
            if (!listOnly) {
                check(tag + ": recovered copies match their SHA-256 (" + checkedCopies + " checked)", checkedCopies > 0 && badCopies == 0,
                        "bad=" + badCopies);
            }
            if (r.succeeded()) {
                EngineResult rep = bridge.run("report", List.of("--case-id", "PENDRIVE-TEST", "--job-id", r.operationId), state, null, null, 900);
                check(tag + ": signed recovery report", rep.succeeded(), rep.summary());
                EngineResult ver = bridge.run("verify-report", List.of("--report", rep.result.optString("json")), state, null, null, 900);
                check(tag + ": recovery report verifies", ver.succeeded(), ver.summary());
            }

            // 3. The original evidence was only read.
            check(tag + ": original size unchanged", Files.size(image) == size, "");
            check(tag + ": original modification time unchanged", Files.getLastModifiedTime(image).equals(mtime), "");
        }
        EngineResult lv = bridge.run("ledger-verify", List.of(), state, null, null, 600);
        check("ledger chain VALID after all operations", lv.succeeded() && "VALID".equals(lv.result.optString("status")),
                lv.summary() + " " + lv.result.optString("explanation"));
        System.out.println("PendriveImagesSelfTest: " + passed + " passed, " + failures.size() + " failed");
        failures.forEach(f -> System.out.println("  FAIL " + f));
        if (!failures.isEmpty()) {
            System.exit(1);
        }
    }

    private static void check(String name, boolean ok, String detail) {
        if (ok) {
            passed++;
            System.out.println("PASS " + name);
        } else {
            failures.add(name + " :: " + detail);
            System.out.println("FAIL " + name + " :: " + detail);
        }
    }
}
