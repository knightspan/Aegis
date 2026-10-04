import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.sleuthkit.autopsy.aegis.engine.EngineBridge;
import org.sleuthkit.autopsy.aegis.engine.EngineResult;
import org.sleuthkit.autopsy.aegis.util.AegisJson.AegisJsonObject;

/**
 * Java -> engine integration test through the real {@link EngineBridge} process
 * protocol. Uses only disposable fixtures and the demo evidence image; no device
 * is ever written. Device commands are exercised only against the system disk,
 * where the expected and asserted outcome is a refusal before any open.
 *
 * Run: java -Daegis.engine.home=<engine home> -cp <classes>;<test-out> EngineBridgeSelfTest <demo image> <work dir>
 */
public final class EngineBridgeSelfTest {

    private static int passed;
    private static final List<String> failures = new ArrayList<>();

    public static void main(String[] args) throws Exception {
        Path demo = Path.of(args[0]);
        Path work = Path.of(args[1]);
        Files.createDirectories(work);
        Path state = Files.createTempDirectory(work, "state-");
        EngineBridge bridge = EngineBridge.get();

        EngineResult h = bridge.run("health", List.of(), state, null, null, 120);
        check("health succeeds", h.succeeded(), h.summary());
        check("E01 writer available", h.result.object("e01_write").optBoolean("supported", false), h.result.toString());
        check("BLAKE3 offered", h.result.optStringList("hashes").contains("BLAKE3"), "");

        // RAW and E01 acquisition of a fixture; SHA-256 must equal Java's own digest.
        byte[] fixture = new byte[3 * 1024 * 1024 + 1024];
        for (int i = 0; i < fixture.length; i++) {
            fixture[i] = (byte) (i * 131 + (i >> 9));
        }
        Path src = work.resolve("fixture.bin");
        Files.write(src, fixture);
        String sha = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(fixture));
        for (String fmt : new String[]{"raw", "e01"}) {
            Path dest = work.resolve("img-" + fmt + (fmt.equals("e01") ? ".E01" : ".raw"));
            Files.deleteIfExists(dest);
            AtomicInteger progress = new AtomicInteger();
            EngineResult a = bridge.run("acquire", List.of("--case-id", "SELFTEST", "--source", src.toString(), "--dest",
                    dest.toString(), "--format", fmt), state, p -> progress.incrementAndGet(), null, 600);
            AegisJsonObject rec = a.result.object("record");
            check(fmt + " acquisition succeeds", a.succeeded(), a.summary());
            check(fmt + " SHA-256 equals independent digest", sha.equals(rec.optString("sha256")), rec.optString("sha256"));
            check(fmt + " BLAKE3 present (64 hex)", rec.optString("blake3").matches("[0-9a-f]{64}"), rec.optString("blake3"));
            check(fmt + " read-back verification passed", a.result.object("verification").optBoolean("passed", false), "");
            check(fmt + " progress streamed", progress.get() > 0, "events=" + progress.get());
            check(fmt + " job id is the operation id", a.operationId.startsWith("acquire-"), a.operationId);
            if (fmt.equals("e01")) {
                check("E01 container written", Files.isRegularFile(dest) && Files.size(dest) > 0, dest.toString());
                EngineResult rep = bridge.run("report", List.of("--case-id", "SELFTEST", "--job-id", a.operationId), state, null, null, 300);
                check("signed acquisition report", rep.succeeded(), rep.summary());
                Path json = Path.of(rep.result.optString("json"));
                EngineResult ver = bridge.run("verify-report", List.of("--report", json.toString()), state, null, null, 300);
                check("acquisition report verifies", ver.succeeded(), ver.summary() + " " + ver.result.optString("verdict"));
                Path tampered = work.resolve("tampered.forensic.json");
                Files.writeString(tampered, Files.readString(json, StandardCharsets.UTF_8).replace("\"bytes_read\":" + fixture.length,
                        "\"bytes_read\":" + (fixture.length + 1)), StandardCharsets.UTF_8);
                EngineResult bad = bridge.run("verify-report", List.of("--report", tampered.toString()), state, null, null, 300);
                check("tampered report rejected", !bad.succeeded() && "FAILED_VERIFICATION".equals(bad.result.optString("verdict")),
                        bad.summary());
            }
        }

        // E01 needs whole sectors: an odd-sized source is refused up front, RAW keeps every byte.
        Path odd = work.resolve("odd.bin");
        Files.write(odd, java.util.Arrays.copyOf(fixture, fixture.length + 77));
        EngineResult oddE01 = bridge.run("acquire", List.of("--source", odd.toString(), "--dest", work.resolve("odd.E01").toString(),
                "--format", "e01"), state, null, null, 300);
        check("odd-sized E01 BLOCKED (E01NeedsWholeSectors)", oddE01.blocked() && "E01NeedsWholeSectors".equals(oddE01.errorType),
                oddE01.summary());
        EngineResult oddRaw = bridge.run("acquire", List.of("--source", odd.toString(), "--dest", work.resolve("odd.raw").toString(),
                "--format", "raw"), state, null, null, 300);
        check("odd-sized RAW acquisition verifies", oddRaw.succeeded()
                && oddRaw.result.object("verification").optBoolean("passed", false), oddRaw.summary());

        // Recovery over the demo image: undelete + carving + bifragment reassembly + decoy rejection.
        EngineResult r = bridge.run("recover", List.of("--case-id", "SELFTEST", "--image", demo.toString()), state, null, null, 1200);
        check("recovery succeeds", r.succeeded(), r.summary());
        AegisJsonObject full = r.fullResult();
        int fs = 0;
        int frag = 0;
        int lowCorrupt = 0;
        for (AegisJsonObject c : full.array("candidates").objects()) {
            fs += "fs_metadata".equals(c.optString("source")) ? 1 : 0;
            frag += c.array("fragments").length() == 2 && "valid".equals(c.optString("validation")) ? 1 : 0;
            lowCorrupt += "LOW".equals(c.optString("bucket")) && "corrupt".equals(c.optString("validation")) ? 1 : 0;
            if (!c.optString("output_path").isBlank()) {
                byte[] out = Files.readAllBytes(Path.of(c.optString("output_path")));
                String h2 = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(out));
                check("recovered copy hash matches candidate " + c.optLong("offset", 0), h2.equals(c.optString("sha256")), h2);
            }
        }
        check("filesystem undelete found the 3 deleted files", fs == 3, "fs_metadata=" + fs);
        check("two bifragment reassemblies validated", frag == 2, "fragments=" + frag);
        check("decoys rejected as LOW/corrupt", lowCorrupt >= 2, "low_corrupt=" + lowCorrupt);
        check("media map present", full.optJSONObject("media_map") != null && full.object("media_map").array("regions").length() > 0, "");

        // Safety. Operator directive: no command may target an internal drive, not even
        // one that is expected to be refused. Internal disks are checked read-only here
        // (enumeration verdict); refusals are exercised against a disk number that does
        // not exist, and the policy itself is unit-tested on simulated devices
        // (tests/aegis/test_internal_drive_policy.py).
        EngineResult devs = bridge.run("devices", List.of(), state, null, null, 180);
        check("device enumeration succeeds (read-only)", devs.succeeded(), devs.summary());
        for (AegisJsonObject d : devs.result.array("devices").objects()) {
            String bus = d.optString("bus_type").toLowerCase(java.util.Locale.ROOT);
            boolean removable = bus.equals("usb") || bus.equals("sd") || bus.equals("mmc");
            check("policy verdict: " + d.optString("id") + " (" + bus + ") eligible only if removable USB/SD",
                    d.object("sanitization").optBoolean("eligible", true) == (removable && !d.optBoolean("system_device", false)),
                    d.object("sanitization").toString());
            if (d.optBoolean("system_device", false)) {
                check("policy verdict: system disk acquisition not offered", !d.object("acquisition").optBoolean("eligible", true),
                        d.object("acquisition").toString());
            }
        }
        String ghost = "PhysicalDrive97";
        EngineResult vanished = bridge.run("sanitize-device", List.of("--device", ghost, "--typed-serial", "X",
                "--waive-backup", "NO BACKUP", "--confirm-destructive"), state, null, null, 180);
        check("absent device BLOCKED (DeviceVanished)", vanished.blocked() && "DeviceVanished".equals(vanished.errorType), vanished.summary());
        EngineResult noConfirm = bridge.run("sanitize-device", List.of("--device", ghost, "--typed-serial", "X"),
                state, null, null, 180);
        check("missing destructive confirmation BLOCKED", noConfirm.blocked() && "ConfirmationMissing".equals(noConfirm.errorType),
                noConfirm.summary());
        EngineResult devPath = bridge.run("recover", List.of("--image", "\\\\.\\" + ghost), state, null, null, 180);
        check("recovery refuses any live device path", devPath.blocked() && "EvidenceOnly".equals(devPath.errorType), devPath.summary());
        EngineResult forged = bridge.run("record", List.of("--operation", "acquire.complete"), state, null, null, 60);
        check("forged engine ledger operation BLOCKED", forged.blocked(), forged.summary());

        // Ledger: intact, then tamper detected on a copy.
        EngineResult lv = bridge.run("ledger-verify", List.of(), state, null, null, 300);
        check("ledger chain VALID", lv.succeeded() && "VALID".equals(lv.result.optString("status")), lv.summary());
        Path copy = Files.createTempDirectory(work, "tamper-");
        copyTree(state, copy);
        Path chain = copy.resolve("ledger").resolve("ledger").resolve("chain.jsonl");
        List<String> lines = new ArrayList<>(Files.readAllLines(chain, StandardCharsets.UTF_8));
        lines.set(2, lines.get(2).replaceFirst("\"actor\":\"[^\"]*\"", "\"actor\":\"mallory\""));
        Files.write(chain, lines, StandardCharsets.UTF_8);
        EngineResult tv = bridge.run("ledger-verify", List.of(), copy, null, null, 300);
        check("tampered ledger detected", !tv.succeeded() && "BROKEN".equals(tv.result.optString("status")), tv.summary());

        // Cancellation: a scan cancelled immediately reports CANCELLED, never success.
        EngineBridge.Cancel cancel = new EngineBridge.Cancel();
        cancel.request();
        EngineResult c = bridge.run("recover", List.of("--image", demo.toString()), state, null, cancel, 600);
        check("cancelled scan reports CANCELLED", c.cancelled(), c.summary());

        System.out.println("EngineBridgeSelfTest: " + passed + " passed, " + failures.size() + " failed");
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

    private static void copyTree(Path from, Path to) throws Exception {
        try (var walk = Files.walk(from)) {
            for (Path p : (Iterable<Path>) walk::iterator) {
                Path t = to.resolve(from.relativize(p).toString());
                if (Files.isDirectory(p)) {
                    Files.createDirectories(t);
                } else {
                    Files.copy(p, t, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                }
            }
        }
    }
}
