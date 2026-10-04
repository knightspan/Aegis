import org.sleuthkit.autopsy.aegis.SanitizerProtocol;

/**
 * Standalone checks for the sanitizer event parser. Compiled against the module source, not the suite.
 */
public final class ProtocolSelfTest {
    public static void main(String[] args) {
        int failures = 0;
        failures += expect(SanitizerProtocol.parse("banner").getKind() == SanitizerProtocol.Kind.IGNORED, "banner ignored");
        SanitizerProtocol progress = SanitizerProtocol.parse(
                "AEGIS_EVENT {\"type\":\"progress\",\"target\":\"C:\\\\Test Data\\\\File.txt\",\"percentage\":12.5,\"status\":\"RUNNING\"}");
        failures += expect(progress.getKind() == SanitizerProtocol.Kind.PROGRESS, "progress kind");
        failures += expect("C:\\Test Data\\File.txt".equals(progress.get("target")), "windows path unescaped");
        failures += expect("12.5".equals(progress.get("percentage")), "percentage kept");
        SanitizerProtocol result = SanitizerProtocol.parse(
                "AEGIS_EVENT {\"type\":\"result\",\"status\":\"FAILED_VERIFICATION\",\"message\":\"quote \\\"here\\\"\"}");
        failures += expect("FAILED_VERIFICATION".equals(result.get("status")), "failure status");
        failures += expect(result.get("message").contains("quote"), "message text");
        failures += expect(!SanitizerProtocol.acceptExit(0, "FAILED"), "zero exit is not success for a failed status");
        failures += expect(!SanitizerProtocol.acceptExit(1, "SUCCESS"), "non-zero exit is not success");
        failures += expect(SanitizerProtocol.acceptExit(0, "SUCCESS_WITH_WARNINGS"), "warnings with exit 0 are accepted");
        failures += expect(!SanitizerProtocol.acceptExit(0, "CANCELLED"), "cancel is not success");
        failures += expect(!SanitizerProtocol.acceptExit(0, "UNSUPPORTED"), "unsupported is not success");
        if (failures != 0) {
            System.err.println(failures + " protocol test(s) failed");
            System.exit(1);
        }
        System.out.println("protocol tests passed");
    }

    private static int expect(boolean condition, String message) {
        if (!condition) {
            System.err.println("FAIL: " + message);
            return 1;
        }
        System.out.println("PASS: " + message);
        return 0;
    }
}
