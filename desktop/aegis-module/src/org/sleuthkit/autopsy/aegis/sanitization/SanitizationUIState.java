package org.sleuthkit.autopsy.aegis.sanitization;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * Mutable UI state for the sanitization wizard. Presentation listens; the
 * engine never trusts this alone.
 */
public final class SanitizationUIState {

    public enum Step {
        TARGET(0, "Target", "Select data"),
        METHOD(1, "Method", "Choose method"),
        VERIFICATION(2, "Verification", "Set verification"),
        CONFIRMATION(3, "Confirmation", "Review & confirm"),
        EXECUTION(4, "Execution", "Sanitize data"),
        RESULT(5, "Result", "View outcome");

        private final int index;
        private final String title;
        private final String caption;

        Step(int index, String title, String caption) {
            this.index = index;
            this.title = title;
            this.caption = caption;
        }

        public int index() {
            return index;
        }

        public String title() {
            return title;
        }

        public String caption() {
            return caption;
        }

        public static Step fromIndex(int index) {
            for (Step step : values()) {
                if (step.index == index) {
                    return step;
                }
            }
            return TARGET;
        }
    }

    public static final class MethodChoice {
        public final String cli;
        public final String label;
        public final String description;
        public final boolean passesConfigurable;

        public MethodChoice(String cli, String label, String description, boolean passesConfigurable) {
            this.cli = cli;
            this.label = label;
            this.description = description;
            this.passesConfigurable = passesConfigurable;
        }

        @Override
        public String toString() {
            return label;
        }
    }

    private final List<Consumer<SanitizationUIState>> listeners = new CopyOnWriteArrayList<>();
    private Step step = Step.TARGET;
    private TargetType targetType = TargetType.FILE;
    private Path targetPath;
    private DeviceClassification classification;
    private MethodChoice method;
    private int passes = 1;
    private boolean readBackVerification = true;
    private boolean generateHash;
    private boolean confirmed;
    private String caseName = "";
    private String phase = "Idle";
    private double progressPercent;
    private String bytesCompleted = "—";
    private String bytesTotal = "—";
    private String rate = "—";
    private String resultTitle = "";
    private String resultDetail = "";
    private boolean resultSuccess;
    private Path auditPath;
    private Path reportPath;
    private String operationId = "";
    private String startTime = "";
    private String endTime = "";
    private boolean volumeDiskEligible;

    public SanitizationUIState() {
        List<MethodChoice> methods = supportedMethods();
        this.method = methods.get(0);
    }

    public static List<MethodChoice> supportedMethods() {
        List<MethodChoice> methods = new ArrayList<>();
        methods.add(new MethodChoice("zero", "Logical zero overwrite (1 pass)",
                "Overwrites the target with zeros. Suitable for general logical-file sanitization.", false));
        methods.add(new MethodChoice("nist", "Logical zero (NIST label in the engine)",
                "The engine's nist flag is the same logical 0x00 pass. It is not ATA SANITIZE, NVMe Sanitize, or cryptographic erase.", false));
        methods.add(new MethodChoice("dod522022m", "DoD 3-pass legacy (0x00, 0xFF, PRNG)",
                "Commonly circulated 3-pass pattern. Not a current DoD sanitization standard. Final-pass verification is an entropy check, not a byte proof.", false));
        methods.add(new MethodChoice("prng", "PRNG logical passes",
                "Configured PRNG passes plus an optional final 0x00 pass. Entropy is not a cryptographic proof.", true));
        methods.add(new MethodChoice("gutmann", "Gutmann-style 35 shuffled logical writes",
                "Four pseudorandom passes, 27 patterns in shuffled order, then four more. Not Peter Gutmann's published fixed sequence.", false));
        return methods;
    }

    public void addListener(Consumer<SanitizationUIState> listener) {
        listeners.add(Objects.requireNonNull(listener));
    }

    public void removeListener(Consumer<SanitizationUIState> listener) {
        listeners.remove(listener);
    }

    private void fire() {
        for (Consumer<SanitizationUIState> listener : listeners) {
            listener.accept(this);
        }
    }

    public Step step() {
        return step;
    }

    public void setStep(Step step) {
        this.step = Objects.requireNonNull(step);
        fire();
    }

    public TargetType targetType() {
        return targetType;
    }

    public void setTargetType(TargetType targetType) {
        this.targetType = Objects.requireNonNull(targetType);
        fire();
    }

    public Path targetPath() {
        return targetPath;
    }

    public void setTargetPath(Path targetPath) {
        this.targetPath = targetPath;
        fire();
    }

    public DeviceClassification classification() {
        return classification;
    }

    public void setClassification(DeviceClassification classification) {
        this.classification = classification;
        fire();
    }

    public MethodChoice method() {
        return method;
    }

    public void setMethod(MethodChoice method) {
        this.method = method;
        if (method != null && !method.passesConfigurable) {
            this.passes = "dod522022m".equals(method.cli) ? 3 : "gutmann".equals(method.cli) ? 35 : 1;
        }
        fire();
    }

    public int passes() {
        return passes;
    }

    public void setPasses(int passes) {
        this.passes = Math.max(1, Math.min(35, passes));
        fire();
    }

    public boolean readBackVerification() {
        return readBackVerification;
    }

    public void setReadBackVerification(boolean readBackVerification) {
        this.readBackVerification = readBackVerification;
        fire();
    }

    public boolean generateHash() {
        return generateHash;
    }

    public void setGenerateHash(boolean generateHash) {
        // Engine does not implement pre/post hashing yet — keep available in state only when enabled.
        this.generateHash = generateHash;
        fire();
    }

    public boolean hashOptionSupported() {
        return false;
    }

    public boolean confirmed() {
        return confirmed;
    }

    public void setConfirmed(boolean confirmed) {
        this.confirmed = confirmed;
        fire();
    }

    public String caseName() {
        return caseName;
    }

    public void setCaseName(String caseName) {
        this.caseName = caseName == null ? "" : caseName;
        fire();
    }

    public String phase() {
        return phase;
    }

    public void setPhase(String phase) {
        this.phase = phase == null ? "" : phase;
        fire();
    }

    public double progressPercent() {
        return progressPercent;
    }

    public void setProgressPercent(double progressPercent) {
        this.progressPercent = progressPercent;
        fire();
    }

    public String bytesCompleted() {
        return bytesCompleted;
    }

    public String bytesTotal() {
        return bytesTotal;
    }

    public String rate() {
        return rate;
    }

    public void setProgressDetail(String completed, String total, String rate) {
        this.bytesCompleted = completed == null ? "—" : completed;
        this.bytesTotal = total == null ? "—" : total;
        this.rate = rate == null ? "—" : rate;
        fire();
    }

    public String resultTitle() {
        return resultTitle;
    }

    public String resultDetail() {
        return resultDetail;
    }

    public boolean resultSuccess() {
        return resultSuccess;
    }

    public void setResult(boolean success, String title, String detail) {
        this.resultSuccess = success;
        this.resultTitle = title == null ? "" : title;
        this.resultDetail = detail == null ? "" : detail;
        fire();
    }

    public Path auditPath() {
        return auditPath;
    }

    public void setAuditPath(Path auditPath) {
        this.auditPath = auditPath;
        fire();
    }

    public Path reportPath() {
        return reportPath;
    }

    public void setReportPath(Path reportPath) {
        this.reportPath = reportPath;
        fire();
    }

    public String operationId() {
        return operationId;
    }

    public void setOperationId(String operationId) {
        this.operationId = operationId == null ? "" : operationId;
        fire();
    }

    public String startTime() {
        return startTime;
    }

    public String endTime() {
        return endTime;
    }

    public void setTimes(String start, String end) {
        this.startTime = start == null ? "" : start;
        this.endTime = end == null ? "" : end;
        fire();
    }

    public boolean volumeDiskEligible() {
        return volumeDiskEligible;
    }

    public void setVolumeDiskEligible(boolean volumeDiskEligible) {
        this.volumeDiskEligible = volumeDiskEligible;
        fire();
    }

    public boolean canProceedFromTarget() {
        if (targetPath == null || classification == null) {
            return false;
        }
        if (targetType.requiresRemovableMedia()) {
            return volumeDiskEligible
                    && DeviceEligibilityService.ENGINE_SUPPORTS_VOLUME_OR_DISK
                    && classification.eligibility().isAllowed();
        }
        return classification.eligibility() == DeviceEligibility.SUPPORTED;
    }

    public String verificationSummary() {
        if (readBackVerification) {
            return "Read-back verification";
        }
        return "None";
    }

    public String targetDisplayName() {
        if (targetPath == null) {
            return "—";
        }
        Path name = targetPath.getFileName();
        return name == null ? targetPath.toString() : name.toString();
    }

    public void resetWorkflow() {
        step = Step.TARGET;
        confirmed = false;
        phase = "Idle";
        progressPercent = 0;
        bytesCompleted = "—";
        bytesTotal = "—";
        rate = "—";
        resultTitle = "";
        resultDetail = "";
        resultSuccess = false;
        auditPath = null;
        reportPath = null;
        operationId = "";
        startTime = "";
        endTime = "";
        fire();
    }
}
