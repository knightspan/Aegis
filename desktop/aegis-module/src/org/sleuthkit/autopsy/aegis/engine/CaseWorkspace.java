package org.sleuthkit.autopsy.aegis.engine;

import java.nio.file.Files;
import java.nio.file.Path;
import org.sleuthkit.autopsy.casemodule.Case;

/**
 * The per-case AEGIS workspace: {@code <case directory>/AEGIS}. It holds the
 * case's hash-chained ledger, engine job records, signed reports, recovered
 * objects and enhanced derivatives, so every AEGIS result stays inside the case.
 * Without an open case the engine uses a per-user state directory, and the UI
 * says so.
 */
public final class CaseWorkspace {

    private CaseWorkspace() {
    }

    public static boolean caseOpen() {
        return Case.isCaseOpen();
    }

    public static Path stateDir() {
        if (Case.isCaseOpen()) {
            try {
                Path dir = Path.of(Case.getCurrentCaseThrows().getCaseDirectory(), "AEGIS");
                Files.createDirectories(dir);
                return dir;
            } catch (Exception ignored) {
                // fall through to the per-user state directory
            }
        }
        String local = System.getenv("LOCALAPPDATA");
        Path base = local != null ? Path.of(local) : Path.of(System.getProperty("user.home", "."));
        return base.resolve("AEGIS").resolve("engine-state");
    }

    /** Default folder for acquired images: the case's AEGIS evidence folder. */
    public static Path evidenceDir() {
        Path dir = stateDir().resolve("evidence");
        try {
            Files.createDirectories(dir);
        } catch (Exception ignored) {
            // the caller validates the destination before use
        }
        return dir;
    }

    /** The case identifier recorded in ledger entries and reports: the case number if set, else the name. */
    public static String caseId() {
        if (!Case.isCaseOpen()) {
            return "";
        }
        try {
            Case c = Case.getCurrentCaseThrows();
            String number = c.getNumber();
            return number != null && !number.isBlank() ? number.trim() : c.getName();
        } catch (Exception ex) {
            return "";
        }
    }

    public static String caseDisplayName() {
        if (!Case.isCaseOpen()) {
            return "";
        }
        try {
            return Case.getCurrentCaseThrows().getDisplayName();
        } catch (Exception ex) {
            return "";
        }
    }

    /** The examiner of the open case, else the Windows user. */
    public static String operator() {
        if (Case.isCaseOpen()) {
            try {
                String examiner = Case.getCurrentCaseThrows().getExaminer();
                if (examiner != null && !examiner.isBlank()) {
                    return examiner.trim();
                }
            } catch (Exception ignored) {
                // fall back to the account name
            }
        }
        String user = System.getenv("USERNAME");
        return user == null || user.isBlank() ? System.getProperty("user.name", "aegis") : user;
    }
}
