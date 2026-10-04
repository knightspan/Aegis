package org.sleuthkit.autopsy.aegis.audit;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Append-only SHA-256 hash-chained audit ledger (tamper-evident, not "tamper-proof").
 */
public final class AuditLedgerService {

    public static final class Entry {
        public final String id;
        public final String operationId;
        public final String type;
        public final String payload;
        public final String previousHash;
        public final String hash;
        public final Instant at;

        Entry(String id, String operationId, String type, String payload, String previousHash, String hash, Instant at) {
            this.id = id;
            this.operationId = operationId;
            this.type = type;
            this.payload = payload;
            this.previousHash = previousHash;
            this.hash = hash;
            this.at = at;
        }
    }

    private final List<Entry> entries = new ArrayList<>();
    private String tip = GENESIS;
    private final Path store;

    public static final String GENESIS = "GENESIS";

    private static final AuditLedgerService SHARED = new AuditLedgerService(ledgerPath());

    public static AuditLedgerService shared() {
        return SHARED;
    }

    public AuditLedgerService() {
        this(null);
    }

    public AuditLedgerService(Path store) {
        this.store = store;
        if (store != null) {
            load();
        }
    }

    public synchronized Entry append(String operationId, String type, String payload) {
        String prev = tip;
        String id = UUID.randomUUID().toString().replace("-", "");
        Instant at = Instant.now();
        String canonical = id + "|" + nullToEmpty(operationId) + "|" + nullToEmpty(type)
                + "|" + nullToEmpty(payload) + "|" + prev + "|" + at;
        String hash = sha256(canonical);
        Entry entry = new Entry(id, nullToEmpty(operationId), nullToEmpty(type), nullToEmpty(payload), prev, hash, at);
        entries.add(entry);
        tip = hash;
        persist(entry);
        return entry;
    }

    public synchronized List<Entry> snapshot() {
        return Collections.unmodifiableList(new ArrayList<>(entries));
    }

    public synchronized String tipHash() {
        return tip;
    }

    public synchronized boolean verifyChain() {
        String prev = GENESIS;
        for (Entry e : entries) {
            if (!prev.equals(e.previousHash)) {
                return false;
            }
            String canonical = e.id + "|" + e.operationId + "|" + e.type + "|" + e.payload + "|" + e.previousHash + "|" + e.at;
            if (!sha256(canonical).equals(e.hash)) {
                return false;
            }
            prev = e.hash;
        }
        return true;
    }

    public synchronized Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("algorithm", "SHA-256");
        map.put("tip", tip);
        map.put("verified", verifyChain());
        map.put("count", entries.size());
        List<Map<String, String>> rows = new ArrayList<>();
        for (Entry e : entries) {
            Map<String, String> row = new LinkedHashMap<>();
            row.put("id", e.id);
            row.put("operationId", e.operationId);
            row.put("type", e.type);
            row.put("payload", e.payload);
            row.put("previousHash", e.previousHash);
            row.put("hash", e.hash);
            row.put("at", e.at.toString());
            rows.add(row);
        }
        map.put("entries", rows);
        return map;
    }

    private void load() {
        try {
            if (!Files.isRegularFile(store)) {
                return;
            }
            String prev = GENESIS;
            for (String line : Files.readAllLines(store, StandardCharsets.UTF_8)) {
                if (line.isBlank()) {
                    continue;
                }
                Entry entry = parse(line);
                String canonical = entry.id + "|" + entry.operationId + "|" + entry.type + "|" + entry.payload
                        + "|" + entry.previousHash + "|" + entry.at;
                if (!prev.equals(entry.previousHash) || !sha256(canonical).equals(entry.hash)) {
                    Files.move(store, store.resolveSibling("audit-ledger-corrupt-" + System.currentTimeMillis() + ".jsonl"));
                    entries.clear();
                    tip = GENESIS;
                    append("", "ledger.corrupt", "Existing ledger failed verification and was preserved aside. A new chain was started.");
                    return;
                }
                entries.add(entry);
                prev = entry.hash;
            }
            tip = prev;
        } catch (IOException ex) {
            entries.clear();
            tip = GENESIS;
        }
    }

    private void persist(Entry entry) {
        if (store == null) {
            return;
        }
        try {
            Files.createDirectories(store.getParent());
            String line = "{\"id\":\"" + esc(entry.id) + "\",\"operationId\":\"" + esc(entry.operationId)
                    + "\",\"type\":\"" + esc(entry.type) + "\",\"payload\":\"" + esc(entry.payload)
                    + "\",\"previousHash\":\"" + esc(entry.previousHash) + "\",\"hash\":\"" + esc(entry.hash)
                    + "\",\"at\":\"" + esc(entry.at.toString()) + "\"}\n";
            Files.writeString(store, line, StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException ex) {
            // The in-memory chain remains available for this session.
        }
    }

    private static Entry parse(String line) {
        return new Entry(
                field(line, "id"),
                field(line, "operationId"),
                field(line, "type"),
                field(line, "payload"),
                field(line, "previousHash"),
                field(line, "hash"),
                Instant.parse(field(line, "at")));
    }

    private static String field(String json, String key) {
        String needle = "\"" + key + "\":\"";
        int i = json.indexOf(needle);
        if (i < 0) {
            return "";
        }
        int start = i + needle.length();
        StringBuilder sb = new StringBuilder();
        for (int p = start; p < json.length(); p++) {
            char c = json.charAt(p);
            if (c == '\\' && p + 1 < json.length()) {
                sb.append(json.charAt(p + 1));
                p++;
                continue;
            }
            if (c == '"') {
                break;
            }
            sb.append(c);
        }
        return sb.toString();
    }

    private static String esc(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "");
    }

    private static Path ledgerPath() {
        return Path.of(System.getProperty("user.home"), ".aegis", "audit-ledger.jsonl");
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }

    private static String sha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] dig = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(dig.length * 2);
            for (byte b : dig) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
