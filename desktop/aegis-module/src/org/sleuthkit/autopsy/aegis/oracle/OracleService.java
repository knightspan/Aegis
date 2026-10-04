package org.sleuthkit.autopsy.aegis.oracle;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.sleuthkit.autopsy.aegis.engine.AegisEngine;
import org.sleuthkit.autopsy.aegis.engine.CaseWorkspace;
import org.sleuthkit.autopsy.aegis.engine.EngineResult;
import org.sleuthkit.autopsy.aegis.util.AegisJson.AegisJsonObject;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.Image;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.sleuthkit.datamodel.TskData;

/**
 * AEGIS ORACLE: a provenance-aware forensic knowledge graph of the open case.
 *
 * <p>Not a chatbot and not an inference engine. Every entity and every edge is
 * read from a recorded source and carries that source as its provenance: a
 * Sleuth Kit object or artifact id, an AEGIS engine job record, or a
 * hash-chained ledger entry (sequence number and entry hash). Two entities are
 * joined only when the same identifier (a device serial, a SHA-256, a job id,
 * an object id) appears in both records. Nothing is joined by similarity.
 */
public final class OracleService {

    private static final Logger LOG = Logger.getLogger(OracleService.class.getName());
    private static final int MAX_FILES = 150;
    private static final int MAX_ARTIFACTS_PER_TYPE = 60;

    public static final class Entity {

        public String id;
        public String type;
        public String label;
        public String provenance = "";
        public final Map<String, String> meta = new LinkedHashMap<>();
        public String hash = "";
        public String time = "";
    }

    public static final class Relationship {

        public String id;
        public String fromId;
        public String toId;
        public String type;
        public String provenance = "";
    }

    public static final class Event {

        public String when = "";
        public String type = "";
        public String label = "";
        public String source = "";
        public String entityId = "";
        public String provenance = "";
    }

    public static final class GraphModel {

        public final Map<String, Entity> byId = new LinkedHashMap<>();
        public final List<Entity> entities = new ArrayList<>();
        public final List<Relationship> relationships = new ArrayList<>();
        public final List<Event> events = new ArrayList<>();
        public final List<String> insights = new ArrayList<>();
        public final List<String> sources = new ArrayList<>();
        public String status = "";
        public String ledgerStatus = "";
        public boolean grounded;

        public List<Relationship> edgesOf(String id) {
            List<Relationship> out = new ArrayList<>();
            for (Relationship r : relationships) {
                if (r.fromId.equals(id) || r.toId.equals(id)) {
                    out.add(r);
                }
            }
            return out;
        }

        public List<Event> eventsOf(String id) {
            List<Event> out = new ArrayList<>();
            for (Event e : events) {
                if (id.equals(e.entityId)) {
                    out.add(e);
                }
            }
            return out;
        }
    }

    public GraphModel buildFromOpenCase() {
        GraphModel m = new GraphModel();
        Case caze;
        try {
            caze = Case.getCurrentCaseThrows();
        } catch (Exception ex) {
            m.status = "Open a case to build the ORACLE graph from its evidence.";
            return m;
        }
        Entity caseEntity = entity(m, "case:" + caze.getName(), "Case", caze.getDisplayName(), "Autopsy case " + caze.getName());
        caseEntity.meta.put("Case number", nz(caze.getNumber()));
        caseEntity.meta.put("Examiner", nz(caze.getExaminer()));
        caseEntity.meta.put("Directory", caze.getCaseDirectory());
        try {
            addCaseDatabase(m, caze, caseEntity);
            m.sources.add("Sleuth Kit case database (data sources, deleted files, blackboard artifacts)");
        } catch (Exception ex) {
            LOG.log(Level.WARNING, "ORACLE: case database read failed", ex);
            m.sources.add("Case database read failed: " + ex.getMessage());
        }
        Map<String, Long> ledgerSeq = new LinkedHashMap<>();
        Map<String, String> ledgerHash = new LinkedHashMap<>();
        try {
            addLedger(m, ledgerSeq, ledgerHash);
        } catch (Exception ex) {
            LOG.log(Level.WARNING, "ORACLE: ledger read failed", ex);
            m.sources.add("AEGIS ledger read failed: " + ex.getMessage());
        }
        try {
            addAegisJobs(m, caseEntity, ledgerSeq, ledgerHash);
            m.sources.add("AEGIS engine job records (" + CaseWorkspace.stateDir().resolve("jobs") + ")");
        } catch (Exception ex) {
            LOG.log(Level.WARNING, "ORACLE: job records read failed", ex);
        }
        m.events.sort((a, b) -> a.when.compareTo(b.when));
        insights(m);
        m.grounded = true;
        m.status = m.entities.size() + " entities · " + m.relationships.size() + " relationships · " + m.events.size()
                + " events. Every edge carries its source; nothing is inferred.";
        return m;
    }

    // ------------------------------------------------------------------ case database

    private void addCaseDatabase(GraphModel m, Case caze, Entity caseEntity) throws Exception {
        SleuthkitCase db = caze.getSleuthkitCase();
        Map<Long, Entity> sources = new LinkedHashMap<>();
        for (Content ds : caze.getDataSources()) {
            String prov = "TSK data source obj_id=" + ds.getId();
            String type = ds.getName().startsWith("AEGIS Recovery") ? "Recovery Set" : "Evidence";
            Entity e = entity(m, "ds:" + ds.getId(), type, ds.getName(), prov);
            if (ds instanceof Image img) {
                String[] paths = img.getPaths();
                if (paths != null && paths.length > 0) {
                    e.meta.put("Path", paths[0]);
                }
                e.meta.put("Size", Long.toString(img.getSize()));
                String sha = img.getSha256();
                if (sha != null && !sha.isBlank()) {
                    e.hash = sha;
                    e.meta.put("SHA-256", sha);
                }
            }
            sources.put(ds.getId(), e);
            rel(m, e.id, "belongs_to", caseEntity.id, prov);
        }
        // Deleted regular files: the recovery-relevant population.
        List<AbstractFile> deleted = db.findAllFilesWhere("dir_flags = " + TskData.TSK_FS_NAME_FLAG_ENUM.UNALLOC.getValue()
                + " AND meta_type = " + TskData.TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_REG.getValue() + " LIMIT " + MAX_FILES);
        for (AbstractFile f : deleted) {
            Entity fe = fileEntity(m, f, "Deleted File");
            Entity ds = sources.get(f.getDataSourceObjectId());
            if (ds != null) {
                rel(m, fe.id, "stored_on", ds.id, "TSK file obj_id=" + f.getId() + " in data source " + f.getDataSourceObjectId());
            }
        }
        // Blackboard artifacts of the types that connect people, devices, places and time.
        BlackboardArtifact.ARTIFACT_TYPE[] types = {
            BlackboardArtifact.ARTIFACT_TYPE.TSK_DEVICE_ATTACHED, BlackboardArtifact.ARTIFACT_TYPE.TSK_METADATA_EXIF,
            BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_TRACKPOINT, BlackboardArtifact.ARTIFACT_TYPE.TSK_RECENT_OBJECT,
            BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_DOWNLOAD, BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_HISTORY,
            BlackboardArtifact.ARTIFACT_TYPE.TSK_EMAIL_MSG, BlackboardArtifact.ARTIFACT_TYPE.TSK_PROG_RUN,
            BlackboardArtifact.ARTIFACT_TYPE.TSK_INSTALLED_PROG, BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT};
        for (BlackboardArtifact.ARTIFACT_TYPE t : types) {
            List<BlackboardArtifact> arts = db.getBlackboardArtifacts(t);
            int n = 0;
            for (BlackboardArtifact a : arts) {
                if (n++ >= MAX_ARTIFACTS_PER_TYPE) {
                    break;
                }
                addArtifact(m, db, a, sources);
            }
        }
    }

    private Entity fileEntity(GraphModel m, AbstractFile f, String type) {
        Entity fe = entity(m, "file:" + f.getId(), type, f.getName(), "TSK file obj_id=" + f.getId());
        fe.meta.put("Path", nz(f.getParentPath()) + f.getName());
        fe.meta.put("Size", Long.toString(f.getSize()));
        fe.meta.put("Deleted", f.isDirNameFlagSet(TskData.TSK_FS_NAME_FLAG_ENUM.UNALLOC) ? "Yes" : "No");
        if (f.getMd5Hash() != null) {
            fe.meta.put("MD5", f.getMd5Hash());
        }
        if (f.getSha256Hash() != null) {
            fe.hash = f.getSha256Hash();
            fe.meta.put("SHA-256", fe.hash);
        }
        if (f.getMtime() > 0) {
            fe.time = iso(f.getMtime());
            event(m, fe.time, "File Modified", f.getName() + " modified", "File system (" + typeName(f) + ")", fe.id,
                    "TSK mtime of obj_id=" + f.getId());
        }
        if (f.getCrtime() > 0) {
            event(m, iso(f.getCrtime()), "File Created", f.getName() + " created", "File system (" + typeName(f) + ")", fe.id,
                    "TSK crtime of obj_id=" + f.getId());
        }
        return fe;
    }

    private static String typeName(AbstractFile f) {
        try {
            return f.getFileSystem() == null ? "file system" : f.getFileSystem().getFsType().getDisplayName();
        } catch (Exception ex) {
            return "file system";
        }
    }

    private void addArtifact(GraphModel m, SleuthkitCase db, BlackboardArtifact a, Map<Long, Entity> sources) throws Exception {
        String display = a.getDisplayName();
        String prov = "TSK artifact id=" + a.getArtifactID() + " (" + a.getArtifactTypeName() + ")";
        Entity art = entity(m, "art:" + a.getArtifactID(), artifactType(a), display, prov);
        Content src = db.getContentById(a.getObjectID());
        if (src instanceof AbstractFile f) {
            Entity fe = m.byId.containsKey("file:" + f.getId()) ? m.byId.get("file:" + f.getId()) : fileEntity(m, f, "File");
            rel(m, art.id, "associated_with", fe.id, prov + " source obj_id=" + f.getId());
            Entity ds = sources.get(f.getDataSourceObjectId());
            if (ds != null && m.edgesOf(fe.id).stream().noneMatch(r -> "stored_on".equals(r.type))) {
                rel(m, fe.id, "stored_on", ds.id, "TSK file obj_id=" + f.getId());
            }
        }
        String user = "";
        String deviceId = "";
        String make = "";
        String model = "";
        Double lat = null;
        Double lon = null;
        for (BlackboardAttribute attr : a.getAttributes()) {
            String key = attr.getAttributeType().getTypeName();
            String value = attr.getDisplayString();
            if (value == null || value.isBlank()) {
                continue;
            }
            art.meta.put(attr.getAttributeType().getDisplayName(), value);
            switch (key) {
                case "TSK_USER_NAME", "TSK_USER_ID" -> user = value;
                case "TSK_DEVICE_ID" -> deviceId = value;
                case "TSK_DEVICE_MAKE" -> make = value;
                case "TSK_DEVICE_MODEL" -> model = value;
                case "TSK_GEO_LATITUDE" -> lat = attr.getValueDouble();
                case "TSK_GEO_LONGITUDE" -> lon = attr.getValueDouble();
                default -> {
                }
            }
            if (attr.getAttributeType().getValueType() == BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME
                    && attr.getValueLong() > 0) {
                art.time = iso(attr.getValueLong());
                event(m, art.time, display, display + ": " + attr.getAttributeType().getDisplayName(), a.getArtifactTypeName(),
                        art.id, prov);
            }
        }
        if (!user.isBlank()) {
            Entity u = entity(m, "user:" + user.toLowerCase(Locale.ROOT), "User", user, "TSK artifact attribute TSK_USER_NAME");
            rel(m, art.id, "accessed_by", u.id, prov);
        }
        if (!deviceId.isBlank()) {
            Entity d = entity(m, "device:" + normalizeSerial(deviceId), "Device", (make + " " + model).trim().isBlank() ? deviceId
                    : (make + " " + model).trim(), "TSK_DEVICE_ATTACHED device id " + deviceId);
            d.meta.put("Device ID", deviceId);
            rel(m, d.id, "referenced_by", art.id, prov);
        }
        if (lat != null && lon != null) {
            String label = String.format(Locale.ROOT, "%.5f, %.5f", lat, lon);
            Entity loc = entity(m, "loc:" + label, "Location", label, "TSK_GEO_LATITUDE/LONGITUDE of artifact " + a.getArtifactID());
            rel(m, art.id, "occurred_at", loc.id, prov);
        }
        if (a.getArtifactTypeID() == BlackboardArtifact.ARTIFACT_TYPE.TSK_PROG_RUN.getTypeID()) {
            String name = art.meta.getOrDefault("Program Name", display);
            Entity p = entity(m, "proc:" + name.toLowerCase(Locale.ROOT), "Process", name, prov);
            rel(m, p.id, "referenced_by", art.id, prov);
        }
    }

    private static String artifactType(BlackboardArtifact a) {
        int id = a.getArtifactTypeID();
        if (id == BlackboardArtifact.ARTIFACT_TYPE.TSK_EMAIL_MSG.getTypeID()) {
            return "Communication";
        }
        if (id == BlackboardArtifact.ARTIFACT_TYPE.TSK_DEVICE_ATTACHED.getTypeID()
                || id == BlackboardArtifact.ARTIFACT_TYPE.TSK_RECENT_OBJECT.getTypeID()
                || id == BlackboardArtifact.ARTIFACT_TYPE.TSK_INSTALLED_PROG.getTypeID()) {
            return "Registry Entry";
        }
        return "Artifact";
    }

    // ------------------------------------------------------------------ AEGIS ledger and jobs

    private void addLedger(GraphModel m, Map<String, Long> seqByJob, Map<String, String> hashByJob) throws Exception {
        EngineResult verify = AegisEngine.ledgerVerify();
        m.ledgerStatus = verify.succeeded() ? verify.result.optString("status", "VALID") + " (" + verify.result.optString("entry_count") + " entries)"
                : "INVALID: " + verify.errorMessage;
        EngineResult list = AegisEngine.ledgerList("");
        if (!list.succeeded()) {
            m.sources.add("AEGIS ledger unavailable: " + list.summary());
            return;
        }
        Path file = Path.of(list.result.optString("result_file"));
        AegisJsonObject export = AegisJsonObject.parseStrict(Files.readString(file, StandardCharsets.UTF_8));
        int n = 0;
        for (AegisJsonObject en : export.array("entries").objects()) {
            String op = en.optString("operation");
            String job = en.object("params").optString("job_id");
            String prov = "AEGIS ledger seq " + en.optLong("seq", 0) + " entry_hash " + en.optString("entry_hash");
            if (!job.isBlank()) {
                seqByJob.putIfAbsent(job, en.optLong("seq", 0));
                hashByJob.put(job, en.optString("entry_hash"));
            }
            if ("GENESIS".equals(op)) {
                continue;
            }
            event(m, en.optString("ts_utc"), "AEGIS " + op, describe(op, en), "AEGIS ledger", job.isBlank() ? "" : "op:" + job, prov);
            n++;
        }
        m.sources.add("AEGIS hash-chained ledger: " + n + " entries, chain " + m.ledgerStatus);
    }

    private static String describe(String op, AegisJsonObject en) {
        AegisJsonObject p = en.object("params");
        return switch (op) {
            case "acquire.start" -> "Acquisition started: " + p.optString("source");
            case "acquire.complete" -> "Acquisition complete: " + p.optString("dest_path") + " sha256 " + Kitless.short16(en.object("result").optString("sha256"));
            case "carve.start" -> "Recovery started on " + p.object("evidence").optString("path");
            case "carve.complete" -> "Recovery complete: " + p.optString("candidates") + " candidate(s)";
            case "report.generated" -> "Signed report generated (" + p.optString("kind") + ")";
            case "aegis.sanitize.authorized" -> "Sanitization authorized for " + p.optString("model") + " serial " + p.optString("serial");
            case "aegis.sanitize.refused" -> "Sanitization REFUSED for " + p.optString("device") + " (" + p.optString("reason") + ")";
            case "aegis.enhance" -> "AI-enhanced derivative of " + p.optString("source");
            default -> op.replace('.', ' ') + (p.optString("job_id").isBlank() ? "" : " (" + p.optString("job_id") + ")");
        };
    }

    private void addAegisJobs(GraphModel m, Entity caseEntity, Map<String, Long> seq, Map<String, String> hash) throws Exception {
        Path jobs = CaseWorkspace.stateDir().resolve("jobs");
        if (!Files.isDirectory(jobs)) {
            return;
        }
        List<AegisJsonObject> all = new ArrayList<>();
        try (var stream = Files.newDirectoryStream(jobs, "*.json")) {
            for (Path p : stream) {
                if (p.getFileName().toString().startsWith("_")) {
                    continue;
                }
                try {
                    all.add(AegisJsonObject.parseStrict(Files.readString(p, StandardCharsets.UTF_8)));
                } catch (Exception ignored) {
                    // unreadable job record: not part of the graph
                }
            }
        }
        all.sort((a, b) -> a.optString("started_at").compareTo(b.optString("started_at")));
        Map<String, Entity> imageByPath = new LinkedHashMap<>();
        for (Entity e : m.entities) {
            String p = e.meta.get("Path");
            if (p != null && "Evidence".equals(e.type)) {
                imageByPath.put(p.toLowerCase(Locale.ROOT), e);
            }
        }
        Map<String, Entity> recoveredByPath = new LinkedHashMap<>();
        for (AegisJsonObject job : all) {
            String id = job.optString("job_id");
            String kind = job.optString("kind");
            AegisJsonObject params = job.object("params");
            AegisJsonObject result = job.object("result");
            String prov = "AEGIS job " + id + (seq.containsKey(id) ? " (ledger seq " + seq.get(id) + ", entry_hash "
                    + Kitless.short16(hash.get(id)) + ")" : "");
            switch (kind) {
                case "acquire" -> {
                    Entity op = entity(m, "op:" + id, "Acquisition", "Acquisition " + id, prov);
                    op.time = job.optString("finished_at");
                    op.meta.put("Status", job.optString("status"));
                    op.meta.put("Format", params.optString("format"));
                    String imagePath = result.optString("image_path");
                    Entity img = imageByPath.get(imagePath.toLowerCase(Locale.ROOT));
                    if (img == null && !imagePath.isBlank()) {
                        img = entity(m, "img:" + imagePath.toLowerCase(Locale.ROOT), "Evidence", Path.of(imagePath).getFileName().toString(), prov);
                        img.meta.put("Path", imagePath);
                        imageByPath.put(imagePath.toLowerCase(Locale.ROOT), img);
                        rel(m, img.id, "belongs_to", caseEntity.id, prov);
                    }
                    String sha = result.object("record").optString("sha256");
                    if (img != null) {
                        img.hash = sha;
                        img.meta.put("SHA-256", sha);
                        img.meta.put("BLAKE3", result.object("record").optString("blake3"));
                        rel(m, img.id, "created_by", op.id, prov);
                        rel(m, op.id, "verified_by", "verify:" + id, prov);
                        Entity v = entity(m, "verify:" + id, "Verification", result.object("verification").optBoolean("passed", false)
                                ? "Image verified" : "Image NOT verified", prov);
                        v.meta.put("SHA-256 match", Boolean.toString(result.object("verification").optBoolean("sha256_matches", false)));
                        v.meta.put("BLAKE3 match", Boolean.toString(result.object("verification").optBoolean("blake3_matches", false)));
                    }
                    String serial = params.optString("expected_serial").trim();
                    if (!serial.isBlank()) {
                        Entity dev = entity(m, "device:" + normalizeSerial(serial), "Device",
                                params.optString("device_model").isBlank() ? serial : params.optString("device_model"), prov);
                        dev.meta.put("Serial", serial);
                        if (img != null) {
                            rel(m, img.id, "derived_from", dev.id, prov + " (read-only image of serial " + serial + ")");
                        }
                    }
                }
                case "carve" -> {
                    Entity op = entity(m, "op:" + id, "Recovery", "Recovery " + id, prov);
                    op.time = job.optString("finished_at");
                    String image = params.optString("image");
                    Entity img = imageByPath.get(image.toLowerCase(Locale.ROOT));
                    if (img == null) {
                        img = entity(m, "img:" + image.toLowerCase(Locale.ROOT), "Evidence", Path.of(image).getFileName().toString(), prov);
                        img.meta.put("Path", image);
                        imageByPath.put(image.toLowerCase(Locale.ROOT), img);
                        rel(m, img.id, "belongs_to", caseEntity.id, prov);
                    }
                    rel(m, op.id, "derived_from", img.id, prov);
                    for (AegisJsonObject c : result.array("candidates").objects()) {
                        String out = c.optString("output_path");
                        String name = c.optString("original_name").isBlank()
                                ? (out.isBlank() ? c.optString("ext") + "@" + c.optLong("offset", 0) : Path.of(out).getFileName().toString())
                                : c.optString("original_name");
                        Entity rf = entity(m, "rec:" + id + ":" + c.optString("source") + ":" + c.optLong("offset", 0), "Recovered File", name,
                                prov + "; offset " + c.optLong("offset", 0) + "; sha256 " + c.optString("sha256"));
                        rf.hash = c.optString("sha256");
                        rf.meta.put("SHA-256", rf.hash);
                        rf.meta.put("Offset", Long.toString(c.optLong("offset", 0)));
                        rf.meta.put("Length", Long.toString(c.optLong("length", 0)));
                        rf.meta.put("Type", c.optString("ext").toUpperCase(Locale.ROOT) + " · " + c.optString("mime"));
                        rf.meta.put("Evidence score", c.optLong("confidence_bp", 0) / 100.0 + "% (" + c.optString("bucket") + ")");
                        rf.meta.put("Validation", c.optString("validation"));
                        rf.meta.put("Recovered by", c.optString("source"));
                        rf.meta.put("Fragments", Integer.toString(c.array("fragments").length()));
                        rf.meta.put("Recovered copy", out);
                        AegisJsonObject mac = c.optJSONObject("mac");
                        if (mac != null) {
                            for (String k : mac.keys()) {
                                if (!mac.optString(k).isBlank()) {
                                    rf.meta.put("MAC " + k, mac.optString(k));
                                    if ("modified".equals(k) || "created".equals(k)) {
                                        event(m, mac.optString(k), "File " + k + " (recovered metadata)", name + " " + k,
                                                "Filesystem metadata (" + c.optString("fs_type") + ")", rf.id, prov);
                                    }
                                }
                            }
                        }
                        rel(m, rf.id, "recovered_from", img.id, prov + "; offset " + c.optLong("offset", 0));
                        rel(m, rf.id, "created_by", op.id, prov);
                        if (!out.isBlank()) {
                            recoveredByPath.put(out.toLowerCase(Locale.ROOT), rf);
                        }
                        // Same bytes as a file Autopsy already knows: joined by exact SHA-256 only.
                        for (Entity e : new ArrayList<>(m.entities)) {
                            if (e != rf && !e.hash.isBlank() && e.hash.equalsIgnoreCase(rf.hash)
                                    && ("File".equals(e.type) || "Deleted File".equals(e.type))) {
                                rel(m, rf.id, "associated_with", e.id, "identical SHA-256 " + rf.hash);
                            }
                        }
                    }
                }
                case "erase-drive" -> {
                    AegisJsonObject dev = params.object("device");
                    String serial = dev.optString("serial").trim();
                    Entity op = entity(m, "op:" + id, "Sanitization Operation", "Sanitization " + id, prov);
                    op.time = job.optString("finished_at");
                    op.meta.put("Level", params.optString("level"));
                    op.meta.put("Overwrite profile", params.optString("overwrite_method"));
                    op.meta.put("Achieved", result.optString("achieved_level"));
                    op.meta.put("Verification", result.object("verification").optBoolean("passed", false) ? "PASSED" : "FAILED");
                    if (!serial.isBlank()) {
                        Entity d = entity(m, "device:" + normalizeSerial(serial), "Device", dev.optString("model"), prov);
                        d.meta.put("Serial", serial);
                        rel(m, d.id, "sanitized_by", op.id, prov);
                    }
                    Entity v = entity(m, "verify:" + id, "Verification", result.object("verification").optBoolean("passed", false)
                            ? "Read-back verified" : "Read-back FAILED", prov);
                    v.meta.put("Strategy", result.object("verification").optString("strategy"));
                    rel(m, op.id, "verified_by", v.id, prov);
                }
                case "traces" -> {
                    Entity op = entity(m, "op:" + id, "Sanitization Operation", "Trace purge " + id, prov);
                    String src = params.optString("source_job");
                    if (!src.isBlank()) {
                        rel(m, op.id, "associated_with", "op:" + src, prov);
                    }
                    op.meta.put("Erased paths", String.join("; ", params.optStringList("erased")));
                }
                case "enhance" -> {
                    String source = result.optString("source");
                    Entity src = recoveredByPath.get(source.toLowerCase(Locale.ROOT));
                    Entity der = entity(m, "der:" + id, "Derivative", Path.of(result.optString("enhanced", id)).getFileName().toString(), prov);
                    der.hash = result.optString("enhanced_sha256");
                    der.meta.put("SHA-256", der.hash);
                    der.meta.put("Model", result.optString("model") + " x" + result.optString("scale"));
                    der.meta.put("Source SHA-256", result.optString("source_sha256"));
                    der.meta.put("Note", "AI-enhanced derivative, not evidence");
                    if (src != null) {
                        rel(m, der.id, "derived_from", src.id, prov);
                    }
                }
                default -> {
                }
            }
        }
        // Reports
        Path reports = CaseWorkspace.stateDir().resolve("reports");
        if (Files.isDirectory(reports)) {
            try (var dirs = Files.newDirectoryStream(reports)) {
                for (Path dir : dirs) {
                    Path meta = dir.resolve("aegis-report.meta.json");
                    if (Files.isRegularFile(meta)) {
                        AegisJsonObject r = AegisJsonObject.parseStrict(Files.readString(meta, StandardCharsets.UTF_8));
                        String job = r.optString("job_id");
                        Entity rep = entity(m, "report:" + job, "Report", "Signed report " + job, "AEGIS report " + r.optString("json")
                                + " sha256 " + r.optString("sha256"));
                        rep.hash = r.optString("sha256");
                        rep.meta.put("SHA-256", rep.hash);
                        rep.meta.put("Signer", r.optString("fingerprint"));
                        rep.meta.put("JSON", r.optString("json"));
                        if (m.byId.containsKey("op:" + job)) {
                            rel(m, "op:" + job, "reported_in", rep.id, "report.generated for job " + job);
                        }
                    }
                }
            }
        }
        // Drop edges whose endpoints were never created (a job referring to one not in this case).
        m.relationships.removeIf(r -> !m.byId.containsKey(r.fromId) || !m.byId.containsKey(r.toId));
    }

    // ------------------------------------------------------------------ insights

    private static void insights(GraphModel m) {
        Map<String, Integer> byType = new LinkedHashMap<>();
        for (Entity e : m.entities) {
            byType.merge(e.type, 1, Integer::sum);
        }
        m.insights.add("Entities by type: " + byType);
        for (Entity d : m.entities) {
            if (!"Device".equals(d.type)) {
                continue;
            }
            List<String> parts = new ArrayList<>();
            for (Relationship r : m.edgesOf(d.id)) {
                Entity other = m.byId.get(r.fromId.equals(d.id) ? r.toId : r.fromId);
                if (other == null) {
                    continue;
                }
                switch (r.type) {
                    case "derived_from" -> parts.add("imaged read-only as " + other.label + " (SHA-256 " + Kitless.short16(other.hash) + ")");
                    case "sanitized_by" -> parts.add("sanitized by " + other.label + " (achieved " + other.meta.getOrDefault("Achieved", "?")
                            + ", verification " + other.meta.getOrDefault("Verification", "?") + ")");
                    case "referenced_by" -> parts.add("recorded by the host in " + other.label);
                    default -> {
                    }
                }
            }
            if (!parts.isEmpty()) {
                m.insights.add("Device " + d.label + " [" + d.meta.getOrDefault("Serial", d.meta.getOrDefault("Device ID", "")) + "]: "
                        + String.join("; ", parts) + ".");
            }
        }
        long recovered = m.entities.stream().filter(e -> "Recovered File".equals(e.type)).count();
        long fragments = m.entities.stream().filter(e -> "Recovered File".equals(e.type)
                && !"0".equals(e.meta.getOrDefault("Fragments", "0"))).count();
        long fromMeta = m.entities.stream().filter(e -> "Recovered File".equals(e.type)
                && "fs_metadata".equals(e.meta.get("Recovered by"))).count();
        if (recovered > 0) {
            m.insights.add(recovered + " recovered object(s): " + fromMeta + " from surviving filesystem metadata, " + fragments
                    + " reassembled from two fragments; each carries its offset and SHA-256.");
        }
        long sameHash = m.relationships.stream().filter(r -> r.provenance.startsWith("identical SHA-256")).count();
        if (sameHash > 0) {
            m.insights.add(sameHash + " recovered object(s) have the same SHA-256 as a file in the case file system.");
        }
        if (!m.ledgerStatus.isBlank()) {
            m.insights.add("Case ledger chain: " + m.ledgerStatus + ".");
        }
        m.insights.add("ORACLE asserts no intent or attribution; it shows recorded relationships and where each came from.");
    }

    // ------------------------------------------------------------------ helpers

    private static Entity entity(GraphModel m, String id, String type, String label, String provenance) {
        Entity existing = m.byId.get(id);
        if (existing != null) {
            if (existing.provenance.length() < 600 && !existing.provenance.contains(provenance)) {
                existing.provenance += "; " + provenance;
            }
            return existing;
        }
        Entity e = new Entity();
        e.id = id;
        e.type = Objects.requireNonNull(type);
        e.label = label == null || label.isBlank() ? type : label;
        e.provenance = provenance == null ? "" : provenance;
        m.byId.put(id, e);
        m.entities.add(e);
        return e;
    }

    private static void rel(GraphModel m, String from, String type, String to, String provenance) {
        for (Relationship r : m.relationships) {
            if (r.fromId.equals(from) && r.toId.equals(to) && r.type.equals(type)) {
                return;
            }
        }
        Relationship r = new Relationship();
        r.id = from + "|" + type + "|" + to;
        r.fromId = from;
        r.toId = to;
        r.type = type;
        r.provenance = provenance == null ? "" : provenance;
        m.relationships.add(r);
    }

    private static void event(GraphModel m, String when, String type, String label, String source, String entity, String prov) {
        if (when == null || when.isBlank()) {
            return;
        }
        Event e = new Event();
        e.when = when;
        e.type = type;
        e.label = label;
        e.source = source;
        e.entityId = entity == null ? "" : entity;
        e.provenance = prov;
        m.events.add(e);
    }

    static String normalizeSerial(String s) {
        return s == null ? "" : s.trim().replaceAll("[^A-Za-z0-9]", "").toUpperCase(Locale.ROOT);
    }

    private static String iso(long epochSeconds) {
        return java.time.Instant.ofEpochSecond(epochSeconds).toString();
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }

    public Map<String, Object> summary(GraphModel model) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("entities", model.entities.size());
        map.put("relationships", model.relationships.size());
        map.put("events", model.events.size());
        map.put("grounded", model.grounded);
        map.put("status", model.status);
        return map;
    }

    /** Small formatting helpers without a UI dependency. */
    static final class Kitless {

        private Kitless() {
        }

        static String short16(String h) {
            return h == null || h.isBlank() ? "-" : h.length() > 16 ? h.substring(0, 16) + "…" : h;
        }
    }
}
