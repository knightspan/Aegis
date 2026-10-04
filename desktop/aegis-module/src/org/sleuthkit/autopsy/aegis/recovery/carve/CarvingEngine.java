package org.sleuthkit.autopsy.aegis.recovery.carve;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Consumer;
import java.util.zip.CRC32;
import java.util.zip.GZIPInputStream;
import javax.imageio.ImageIO;

/**
 * AEGIS structure-aware carver.
 * A header match is not enough: formats with a parser are rejected when that parser fails.
 * Bifragment support is JPEG and PNG only, and it is a bounded two-run structural join.
 */
public final class CarvingEngine {

    public static final int WINDOW = 8 * 1024 * 1024;
    private static final int CHUNK = 1024 * 1024;
    private static final int OVERLAP = 280;
    private static final int HIGH = 8500;
    private static final int MEDIUM = 5000;
    private static final int REASSEMBLY_CAP = 7999;

    public static final class Progress {
        public long bytes;
        public long total;
        public int candidates;
        public int validated;
        public int rejected;
        public String region = "";
    }

    private static final class Sig {
        final String name;
        final String ext;
        final byte[] magic;
        final int headerOffset;
        final int minSize;

        Sig(String name, String ext, String hex, int headerOffset, int minSize) {
            this.name = name;
            this.ext = ext;
            this.magic = hexToBytes(hex);
            this.headerOffset = headerOffset;
            this.minSize = minSize;
        }
    }

    private static final List<Sig> SIGS = List.of(
            new Sig("JPEG", "jpg", "FFD8FF", 0, 128),
            new Sig("PNG", "png", "89504E470D0A1A0A", 0, 67),
            new Sig("GIF", "gif", "474946383761", 0, 35),
            new Sig("GIF", "gif", "474946383961", 0, 35),
            new Sig("PDF", "pdf", "255044462D", 0, 64),
            new Sig("ZIP", "zip", "504B0304", 0, 22),
            new Sig("MP4", "mp4", "66747970", 4, 32),
            new Sig("SQLite", "sqlite", "53514C69746520666F726D6174203300", 0, 512),
            new Sig("BMP", "bmp", "424D", 0, 54),
            new Sig("GZIP", "gz", "1F8B08", 0, 20),
            new Sig("RIFF", "riff", "52494646", 0, 12),
            new Sig("OLE", "ole", "D0CF11E0A1B11AE1", 0, 512),
            new Sig("ELF", "elf", "7F454C46", 0, 52),
            new Sig("PE", "exe", "4D5A", 0, 64),
            new Sig("RAR", "rar", "526172211A0700", 0, 20),
            new Sig("7z", "7z", "377ABCAF271C", 0, 32),
            new Sig("EVTX", "evtx", "456C6646696C6500", 0, 4096),
            new Sig("TIFF", "tiff", "49492A00", 0, 8),
            new Sig("TIFF", "tiff", "4D4D002A", 0, 8),
            new Sig("TAR", "tar", "7573746172", 257, 512),
            new Sig("RTF", "rtf", "7B5C72746631", 0, 16),
            new Sig("HTML", "html", "3C21444F43545950452068746D6C", 0, 32),
            new Sig("HTML", "html", "3C68746D6C3E", 0, 13)
    );

    public List<FormatRow> formatMatrix() {
        List<FormatRow> rows = new ArrayList<>();
        rows.add(new FormatRow("JPEG", true, true, true, true, "Marker walk to EOI. ImageIO is a weak decoder and is labeled as such. Bifragment is a structural two-run join, not Huffman MCU accounting."));
        rows.add(new FormatRow("PNG", true, true, true, true, "Chunk walk plus CRC32. Unique CRC-valid bifragment join is capped below HIGH."));
        rows.add(new FormatRow("GIF", true, true, false, false, "Screen descriptor plus 00 3B trailer. Trailer is a weak end marker."));
        rows.add(new FormatRow("PDF", true, true, false, false, "Requires %%EOF inside the scan window. startxref is recorded when present."));
        rows.add(new FormatRow("ZIP", true, true, true, false, "EOCD plus central-directory signature. OOXML renamed when package names are present."));
        rows.add(new FormatRow("DOCX/XLSX/PPTX", true, true, true, false, "ZIP package whose central directory names the OOXML part."));
        rows.add(new FormatRow("MP4", true, true, false, false, "ftyp at byte 4 and a top-level box-size walk."));
        rows.add(new FormatRow("SQLite", true, true, false, false, "Page size and page count from the header."));
        rows.add(new FormatRow("GZIP", true, true, true, false, "Inflater must consume a complete member."));
        rows.add(new FormatRow("BMP", true, true, false, false, "File size, pixel offset, and DIB header size must agree."));
        rows.add(new FormatRow("WAV", true, true, false, false, "RIFF form type WAVE and size field."));
        rows.add(new FormatRow("WebP", true, true, false, false, "RIFF form type WEBP and size field."));
        rows.add(new FormatRow("PE", true, true, false, false, "e_lfanew must point at PE\\0\\0. Length is not established."));
        rows.add(new FormatRow("ELF", true, true, false, false, "EI_CLASS and EI_DATA checked. Length is not established."));
        rows.add(new FormatRow("TAR", true, true, false, false, "ustar checksum. Archive length is not established."));
        rows.add(new FormatRow("RTF", true, true, false, false, "Brace-matched {\\rtf1 group inside the window."));
        rows.add(new FormatRow("HTML", true, true, false, false, "Requires a </html> end inside the window."));
        rows.add(new FormatRow("OLE/RAR/7z/EVTX/TIFF", true, false, false, false, "Signature only. Not extracted. Magic is not acceptance."));
        return rows;
    }

    public static final class FormatRow {
        public final String name;
        public final boolean signature;
        public final boolean structure;
        public final boolean decoder;
        public final boolean bifragment;
        public final String note;

        public FormatRow(String name, boolean signature, boolean structure, boolean decoder, boolean bifragment, String note) {
            this.name = name;
            this.signature = signature;
            this.structure = structure;
            this.decoder = decoder;
            this.bifragment = bifragment;
            this.note = note;
        }
    }

    public CarveReport scan(ByteSource source, long maxBytes, Consumer<Progress> progress) throws IOException {
        long started = System.nanoTime();
        CarveReport report = new CarveReport();
        long size = source.size();
        report.sourceSize = size;
        long limit = maxBytes > 0 ? Math.min(size, maxBytes) : size;
        report.scanTruncated = limit < size;
        List<Hit> hits = findHits(source, limit, progress, report);
        for (Hit hit : hits) {
            CarveCandidate candidate = validate(source, hit, limit);
            report.candidates.add(candidate);
            tally(report, candidate);
            publish(progress, report, hit.offset, "validate " + hit.sig.name);
        }
        resolveOverlaps(report);
        buildMediaMap(source, limit, report);
        report.elapsedMillis = (System.nanoTime() - started) / 1_000_000L;
        report.note = "Scanned " + report.bytesScanned + " of " + size + " bytes. "
                + "Accepted=" + report.accepted + " reassembled=" + report.reassembled
                + " identified=" + report.identified + " rejected=" + report.rejected + ". "
                + "Score is not a probability.";
        return report;
    }

    private static void tally(CarveReport report, CarveCandidate candidate) {
        switch (candidate.disposition) {
            case ACCEPTED -> report.accepted++;
            case REASSEMBLED -> report.reassembled++;
            case IDENTIFIED -> report.identified++;
            default -> report.rejected++;
        }
    }

    private List<Hit> findHits(ByteSource source, long limit, Consumer<Progress> progress, CarveReport report) throws IOException {
        List<Hit> hits = new ArrayList<>();
        byte[] buf = new byte[CHUNK + OVERLAP];
        long offset = 0;
        int carry = 0;
        while (offset < limit) {
            int want = (int) Math.min(CHUNK, limit - offset);
            int n = readFully(source, offset, buf, carry, want);
            if (n <= 0) {
                break;
            }
            int available = carry + n;
            for (Sig sig : SIGS) {
                int from = 0;
                while (from + sig.magic.length <= available) {
                    int at = indexOf(buf, from, available, sig.magic);
                    if (at < 0) {
                        break;
                    }
                    long abs = offset - carry + at;
                    long start = abs - sig.headerOffset;
                    if (start >= 0 && start + sig.minSize <= limit) {
                        hits.add(new Hit(sig, start));
                    }
                    from = at + 1;
                    if (hits.size() > 8000) {
                        report.note = "Hit cap reached.";
                        report.bytesScanned = offset + n;
                        return dedupe(hits);
                    }
                }
            }
            offset += n;
            report.bytesScanned = offset;
            carry = Math.min(OVERLAP, available);
            System.arraycopy(buf, available - carry, buf, 0, carry);
            publish(progress, report, offset, "scan");
        }
        report.bytesScanned = limit;
        return dedupe(hits);
    }

    private static List<Hit> dedupe(List<Hit> hits) {
        Map<String, Hit> map = new LinkedHashMap<>();
        for (Hit hit : hits) {
            map.putIfAbsent(hit.sig.name + "@" + hit.offset, hit);
        }
        return new ArrayList<>(map.values());
    }

    private CarveCandidate validate(ByteSource source, Hit hit, long limit) throws IOException {
        return switch (hit.sig.name) {
            case "JPEG" -> jpeg(source, hit, limit);
            case "PNG" -> png(source, hit, limit);
            case "GIF" -> gif(source, hit, limit);
            case "PDF" -> pdf(source, hit, limit);
            case "ZIP" -> zip(source, hit, limit);
            case "MP4" -> mp4(source, hit, limit);
            case "SQLite" -> sqlite(source, hit, limit);
            case "BMP" -> bmp(source, hit, limit);
            case "GZIP" -> gzip(source, hit, limit);
            case "RIFF" -> riff(source, hit, limit);
            case "PE" -> pe(source, hit);
            case "ELF" -> elf(source, hit);
            case "TAR" -> tar(source, hit);
            case "RTF" -> rtf(source, hit, limit);
            case "HTML" -> html(source, hit, limit);
            default -> identifiedOrReject(hit, "Signature only. Length and structure were not established, so the object was not extracted.");
        };
    }

    private CarveCandidate jpeg(ByteSource source, Hit hit, long limit) throws IOException {
        int max = (int) Math.min(WINDOW, limit - hit.offset);
        byte[] window = readUpTo(source, hit.offset, max);
        Parse end = jpegEnd(window);
        if (end.ok) {
            CarveCandidate c = base(hit, end.length, true, true, false);
            c.decoderName = "marker-walk";
            applyImageIo(c, Arrays.copyOf(window, (int) end.length), "JPEG");
            finishScore(c, "high");
            c.disposition = c.structure ? CarveCandidate.Disposition.ACCEPTED : CarveCandidate.Disposition.REJECTED;
            c.reason = "Contiguous JPEG marker walk reached EOI.";
            return c;
        }
        return jpegBifragment(source, hit, limit, window, end);
    }

    private CarveCandidate jpegBifragment(ByteSource source, Hit hit, long limit, byte[] head, Parse failed) throws IOException {
        CarveCandidate refused = base(hit, 0, true, false, false);
        refused.reason = "JPEG marker walk did not reach EOI (" + failed.reason + ").";
        refused.disposition = CarveCandidate.Disposition.REJECTED;
        finishScore(refused, "high");
        if (failed.cut <= 0) {
            return refused;
        }
        long searchEnd = Math.min(limit, hit.offset + WINDOW);
        byte[] region = readUpTo(source, hit.offset, (int) (searchEnd - hit.offset));
        List<Integer> eois = findMarker(region, failed.cut, new byte[]{(byte) 0xFF, (byte) 0xD9});
        int passes = 0;
        int chosenTail = -1;
        int chosenCut = failed.cut;
        for (int eoi : eois) {
            if (passes > 1) {
                break;
            }
            int tail = alignUp(failed.cut, 512);
            if (tail >= eoi) {
                tail = failed.cut;
            }
            byte[] joined = join(region, chosenCut, tail, eoi + 2);
            Parse again = jpegEnd(joined);
            if (again.ok) {
                passes++;
                chosenTail = tail;
            }
            if (eois.size() > 24) {
                break;
            }
        }
        if (passes != 1 || chosenTail < 0) {
            refused.reason = passes == 0
                    ? "No structural JPEG bifragment join validated."
                    : "JPEG bifragment refused: more than one join validated.";
            return refused;
        }
        int eoi = -1;
        for (int candidate : eois) {
            byte[] joined = join(region, chosenCut, chosenTail, candidate + 2);
            if (jpegEnd(joined).ok) {
                eoi = candidate;
                break;
            }
        }
        if (eoi < 0) {
            return refused;
        }
        byte[] joined = join(region, chosenCut, chosenTail, eoi + 2);
        CarveCandidate c = base(hit, joined.length, true, true, true);
        c.fragment2Offset = hit.offset + chosenTail;
        c.reassembled = true;
        c.decoderName = "structural-join";
        applyImageIo(c, joined, "JPEG");
        c.sha256 = sha256(joined);
        c.derivative = joined;
        finishScore(c, "high");
        c.disposition = CarveCandidate.Disposition.REASSEMBLED;
        c.reason = "Exactly one structural JPEG join validated. Not Huffman MCU accounting. "
                + "Fragment1=0.." + chosenCut + " fragment2=" + chosenTail + ".." + (eoi + 2) + ".";
        return c;
    }

    private CarveCandidate png(ByteSource source, Hit hit, long limit) throws IOException {
        int max = (int) Math.min(WINDOW, limit - hit.offset);
        byte[] window = readUpTo(source, hit.offset, max);
        PngParse parsed = pngParse(window);
        if (parsed.ok) {
            CarveCandidate c = base(hit, parsed.length, true, true, true);
            c.decoderName = "png-crc32";
            c.decoder = true;
            int n = (int) Math.min(parsed.length, window.length);
            c.entropyMillibits = entropyMillibits(window, n);
            c.entropyMatch = entropyMatches("high", c.entropyMillibits);
            c.sha256 = sha256(Arrays.copyOf(window, n));
            finishScore(c, "high");
            c.disposition = CarveCandidate.Disposition.ACCEPTED;
            c.reason = "PNG chunks and CRCs validated through IEND.";
            return c;
        }
        return pngBifragment(hit, window, parsed);
    }

    private CarveCandidate pngBifragment(Hit hit, byte[] window, PngParse failed) {
        CarveCandidate refused = base(hit, 0, true, false, false);
        refused.disposition = CarveCandidate.Disposition.REJECTED;
        refused.reason = "PNG structure failed: " + failed.reason;
        finishScore(refused, "high");
        byte[] iend = hexToBytes("0000000049454E44AE426082");
        List<Integer> ends = findMarker(window, 8, iend);
        int passes = 0;
        byte[] chosen = null;
        int tail = -1;
        for (int at : ends) {
            if (failed.goodEnd <= 8 || at < failed.goodEnd) {
                continue;
            }
            byte[] joined = join(window, failed.goodEnd, at, at + iend.length);
            PngParse again = pngParse(joined);
            if (again.ok) {
                passes++;
                chosen = joined;
                tail = at;
            }
        }
        if (passes != 1 || chosen == null) {
            refused.reason = passes == 0
                    ? "No CRC-valid PNG bifragment join."
                    : "PNG bifragment refused: more than one CRC-valid join.";
            return refused;
        }
        CarveCandidate c = base(hit, chosen.length, true, true, true);
        c.reassembled = true;
        c.fragment2Offset = hit.offset + tail;
        c.decoder = true;
        c.decoderName = "png-crc32-join";
        c.sha256 = sha256(chosen);
        c.derivative = chosen;
        c.entropyMillibits = entropyMillibits(chosen, chosen.length);
        c.entropyMatch = entropyMatches("high", c.entropyMillibits);
        finishScore(c, "high");
        c.disposition = CarveCandidate.Disposition.REASSEMBLED;
        c.reason = "Exactly one PNG join passed chunk CRC validation. Gap bytes were not copied into the derivative.";
        return c;
    }

    private CarveCandidate gif(ByteSource source, Hit hit, long limit) throws IOException {
        byte[] window = readUpTo(source, hit.offset, (int) Math.min(WINDOW, limit - hit.offset));
        if (window.length < 13 || window[6] == 0 && window[7] == 0) {
            return reject(hit, "GIF logical screen is missing or empty.");
        }
        int trailer = indexOf(window, 13, window.length, new byte[]{0x00, 0x3B});
        if (trailer < 0) {
            return reject(hit, "GIF trailer 00 3B was not found in the scan window.");
        }
        CarveCandidate c = base(hit, trailer + 2, true, true, false);
        c.decoderName = "none";
        c.reason = "GIF trailer is a weak end marker. No LZW decoder was applied.";
        finishScore(c, "high");
        c.disposition = CarveCandidate.Disposition.ACCEPTED;
        return c;
    }

    private CarveCandidate pdf(ByteSource source, Hit hit, long limit) throws IOException {
        byte[] window = readUpTo(source, hit.offset, (int) Math.min(WINDOW, limit - hit.offset));
        int eof = lastIndexOf(window, "%%EOF".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        if (eof < 0) {
            return reject(hit, "PDF %%EOF was not found. Magic alone was not accepted.");
        }
        boolean startxref = indexOf(window, 0, window.length, "startxref".getBytes(java.nio.charset.StandardCharsets.US_ASCII)) >= 0;
        CarveCandidate c = base(hit, eof + 5, true, true, false);
        c.decoder = false;
        c.decoderName = startxref ? "startxref-present" : "none";
        c.reason = startxref ? "%%EOF and startxref present." : "%%EOF present. startxref was not found in the window.";
        finishScore(c, "mixed");
        c.disposition = CarveCandidate.Disposition.ACCEPTED;
        return c;
    }

    private CarveCandidate zip(ByteSource source, Hit hit, long limit) throws IOException {
        byte[] window = readUpTo(source, hit.offset, (int) Math.min(WINDOW, limit - hit.offset));
        int eocd = lastIndexOf(window, hexToBytes("504B0506"));
        if (eocd < 22 || eocd + 22 > window.length) {
            return reject(hit, "ZIP end of central directory was not found in the scan window.");
        }
        int comment = le16(window, eocd + 20);
        if (eocd + 22 + comment > window.length) {
            return reject(hit, "ZIP EOCD comment length runs past the window.");
        }
        long cd = le32(window, eocd + 16);
        if (cd < 0 || cd >= eocd || cd + 4 > window.length) {
            return reject(hit, "ZIP central-directory offset is inconsistent with the EOCD.");
        }
        if (window[(int) cd] != 0x50 || window[(int) cd + 1] != 0x4B || window[(int) cd + 2] != 0x01 || window[(int) cd + 3] != 0x02) {
            return reject(hit, "Bytes at the central-directory offset are not a central-directory header.");
        }
        CarveCandidate c = base(hit, eocd + 22 + comment, true, true, true);
        c.decoderName = "eocd-cd";
        String names = new String(window, 0, window.length, java.nio.charset.StandardCharsets.ISO_8859_1);
        if (names.contains("word/document.xml")) {
            c.format = "DOCX";
            c.extension = "docx";
        } else if (names.contains("xl/workbook.xml")) {
            c.format = "XLSX";
            c.extension = "xlsx";
        } else if (names.contains("ppt/presentation.xml")) {
            c.format = "PPTX";
            c.extension = "pptx";
        }
        c.reason = "EOCD and central-directory signature agree.";
        finishScore(c, "high");
        c.disposition = CarveCandidate.Disposition.ACCEPTED;
        return c;
    }

    private CarveCandidate mp4(ByteSource source, Hit hit, long limit) throws IOException {
        if (hit.offset + 8 > limit) {
            return reject(hit, "MP4 header is truncated.");
        }
        byte[] header = readUpTo(source, hit.offset, 8);
        if (header.length < 8 || !Arrays.equals(Arrays.copyOfRange(header, 4, 8), "ftyp".getBytes(java.nio.charset.StandardCharsets.US_ASCII))) {
            return reject(hit, "MP4 ftyp box is missing.");
        }
        long cursor = hit.offset;
        int boxes = 0;
        long end = hit.offset;
        while (cursor + 8 <= limit && boxes < 4096 && cursor - hit.offset < WINDOW) {
            byte[] box = readUpTo(source, cursor, 8);
            if (box.length < 8) {
                break;
            }
            long boxSize = u32(box, 0);
            if (boxSize < 8) {
                return reject(hit, "MP4 box size is smaller than a header.");
            }
            if (cursor + boxSize > source.size()) {
                return reject(hit, "MP4 box size runs past the evidence.");
            }
            cursor += boxSize;
            end = cursor;
            boxes++;
            if (cursor - hit.offset > WINDOW) {
                break;
            }
        }
        if (boxes < 1) {
            return reject(hit, "MP4 box walk produced no boxes.");
        }
        CarveCandidate c = base(hit, end - hit.offset, true, true, false);
        c.decoderName = "box-sizes";
        c.reason = "Walked " + boxes + " top-level MP4 boxes. No sample decoder was applied.";
        finishScore(c, "high");
        c.disposition = CarveCandidate.Disposition.ACCEPTED;
        return c;
    }

    private CarveCandidate sqlite(ByteSource source, Hit hit, long limit) throws IOException {
        byte[] header = readUpTo(source, hit.offset, 100);
        if (header.length < 100) {
            return reject(hit, "SQLite header is truncated.");
        }
        int pageSize = u16(header, 16);
        if (pageSize == 1) {
            pageSize = 65536;
        }
        long pages = u32(header, 28);
        if (pageSize < 512 || pageSize > 65536 || Integer.bitCount(pageSize) != 1 || pages <= 0) {
            return reject(hit, "SQLite page size or page count is not usable.");
        }
        long length = (long) pageSize * pages;
        if (hit.offset + length > limit && hit.offset + length > source.size()) {
            return reject(hit, "SQLite declared length exceeds the evidence.");
        }
        CarveCandidate c = base(hit, length, true, true, false);
        c.decoderName = "header-page-count";
        c.reason = "Length is page size times page count from the database header.";
        finishScore(c, "low");
        c.disposition = CarveCandidate.Disposition.ACCEPTED;
        return c;
    }

    private CarveCandidate bmp(ByteSource source, Hit hit, long limit) throws IOException {
        byte[] header = readUpTo(source, hit.offset, 32);
        if (header.length < 18) {
            return reject(hit, "BMP header is truncated.");
        }
        long fileSize = le32(header, 2);
        long pixelOff = le32(header, 10);
        long dib = le32(header, 14);
        boolean dibOk = dib == 12 || dib == 40 || dib == 52 || dib == 56 || dib == 108 || dib == 124;
        if (fileSize < 54 || pixelOff < 14 || pixelOff > fileSize || !dibOk) {
            return reject(hit, "BMP size fields do not agree. Magic alone was not accepted.");
        }
        if (hit.offset + fileSize > source.size()) {
            return reject(hit, "BMP declared size exceeds the evidence.");
        }
        CarveCandidate c = base(hit, fileSize, true, true, false);
        c.reason = "BMP file size, pixel offset, and DIB size agree.";
        finishScore(c, "low");
        c.disposition = CarveCandidate.Disposition.ACCEPTED;
        return c;
    }

    private CarveCandidate gzip(ByteSource source, Hit hit, long limit) throws IOException {
        int max = (int) Math.min(WINDOW, limit - hit.offset);
        byte[] window = readUpTo(source, hit.offset, max);
        try {
            ByteArrayInputStream raw = new ByteArrayInputStream(window);
            try (GZIPInputStream in = new GZIPInputStream(raw)) {
                byte[] sink = new byte[8192];
                while (in.read(sink) >= 0) {
                    // consume the member
                }
            }
            int consumed = window.length - raw.available();
            if (consumed < 18) {
                return reject(hit, "GZIP inflate consumed too little input.");
            }
            CarveCandidate c = base(hit, consumed, true, true, true);
            c.decoderName = "gzip-inflate";
            c.entropyMillibits = entropyMillibits(window, consumed);
            c.entropyMatch = entropyMatches("high", c.entropyMillibits);
            c.sha256 = sha256(java.util.Arrays.copyOf(window, consumed));
            c.reason = "Inflater consumed a complete GZIP member (" + consumed + " bytes).";
            finishScore(c, "high");
            c.disposition = CarveCandidate.Disposition.ACCEPTED;
            return c;
        } catch (IOException ex) {
            return reject(hit, "GZIP inflate failed: " + ex.getMessage());
        }
    }

    private CarveCandidate riff(ByteSource source, Hit hit, long limit) throws IOException {
        byte[] header = readUpTo(source, hit.offset, 12);
        if (header.length < 12) {
            return reject(hit, "RIFF header is truncated.");
        }
        String form = new String(header, 8, 4, java.nio.charset.StandardCharsets.US_ASCII);
        long size = le32(header, 4);
        long total = 8 + size;
        if (size < 4 || hit.offset + total > source.size()) {
            return reject(hit, "RIFF size is not usable.");
        }
        if (!"WAVE".equals(form) && !"WEBP".equals(form)) {
            return reject(hit, "RIFF form '" + form + "' is not WAV or WebP in this carver.");
        }
        CarveCandidate c = base(hit, total, true, true, false);
        c.format = "WAVE".equals(form) ? "WAV" : "WebP";
        c.extension = "WAVE".equals(form) ? "wav" : "webp";
        c.reason = "RIFF form " + form + " and size field agree.";
        finishScore(c, "mixed");
        c.disposition = CarveCandidate.Disposition.ACCEPTED;
        return c;
    }

    private CarveCandidate pe(ByteSource source, Hit hit) throws IOException {
        byte[] header = readUpTo(source, hit.offset, 0x40 + 4);
        if (header.length < 0x40) {
            return reject(hit, "PE DOS header is truncated.");
        }
        long lfanew = le32(header, 0x3C);
        if (lfanew < 0x40 || lfanew > 1024 * 1024) {
            return reject(hit, "PE e_lfanew is not credible. MZ alone was not accepted.");
        }
        byte[] sig = readUpTo(source, hit.offset + lfanew, 4);
        if (sig.length < 4 || sig[0] != 'P' || sig[1] != 'E' || sig[2] != 0 || sig[3] != 0) {
            return reject(hit, "PE\\0\\0 was not at e_lfanew.");
        }
        CarveCandidate c = base(hit, 0, true, true, false);
        c.exactLength = false;
        c.length = 0;
        c.disposition = CarveCandidate.Disposition.IDENTIFIED;
        c.reason = "PE signature corroborated. Section table length was not walked, so the file was not extracted.";
        finishScore(c, "mixed");
        return c;
    }

    private CarveCandidate elf(ByteSource source, Hit hit) throws IOException {
        byte[] header = readUpTo(source, hit.offset, 20);
        if (header.length < 20) {
            return reject(hit, "ELF header is truncated.");
        }
        int cls = header[4] & 0xFF;
        int data = header[5] & 0xFF;
        if ((cls != 1 && cls != 2) || (data != 1 && data != 2)) {
            return reject(hit, "ELF class or endianness is not valid.");
        }
        CarveCandidate c = base(hit, 0, true, true, false);
        c.exactLength = false;
        c.length = 0;
        c.disposition = CarveCandidate.Disposition.IDENTIFIED;
        c.reason = "ELF identification bytes checked. Section length was not established, so the file was not extracted.";
        finishScore(c, "mixed");
        return c;
    }

    private CarveCandidate tar(ByteSource source, Hit hit) throws IOException {
        if (hit.offset < 0) {
            return reject(hit, "TAR header starts before the evidence.");
        }
        byte[] header = readUpTo(source, hit.offset, 512);
        if (header.length < 512) {
            return reject(hit, "TAR header is truncated.");
        }
        if (!tarChecksum(header)) {
            return reject(hit, "TAR ustar checksum failed.");
        }
        CarveCandidate c = base(hit, 512, true, true, false);
        c.exactLength = false;
        c.length = 512;
        c.disposition = CarveCandidate.Disposition.IDENTIFIED;
        c.reason = "ustar header checksum matched. The member run length was not established, so only the header was identified.";
        finishScore(c, "mixed");
        return c;
    }

    private CarveCandidate rtf(ByteSource source, Hit hit, long limit) throws IOException {
        byte[] window = readUpTo(source, hit.offset, (int) Math.min(2 * 1024 * 1024, limit - hit.offset));
        int depth = 0;
        boolean started = false;
        for (int i = 0; i < window.length; i++) {
            byte b = window[i];
            if (b == '{') {
                depth++;
                started = true;
            } else if (b == '}') {
                depth--;
                if (started && depth == 0) {
                    CarveCandidate c = base(hit, i + 1, true, true, false);
                    c.reason = "RTF brace group closed.";
                    finishScore(c, "low");
                    c.disposition = CarveCandidate.Disposition.ACCEPTED;
                    return c;
                }
            }
        }
        return reject(hit, "RTF group did not close inside the window.");
    }

    private CarveCandidate html(ByteSource source, Hit hit, long limit) throws IOException {
        byte[] window = readUpTo(source, hit.offset, (int) Math.min(WINDOW, limit - hit.offset));
        String text = new String(window, java.nio.charset.StandardCharsets.ISO_8859_1).toLowerCase(Locale.ROOT);
        int end = text.lastIndexOf("</html>");
        if (end < 0) {
            return reject(hit, "HTML end tag was not found. A doctype or <html> alone was not accepted.");
        }
        CarveCandidate c = base(hit, end + "</html>".length(), true, true, false);
        c.reason = "HTML end tag found. This is a textual bound, not a parser.";
        finishScore(c, "low");
        c.disposition = CarveCandidate.Disposition.ACCEPTED;
        return c;
    }

    private void buildMediaMap(ByteSource source, long limit, CarveReport report) throws IOException {
        int block = 64 * 1024;
        String previous = "";
        long regionStart = 0;
        byte[] buf = new byte[block];
        for (long off = 0; off < limit; off += block) {
            int n = readFully(source, off, buf, 0, (int) Math.min(block, limit - off));
            if (n <= 0) {
                break;
            }
            boolean zero = true;
            for (int i = 0; i < n; i++) {
                if (buf[i] != 0) {
                    zero = false;
                    break;
                }
            }
            String kind = zero ? "ZERO" : "DATA";
            if (!kind.equals(previous)) {
                if (!previous.isEmpty()) {
                    report.media.add(new CarveReport.MediaRegion(regionStart, off - regionStart, previous));
                }
                previous = kind;
                regionStart = off;
            }
        }
        if (!previous.isEmpty()) {
            report.media.add(new CarveReport.MediaRegion(regionStart, limit - regionStart, previous));
        }
        byte[] boot = readUpTo(source, 0, 512);
        String fs = filesystemHint(boot);
        if (!fs.isEmpty()) {
            report.media.add(new CarveReport.MediaRegion(0, 512, "FILESYSTEM_SIGNATURE:" + fs));
        }
        for (CarveCandidate c : report.candidates) {
            if ((c.disposition == CarveCandidate.Disposition.ACCEPTED || c.disposition == CarveCandidate.Disposition.REASSEMBLED)
                    && c.length > 0) {
                report.media.add(new CarveReport.MediaRegion(c.offset, c.length, "CARVED:" + c.format));
            }
        }
    }

    static String filesystemHint(byte[] sector) {
        if (sector.length >= 11) {
            String oem = new String(sector, 3, Math.min(8, sector.length - 3), java.nio.charset.StandardCharsets.US_ASCII);
            if (oem.startsWith("NTFS")) {
                return "NTFS";
            }
            if (oem.startsWith("EXFAT")) {
                return "EXFAT";
            }
            if (oem.startsWith("MSDOS") || oem.startsWith("MSWIN") || oem.startsWith("mkfs.fat")) {
                return "FAT";
            }
        }
        return "";
    }

    private static void resolveOverlaps(CarveReport report) {
        List<CarveCandidate> live = new ArrayList<>();
        for (CarveCandidate c : report.candidates) {
            if (c.disposition == CarveCandidate.Disposition.ACCEPTED || c.disposition == CarveCandidate.Disposition.REASSEMBLED) {
                live.add(c);
            }
        }
        for (CarveCandidate c : live) {
            boolean overlap = false;
            for (CarveCandidate other : live) {
                if (other == c || other.scoreBasisPoints < c.scoreBasisPoints) {
                    continue;
                }
                if (other == c) {
                    continue;
                }
                long a1 = c.offset;
                long a2 = c.offset + Math.max(c.length, 1);
                long b1 = other.offset;
                long b2 = other.offset + Math.max(other.length, 1);
                if (a1 < b2 && b1 < a2 && other.scoreBasisPoints >= c.scoreBasisPoints && other != c) {
                    if (other.scoreBasisPoints > c.scoreBasisPoints) {
                        overlap = true;
                    }
                }
            }
            if (!overlap) {
                c.components.put("no_overlap", 500);
                if (!c.reassembled) {
                    c.scoreBasisPoints = Math.min(10000, c.scoreBasisPoints + 500);
                } else {
                    c.scoreBasisPoints = Math.min(REASSEMBLY_CAP, c.scoreBasisPoints + 500);
                }
                c.bucket = bucket(c);
            } else {
                c.components.put("no_overlap", 0);
                c.reason = c.reason + " Overlaps a higher-scoring candidate.";
            }
        }
    }

    private static CarveCandidate base(Hit hit, long length, boolean header, boolean structure, boolean decoder) {
        CarveCandidate c = new CarveCandidate();
        c.format = hit.sig.name;
        c.extension = hit.sig.ext;
        c.offset = hit.offset;
        c.length = length;
        c.header = header;
        c.structure = structure;
        c.exactLength = length > 0;
        c.decoder = decoder;
        return c;
    }

    private static CarveCandidate reject(Hit hit, String reason) {
        CarveCandidate c = base(hit, 0, true, false, false);
        c.exactLength = false;
        c.disposition = CarveCandidate.Disposition.REJECTED;
        c.reason = reason;
        finishScore(c, "mixed");
        return c;
    }

    private static CarveCandidate identifiedOrReject(Hit hit, String reason) {
        CarveCandidate c = base(hit, 0, true, false, false);
        c.exactLength = false;
        c.disposition = CarveCandidate.Disposition.REJECTED;
        c.reason = reason;
        finishScore(c, "mixed");
        return c;
    }

    private static void finishScore(CarveCandidate c, String entropyProfile) {
        int header = c.header ? 2000 : 0;
        int length = c.exactLength ? 1500 : 0;
        int structure = c.structure ? 1500 : 0;
        int decoder = c.decoder ? 2500 : 0;
        if (!c.decoder && c.decoderName != null && !c.decoderName.isBlank() && !"none".equals(c.decoderName)) {
            decoder = 1000;
        }
        c.components.put("header", header);
        c.components.put("exact_length", length);
        c.components.put("structure", structure);
        c.components.put("decoder", decoder);
        int entropy = 0;
        if (c.entropyMillibits == 0 && c.length > 0) {
            // entropy filled by caller when bytes are available; leave 0 if unknown
        }
        if (c.entropyMatch) {
            entropy = 1000;
        }
        c.components.put("entropy", entropy);
        c.components.put("filesystem_metadata", 0);
        c.components.put("fragmentation", c.reassembled ? -1 : 0);
        int score = header + length + structure + decoder + entropy;
        if (c.reassembled) {
            score = Math.min(score, REASSEMBLY_CAP);
        }
        c.scoreBasisPoints = Math.max(0, Math.min(10000, score));
        c.bucket = bucket(c);
        if (entropyProfile != null && c.entropyMillibits > 0) {
            c.entropyMatch = entropyMatches(entropyProfile, c.entropyMillibits);
            if (c.entropyMatch && !c.components.get("entropy").equals(1000)) {
                c.components.put("entropy", 1000);
                c.scoreBasisPoints = Math.min(c.reassembled ? REASSEMBLY_CAP : 10000, c.scoreBasisPoints + 1000);
                c.bucket = bucket(c);
            }
        }
    }

    private static String bucket(CarveCandidate c) {
        if (c.disposition == CarveCandidate.Disposition.REJECTED || !c.structure) {
            return "REJECT";
        }
        if (c.reassembled) {
            return c.scoreBasisPoints >= MEDIUM ? "MEDIUM" : "LOW";
        }
        if (c.scoreBasisPoints >= HIGH) {
            return "HIGH";
        }
        if (c.scoreBasisPoints >= MEDIUM) {
            return "MEDIUM";
        }
        return "LOW";
    }

    private static boolean entropyMatches(String profile, int millibits) {
        return switch (profile) {
            case "high" -> millibits >= 7000;
            case "low" -> millibits <= 6500;
            default -> millibits >= 2000;
        };
    }

    static int entropyMillibits(byte[] data, int length) {
        int n = Math.min(length, data.length);
        if (n <= 0) {
            return 0;
        }
        int[] counts = new int[256];
        int used = Math.min(n, 65536);
        for (int i = 0; i < used; i++) {
            counts[data[i] & 0xFF]++;
        }
        double bits = 0;
        for (int count : counts) {
            if (count == 0) {
                continue;
            }
            double p = count / (double) used;
            bits -= p * (Math.log(p) / Math.log(2));
        }
        return (int) Math.round(bits * 1000);
    }

    private static void applyImageIo(CarveCandidate c, byte[] bytes, String format) {
        c.entropyMillibits = entropyMillibits(bytes, bytes.length);
        c.entropyMatch = entropyMatches("high", c.entropyMillibits);
        c.sha256 = sha256(bytes);
        try {
            if (ImageIO.read(new ByteArrayInputStream(bytes)) != null) {
                c.decoderName = c.decoderName + "+ImageIO";
                if (!c.decoder) {
                    c.components.put("decoder", 1000);
                }
            }
        } catch (IOException ex) {
            c.reason = c.reason + " ImageIO did not decode (" + ex.getMessage() + ").";
        }
    }

    private static final class Hit {
        final Sig sig;
        final long offset;

        Hit(Sig sig, long offset) {
            this.sig = sig;
            this.offset = offset;
        }
    }

    private static final class Parse {
        boolean ok;
        int length;
        int cut;
        String reason = "";
    }

    private static final class PngParse {
        boolean ok;
        int length;
        int goodEnd;
        String reason = "";
    }

    static Parse jpegEnd(byte[] buf) {
        Parse parse = new Parse();
        if (buf.length < 4 || (buf[0] & 0xFF) != 0xFF || (buf[1] & 0xFF) != 0xD8) {
            parse.reason = "missing SOI";
            return parse;
        }
        int i = 2;
        while (i + 1 < buf.length) {
            if ((buf[i] & 0xFF) != 0xFF) {
                parse.reason = "expected marker";
                parse.cut = i;
                return parse;
            }
            while (i < buf.length && (buf[i] & 0xFF) == 0xFF) {
                i++;
            }
            if (i >= buf.length) {
                parse.reason = "truncated marker";
                parse.cut = buf.length;
                return parse;
            }
            int marker = buf[i++] & 0xFF;
            if (marker == 0xD9) {
                parse.ok = true;
                parse.length = i;
                return parse;
            }
            if (marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7)) {
                continue;
            }
            if (i + 1 >= buf.length) {
                parse.reason = "truncated segment";
                parse.cut = i;
                return parse;
            }
            int len = ((buf[i] & 0xFF) << 8) | (buf[i + 1] & 0xFF);
            if (len < 2 || i + len > buf.length) {
                parse.reason = "bad segment length";
                parse.cut = i;
                return parse;
            }
            i += len;
            if (marker == 0xDA) {
                while (i + 1 < buf.length) {
                    if ((buf[i] & 0xFF) == 0xFF) {
                        int next = buf[i + 1] & 0xFF;
                        if (next == 0x00 || (next >= 0xD0 && next <= 0xD7)) {
                            i += 2;
                            continue;
                        }
                        if (next == 0xFF) {
                            i++;
                            continue;
                        }
                        break;
                    }
                    i++;
                }
            }
        }
        parse.reason = "EOI not reached";
        parse.cut = Math.max(2, i);
        return parse;
    }

    static PngParse pngParse(byte[] buf) {
        PngParse parse = new PngParse();
        byte[] magic = hexToBytes("89504E470D0A1A0A");
        if (buf.length < magic.length || !Arrays.equals(Arrays.copyOf(buf, magic.length), magic)) {
            parse.reason = "missing PNG signature";
            return parse;
        }
        int p = 8;
        boolean ihdr = false;
        boolean idat = false;
        parse.goodEnd = 8;
        while (p + 12 <= buf.length) {
            int len = (int) u32(buf, p);
            if (len < 0 || p + 12L + len > buf.length) {
                parse.reason = "truncated chunk";
                return parse;
            }
            CRC32 crc = new CRC32();
            crc.update(buf, p + 4, 4 + len);
            long actual = u32(buf, p + 8 + len);
            if ((crc.getValue() & 0xFFFFFFFFL) != actual) {
                parse.reason = "chunk CRC mismatch";
                return parse;
            }
            String type = new String(buf, p + 4, 4, java.nio.charset.StandardCharsets.US_ASCII);
            if ("IHDR".equals(type)) {
                ihdr = true;
            }
            if ("IDAT".equals(type)) {
                idat = true;
            }
            p += 12 + len;
            parse.goodEnd = p;
            if ("IEND".equals(type)) {
                parse.ok = ihdr && idat;
                parse.length = p;
                if (!parse.ok) {
                    parse.reason = "PNG is missing IHDR or IDAT";
                }
                return parse;
            }
        }
        parse.reason = "IEND not reached";
        return parse;
    }

    private static boolean tarChecksum(byte[] header) {
        int stored = parseOctal(header, 148, 8);
        if (stored < 0) {
            return false;
        }
        int unsigned = 0;
        int signed = 0;
        for (int i = 0; i < 512; i++) {
            int value = (i >= 148 && i < 156) ? 0x20 : (header[i] & 0xFF);
            unsigned += value;
            int s = (i >= 148 && i < 156) ? 0x20 : header[i];
            signed += s;
        }
        return stored == unsigned || stored == signed;
    }

    private static int parseOctal(byte[] buf, int off, int len) {
        int value = 0;
        boolean any = false;
        for (int i = 0; i < len; i++) {
            int b = buf[off + i] & 0xFF;
            if (b == 0 || b == ' ') {
                if (any) {
                    break;
                }
                continue;
            }
            if (b < '0' || b > '7') {
                return -1;
            }
            any = true;
            value = (value << 3) + (b - '0');
        }
        return any ? value : -1;
    }

    private static byte[] join(byte[] src, int headEnd, int tailStart, int tailEnd) {
        if (headEnd < 0 || tailStart < headEnd || tailEnd > src.length || tailEnd < tailStart) {
            return new byte[0];
        }
        byte[] out = new byte[(headEnd) + (tailEnd - tailStart)];
        System.arraycopy(src, 0, out, 0, headEnd);
        System.arraycopy(src, tailStart, out, headEnd, tailEnd - tailStart);
        return out;
    }

    private static List<Integer> findMarker(byte[] buf, int from, byte[] needle) {
        List<Integer> hits = new ArrayList<>();
        int at = from;
        while (at < buf.length) {
            int found = indexOf(buf, at, buf.length, needle);
            if (found < 0 || hits.size() > 32) {
                break;
            }
            hits.add(found);
            at = found + 1;
        }
        return hits;
    }

    private static int alignUp(int value, int boundary) {
        int mod = value % boundary;
        return mod == 0 ? value : value + (boundary - mod);
    }

    public static byte[] readUpTo(ByteSource source, long offset, int max) throws IOException {
        if (max <= 0 || offset >= source.size()) {
            return new byte[0];
        }
        int n = (int) Math.min(max, source.size() - offset);
        byte[] buf = new byte[n];
        int got = readFully(source, offset, buf, 0, n);
        if (got < 0) {
            return new byte[0];
        }
        return got == n ? buf : Arrays.copyOf(buf, got);
    }

    private static int readFully(ByteSource source, long offset, byte[] dst, int dstOff, int len) throws IOException {
        int got = 0;
        while (got < len) {
            int n = source.read(offset + got, dst, dstOff + got, len - got);
            if (n < 0) {
                break;
            }
            if (n == 0) {
                break;
            }
            got += n;
        }
        return got == 0 ? -1 : got;
    }

    static int indexOf(byte[] hay, int from, int to, byte[] needle) {
        int last = to - needle.length;
        for (int i = Math.max(0, from); i <= last; i++) {
            boolean match = true;
            for (int j = 0; j < needle.length; j++) {
                if (hay[i + j] != needle[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return i;
            }
        }
        return -1;
    }

    private static int lastIndexOf(byte[] hay, byte[] needle) {
        int last = -1;
        int from = 0;
        while (from <= hay.length - needle.length) {
            int at = indexOf(hay, from, hay.length, needle);
            if (at < 0) {
                break;
            }
            last = at;
            from = at + 1;
        }
        return last;
    }

    private static int u16(byte[] buf, int off) {
        return ((buf[off] & 0xFF) << 8) | (buf[off + 1] & 0xFF);
    }

    private static long u32(byte[] buf, int off) {
        return ((buf[off] & 0xFFL) << 24) | ((buf[off + 1] & 0xFFL) << 16)
                | ((buf[off + 2] & 0xFFL) << 8) | (buf[off + 3] & 0xFFL);
    }

    private static int le16(byte[] buf, int off) {
        return (buf[off] & 0xFF) | ((buf[off + 1] & 0xFF) << 8);
    }

    private static long le32(byte[] buf, int off) {
        return (buf[off] & 0xFFL) | ((buf[off + 1] & 0xFFL) << 8)
                | ((buf[off + 2] & 0xFFL) << 16) | ((buf[off + 3] & 0xFFL) << 24);
    }

    static byte[] hexToBytes(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    public static String sha256(byte[] data) {
        try {
            byte[] dig = MessageDigest.getInstance("SHA-256").digest(data);
            StringBuilder sb = new StringBuilder(dig.length * 2);
            for (byte b : dig) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException ex) {
            return "";
        }
    }

    private static void publish(Consumer<Progress> progress, CarveReport report, long bytes, String region) {
        if (progress == null) {
            return;
        }
        Progress p = new Progress();
        p.bytes = bytes;
        p.total = report.sourceSize;
        p.candidates = report.candidates.size();
        p.validated = report.accepted + report.reassembled + report.identified;
        p.rejected = report.rejected;
        p.region = region;
        progress.accept(p);
    }
}
