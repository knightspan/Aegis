package org.sleuthkit.autopsy.aegis.audit;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Ed25519 signatures over a canonical payload. A valid signature makes the
 * payload cryptographically verifiable. It does not make the operation tamper-proof.
 */
public final class ReportSigner {

    public static final class Signed {
        public String algorithm = "Ed25519";
        public String payloadSha256 = "";
        public String signatureBase64 = "";
        public String publicKeyBase64 = "";
        public boolean verified;
        public String keyPath = "";
    }

    public static final class Verification {
        public boolean valid;
        public String message = "";
        public String payloadSha256 = "";
        public String keyFingerprint = "";
    }

    public Signed sign(String payload) throws IOException, GeneralSecurityException {
        Path dir = Path.of(System.getProperty("user.home"), ".aegis");
        Files.createDirectories(dir);
        Path priv = dir.resolve("report-ed25519.pkcs8");
        Path pub = dir.resolve("report-ed25519.x509");
        KeyPair pair = loadOrCreate(priv, pub);
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(pair.getPrivate());
        byte[] data = payload.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        signature.update(data);
        byte[] sig = signature.sign();
        Signed signed = new Signed();
        signed.payloadSha256 = sha256(data);
        signed.signatureBase64 = Base64.getEncoder().encodeToString(sig);
        signed.publicKeyBase64 = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
        signed.keyPath = pub.toString();
        signed.verified = verify(data, sig, pair.getPublic());
        return signed;
    }

    public boolean verify(byte[] payload, byte[] signatureBytes, PublicKey publicKey) throws GeneralSecurityException {
        Signature signature = Signature.getInstance("Ed25519");
        signature.initVerify(publicKey);
        signature.update(payload);
        return signature.verify(signatureBytes);
    }

    /** Verify the signed fields embedded in an AEGIS HTML sanitization report. */
    public Verification verifyHtmlReport(Path report) throws IOException {
        Verification result = new Verification();
        if (report == null || !Files.isRegularFile(report)) {
            result.message = "Report file does not exist.";
            return result;
        }
        String html = Files.readString(report, StandardCharsets.UTF_8);
        String payload = htmlField(html, "Canonical payload");
        String expectedHash = htmlField(html, "Payload SHA-256");
        String signatureText = htmlField(html, "Signature");
        String publicKeyText = htmlField(html, "Public key");
        if (payload == null || expectedHash == null || signatureText == null || publicKeyText == null) {
            result.message = "The selected file does not contain the AEGIS signed-report fields.";
            return result;
        }
        try {
            byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);
            result.payloadSha256 = sha256(payloadBytes);
            if (!result.payloadSha256.equalsIgnoreCase(expectedHash)) {
                result.message = "Payload SHA-256 does not match the signed report.";
                return result;
            }
            byte[] keyBytes = Base64.getDecoder().decode(publicKeyText.trim());
            PublicKey publicKey = KeyFactory.getInstance("Ed25519")
                    .generatePublic(new X509EncodedKeySpec(keyBytes));
            byte[] signatureBytes = Base64.getDecoder().decode(signatureText.trim());
            result.keyFingerprint = "SHA-256:" + sha256(keyBytes);
            result.valid = verify(payloadBytes, signatureBytes, publicKey);
            result.message = result.valid ? "Ed25519 signature and payload digest are valid."
                    : "Ed25519 signature verification failed.";
            return result;
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            result.valid = false;
            result.message = "Invalid signature fields: " + ex.getMessage();
            return result;
        }
    }

    private static String htmlField(String html, String label) {
        Pattern pattern = Pattern.compile("(?is)<tr>\\s*<th>" + Pattern.quote(label)
                + "</th>\\s*<td>(.*?)</td>\\s*</tr>");
        Matcher matcher = pattern.matcher(html);
        return matcher.find() ? unescapeHtml(matcher.group(1).trim()) : null;
    }

    private static String unescapeHtml(String value) {
        return value.replace("&quot;", "\"").replace("&gt;", ">")
                .replace("&lt;", "<").replace("&#39;", "'").replace("&amp;", "&");
    }

    private static KeyPair loadOrCreate(Path priv, Path pub) throws IOException, GeneralSecurityException {
        if (Files.isRegularFile(priv) && Files.isRegularFile(pub)) {
            KeyFactory factory = KeyFactory.getInstance("Ed25519");
            PrivateKey privateKey = factory.generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(priv)));
            PublicKey publicKey = factory.generatePublic(new X509EncodedKeySpec(Files.readAllBytes(pub)));
            return new KeyPair(publicKey, privateKey);
        }
        KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
        KeyPair pair = generator.generateKeyPair();
        Files.write(priv, pair.getPrivate().getEncoded());
        Files.write(pub, pair.getPublic().getEncoded());
        return pair;
    }

    private static String sha256(byte[] data) throws GeneralSecurityException {
        byte[] dig = java.security.MessageDigest.getInstance("SHA-256").digest(data);
        StringBuilder sb = new StringBuilder(dig.length * 2);
        for (byte b : dig) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
