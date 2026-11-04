import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.KDF;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.HKDFParameterSpec;
import javax.crypto.spec.HPKEParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Independent check of the Cloak protocol v1 test vectors, written against PROTOCOL.md without
 * sharing code with the generator. Uses only the JDK (27+): its HPKE, Ed25519, X25519,
 * ChaCha20-Poly1305 and HKDF implementations; HChaCha20, the canonical encoding, Merkle trees,
 * strict Ed25519 checks and Crockford base32 are re-implemented here.
 *
 * <p>Argon2id is not in the JDK, so the password-key step is taken from the vectors; everything
 * derived after it is recomputed.
 *
 * <p>Every refusal that rests on bytes (chain, signatures, flags, keys, commitments, checkpoints,
 * proofs, decryption, padding, codes) is reproduced here. A refusal that rests on a vault-log or
 * section rule (roles, request shapes, standing) is the implementations' to reproduce; for those
 * this check confirms the case is otherwise valid, so the rule is the only reason to refuse it.
 *
 * <p>Usage: {@code java VerifyVectors.java [vector-directory]}
 */
public final class VerifyVectors {
    private static final HexFormat HEX = HexFormat.of();
    private static int checks = 0;
    private static final List<String> failures = new ArrayList<>();

    private static final List<String> KINDS = List.of("vault_created", "member_added", "member_role_set",
            "member_removed", "member_keys_replaced", "key_rotated", "node_created", "node_shared", "node_unshared", "vault_deleted");
    private static final List<String> ROLES = List.of("viewer", "editor", "admin", "owner");
    private static final String NIL = "00000000-0000-0000-0000-000000000000";
    private static final BigInteger GROUP_ORDER = BigInteger.TWO.pow(252)
            .add(new BigInteger("27742317777372353535851937790883648493"));
    private static final BigInteger FIELD_PRIME = BigInteger.TWO.pow(255).subtract(BigInteger.valueOf(19));

    private static List<Object> identities = List.of();

    public static void main(String[] args) throws Exception {
        Path dir = Path.of(args.length > 0 ? args[0] : "test-vectors/v1");
        Map<String, Object> identity = read(dir, "identity.json");
        identities = list(identity, "identities");
        verifyEncoding(read(dir, "encoding.json"));
        verifyText(read(dir, "text.json"));
        Map<String, Object> kdf = read(dir, "kdf.json");
        verifyKdf(kdf);
        verifyAead(read(dir, "aead.json"), kdf);
        verifyHpke(read(dir, "hpke.json"), kdf);
        verifySignatures(read(dir, "signatures.json"));
        verifyIdentity(identity);
        Map<String, Object> log = read(dir, "vault-log.json");
        verifyVaultLog(log);
        verifyCheckpoints(read(dir, "checkpoints.json"));
        verifySections(read(dir, "sections.json"), log, kdf);
        if (failures.isEmpty()) {
            System.out.println("All " + checks + " checks passed.");
        } else {
            failures.forEach(f -> System.out.println("FAIL " + f));
            System.out.println(failures.size() + " of " + checks + " checks failed.");
            System.exit(1);
        }
    }

    // -----------------------------------------------------------------------------------------
    // encoding.json, text.json
    // -----------------------------------------------------------------------------------------

    private static void verifyEncoding(Map<String, Object> file) {
        for (Object o : list(file, "cases")) {
            Map<String, Object> c = map(o);
            check("encoding " + c.get("name"), hex(canonical(list(c, "fields"))), str(c, "expected"));
        }
    }

    private static void verifyText(Map<String, Object> file) throws Exception {
        for (Object o : list(file, "crockford")) {
            Map<String, Object> c = map(o);
            check("crockford " + c.get("input"), crockford(bytes(c, "input")), str(c, "expected"));
        }
        Map<String, Object> secret = map(file.get("secretKey"));
        byte[] sk = bytes(secret, "bytes");
        check("secret key code", "CS1-" + group(crockford(concat(sk, Arrays.copyOf(sha256(sk), 1))), 4), str(secret, "code"));
        check("secret key decode", hex(decodeCode("CS1", str(secret, "code"), 16, 1)), hex(sk));
        check("secret key decode lowercase", hex(decodeCode("CS1", str(secret, "lowercase"), 16, 1)), hex(sk));
        Map<String, Object> recovery = map(file.get("recoveryKey"));
        byte[] rk = bytes(recovery, "bytes");
        check("recovery key code", "CR1-" + group(crockford(concat(rk, Arrays.copyOf(sha256(rk), 3))), 4), str(recovery, "code"));
        check("recovery key decode", hex(decodeCode("CR1", str(recovery, "code"), 32, 3)), hex(rk));

        Map<String, Object> fp = map(file.get("fingerprint"));
        byte[] message = fingerprintMessage(map(fp.get("identity")));
        check("fingerprint message", hex(message), str(fp, "message"));
        check("fingerprint digest", hex(sha256(message)), str(fp, "digest"));
        check("fingerprint code", group(crockford(Arrays.copyOf(sha256(message), 20)), 4), str(fp, "code"));

        for (Object o : list(file, "negatives")) {
            Map<String, Object> n = map(o);
            boolean secretKind = str(n, "kind").equals("secretKey");
            String reason = null;
            try {
                decodeCode(secretKind ? "CS1" : "CR1", str(n, "code"), secretKind ? 16 : 32, secretKind ? 1 : 3);
            } catch (IllegalArgumentException e) {
                reason = "bad_code";
            }
            check("code refused " + n.get("name"), String.valueOf(reason), str(n, "reason"));
        }
    }

    /** Strict decoding of a prefixed code (PROTOCOL.md §10). */
    private static byte[] decodeCode(String prefix, String code, int length, int checksumLength) throws Exception {
        String normalized = code.toUpperCase().replaceAll("[\\s-]", "");
        if (!normalized.startsWith(prefix)) throw new IllegalArgumentException("prefix");
        String body = normalized.substring(prefix.length()).replace('O', '0').replace('I', '1').replace('L', '1');
        int total = length + checksumLength;
        if (body.length() != (total * 8 + 4) / 5) throw new IllegalArgumentException("length");
        BigInteger value = BigInteger.ZERO;
        for (char ch : body.toCharArray()) {
            int digit = CROCKFORD.indexOf(ch);
            if (digit < 0) throw new IllegalArgumentException("character");
            value = value.shiftLeft(5).or(BigInteger.valueOf(digit));
        }
        int padding = body.length() * 5 - total * 8;
        if (value.and(BigInteger.ONE.shiftLeft(padding).subtract(BigInteger.ONE)).signum() != 0) {
            throw new IllegalArgumentException("padding bits");
        }
        byte[] raw = value.shiftRight(padding).toByteArray();
        byte[] fixed = new byte[total];
        int n = Math.min(total, raw.length);
        System.arraycopy(raw, raw.length - n, fixed, total - n, n);
        byte[] data = Arrays.copyOf(fixed, length);
        if (!Arrays.equals(Arrays.copyOf(sha256(data), checksumLength), Arrays.copyOfRange(fixed, length, total))) {
            throw new IllegalArgumentException("checksum");
        }
        return data;
    }

    // -----------------------------------------------------------------------------------------
    // kdf.json, aead.json, hpke.json
    // -----------------------------------------------------------------------------------------

    private static void verifyKdf(Map<String, Object> file) throws Exception {
        Map<String, Object> m = map(file.get("masterKey"));
        byte[] userId = uuid(str(m, "userId"));
        check("password NFKC UTF-8",
                hex(Normalizer.normalize(str(m, "password"), Normalizer.Form.NFKC).getBytes(StandardCharsets.UTF_8)),
                str(m, "passwordNfkcUtf8"));
        Map<String, Object> params = map(m.get("kdf"));
        check("kdf parallelism", String.valueOf(num(params, "parallelism")), "1");
        check("kdf parameters accepted", String.valueOf(kdfAccepted(num(params, "memoryKib"), num(params, "iterations"))), "true");
        byte[] skm = hkdf(bytes(m, "secretKey"), userId, "cloak/v1/secret-key");
        check("secret key material", hex(skm), str(m, "secretKeyMaterial"));
        byte[] passwordKey = bytes(m, "passwordKey");
        byte[] master = new byte[32];
        for (int i = 0; i < 32; i++) master[i] = (byte) (passwordKey[i] ^ skm[i]);
        check("master key", hex(master), str(m, "masterKey"));
        check("private key bundle key", hex(hkdf(master, new byte[0], "cloak/v1/private-key-bundle")), str(m, "privateKeyBundleKey"));

        Map<String, Object> limits = map(file.get("kdfLimits"));
        for (Object o : list(limits, "accept")) {
            Map<String, Object> l = map(o);
            check("kdf accept " + l, String.valueOf(kdfAccepted(num(l, "memoryKib"), num(l, "iterations"))), "true");
        }
        for (Object o : list(limits, "refuse")) {
            Map<String, Object> l = map(o);
            check("kdf refuse " + l, String.valueOf(kdfAccepted(num(l, "memoryKib"), num(l, "iterations"))), "false");
        }

        for (Object o : list(file, "recoveryKeys")) {
            Map<String, Object> r = map(o);
            byte[] id = uuid(str(r, "userId"));
            String name = "recovery v" + r.get("keyVersion");
            check(name + " bundle key", hex(hkdf(bytes(r, "recoveryKey"), id, "cloak/v1/recovery-key-bundle")), str(r, "recoveryKeyBundleKey"));
            byte[] seed = hkdf(bytes(r, "recoveryKey"), id, "cloak/v1/recovery-sign");
            check(name + " signing seed", hex(seed), str(r, "recoverySigningSeed"));
            checkKeyPair(name + " signing key", seed, bytes(r, "recoverySigningPublicKey"));
        }

        for (Object o : list(file, "vaultKeys")) {
            Map<String, Object> v = map(o);
            byte[] key = bytes(v, "vaultKey");
            byte[] vaultId = uuid(str(v, "vaultId"));
            String name = "vault key v" + v.get("keyVersion");
            check(name + " content key", hex(hkdf(key, vaultId, "cloak/v1/vault-content")), str(v, "contentKey"));
            check(name + " wrap key", hex(hkdf(key, vaultId, "cloak/v1/vault-wrap")), str(v, "wrapKey"));
            check(name + " commitment", hex(commitment(key, str(v, "vaultId"), num(v, "keyVersion"))), str(v, "keyCommitment"));
        }

        Map<String, Object> mismatch = map(file.get("keyMismatch"));
        byte[] opened = commitment(bytes(mismatch, "openedKey"), str(mismatch, "vaultId"), num(mismatch, "keyVersion"));
        check("key mismatch: commitment of the opened key", hex(opened), str(mismatch, "itsCommitment"));
        check("key mismatch: refused", String.valueOf(!hex(opened).equals(str(mismatch, "committed"))), "true");

        for (Object o : list(file, "localState")) {
            Map<String, Object> l = map(o);
            check("local state record key", hex(hkdf(bytes(l, "localStateKey"), uuid(str(l, "userId")), "cloak/v1/local-state")), str(l, "recordKey"));
        }
    }

    private static boolean kdfAccepted(long memoryKib, long iterations) {
        return memoryKib >= 65536 && memoryKib <= 1048576 && iterations >= 2 && iterations <= 10;
    }

    private static byte[] commitment(byte[] vaultKey, String vaultId, long version) throws Exception {
        return hkdf(vaultKey, concat(uuid(vaultId), u32(version)), "cloak/v1/vault-key-commit");
    }

    private static void verifyAead(Map<String, Object> file, Map<String, Object> kdf) throws Exception {
        Map<String, Object> h = map(file.get("hchacha20"));
        check("hchacha20 KAT", hex(hchacha20(bytes(h, "key"), bytes(h, "nonce"))), str(h, "subkey"));

        for (Object o : list(file, "padding")) {
            Map<String, Object> p = map(o);
            byte[] in = bytes(p, "input");
            int length = ((in.length + 1 + 255) / 256) * 256;
            byte[] padded = Arrays.copyOf(in, length);
            padded[in.length] = (byte) 0x80;
            check("padding " + in.length, hex(padded), str(p, "padded"));
            check("unpadding " + in.length, hex(unpad(padded)), hex(in));
        }
        for (Object o : list(file, "paddingNegatives")) {
            Map<String, Object> p = map(o);
            String reason = null;
            try {
                unpad(bytes(p, "input"));
            } catch (IllegalArgumentException e) {
                reason = "bad_padding";
            }
            check("padding refused " + p.get("name"), String.valueOf(reason), str(p, "reason"));
        }

        Map<String, Object> ownerV1 = identity(str(map(kdf.get("masterKey")), "userId"), 1);
        Map<String, Object> ownerV2 = identity(str(map(kdf.get("masterKey")), "userId"), 2);
        List<Object> localState = list(kdf, "localState");
        String lsk1 = str(map(localState.get(0)), "localStateKey");
        String lsk2 = str(map(localState.get(1)), "localStateKey");
        String bundleKey = str(map(kdf.get("masterKey")), "privateKeyBundleKey");
        String userId = str(ownerV1, "userId");
        String bundleV1 = "01" + str(ownerV1, "encryptionPrivateKey") + str(ownerV1, "signingSeed") + lsk1 + "00".repeat(32);
        String bundleV2 = "01" + str(ownerV2, "encryptionPrivateKey") + str(ownerV2, "signingSeed") + lsk2 + lsk1
                + str(ownerV1, "encryptionPrivateKey");

        for (Object o : list(file, "cases")) {
            Map<String, Object> c = map(o);
            String name = str(c, "name");
            byte[] key = bytes(c, "key");
            byte[] nonce = bytes(c, "nonce");
            byte[] ad = bytes(c, "ad");
            byte[] plaintext = bytes(c, "plaintext");
            check("aead seal " + name, hex(concat(new byte[] {1}, nonce, xchacha(Cipher.ENCRYPT_MODE, key, nonce, ad, plaintext))), str(c, "blob"));
            check("aead open " + name, hex(openBlob(key, ad, bytes(c, "blob"))), hex(plaintext));
            switch (name) {
                case "private-key-bundle-v1" -> {
                    check(name + " key", hex(key), bundleKey);
                    check(name + " plaintext", hex(plaintext), bundleV1);
                    check(name + " ad", hex(ad), hex(bundleAd("cloak/v1/private-key-bundle", userId, 1)));
                }
                case "private-key-bundle-v2" -> {
                    check(name + " plaintext", hex(plaintext), bundleV2);
                    check(name + " ad", hex(ad), hex(bundleAd("cloak/v1/private-key-bundle", userId, 2)));
                }
                case "recovery-key-bundle-v1" -> {
                    check(name + " key", hex(key), str(map(list(kdf, "recoveryKeys").get(0)), "recoveryKeyBundleKey"));
                    check(name + " ad", hex(ad), hex(bundleAd("cloak/v1/recovery-key-bundle", userId, 1)));
                }
                case "section-content" -> {
                    check(name + " key", hex(key), str(map(list(kdf, "vaultKeys").get(0)), "contentKey"));
                    check(name + " content", hex(unpad(plaintext)), hex(str(c, "contentUtf8").getBytes(StandardCharsets.UTF_8)));
                }
                case "vault-previous" -> {
                    check(name + " key", hex(key), str(map(list(kdf, "vaultKeys").get(1)), "wrapKey"));
                    check(name + " plaintext", hex(plaintext), str(map(list(kdf, "vaultKeys").get(0)), "vaultKey"));
                }
                case "local-record" -> check(name + " key", hex(key), str(map(localState.get(0)), "recordKey"));
                default -> check("known aead case " + name, "unknown", "known");
            }
        }
        for (Object o : list(file, "negatives")) {
            Map<String, Object> n = map(o);
            check("aead refused " + n.get("name"), String.valueOf(failsToOpen(bytes(n, "key"), bytes(n, "ad"), bytes(n, "blob"))), "true");
        }
    }

    private static byte[] bundleAd(String label, String userId, long keyVersion) {
        return new Canonical().label(label).uuid(userId).u8(1).u32(keyVersion).bytes();
    }

    private static byte[] openBlob(byte[] key, byte[] ad, byte[] blob) throws Exception {
        if (blob[0] != 1 || blob.length < 41) throw new IllegalArgumentException("blob format");
        return xchacha(Cipher.DECRYPT_MODE, key, Arrays.copyOfRange(blob, 1, 25), ad, Arrays.copyOfRange(blob, 25, blob.length));
    }

    private static boolean failsToOpen(byte[] key, byte[] ad, byte[] blob) {
        try {
            openBlob(key, ad, blob);
            return false;
        } catch (Exception e) {
            return true;
        }
    }

    /** Strict unpadding (PROTOCOL.md §8.1). */
    private static byte[] unpad(byte[] data) {
        if (data.length == 0 || data.length % 256 != 0) throw new IllegalArgumentException("blocks");
        int i = data.length - 1;
        while (i >= 0 && data[i] == 0) i--;
        if (i < 0 || (data[i] & 0xff) != 0x80 || data.length - i > 256) throw new IllegalArgumentException("marker");
        return Arrays.copyOf(data, i);
    }

    private static void verifyHpke(Map<String, Object> file, Map<String, Object> kdf) throws Exception {
        for (Object o : list(file, "cases")) {
            Map<String, Object> c = map(o);
            String name = str(c, "name");
            byte[] blob = bytes(c, "blob");
            byte[] enc = Arrays.copyOfRange(blob, 1, 33);
            check("hpke format " + name, String.valueOf(blob[0]), "1");
            check("hpke enc " + name, hex(enc), str(c, "enc"));
            check("hpke pkR " + name, hex(x25519(bytes(c, "skR"), basePoint())), str(c, "pkR"));
            check("hpke open (JDK) " + name, hex(hpkeOpen(bytes(c, "skR"), bytes(c, "info"), bytes(c, "aad"), blob)), str(c, "plaintext"));
            check("hpke ecdh " + name, hex(x25519(bytes(c, "skE"), bytes(c, "pkR"))), hex(x25519(bytes(c, "skR"), enc)));
            check("hpke info " + name, new String(bytes(c, "info"), StandardCharsets.UTF_8), "cloak/v1/vault-key");
        }
        for (Object o : list(file, "negatives")) {
            Map<String, Object> n = map(o);
            boolean refused;
            try {
                hpkeOpen(bytes(n, "skR"), bytes(n, "info"), bytes(n, "aad"), bytes(n, "blob"));
                refused = false;
            } catch (Exception e) {
                refused = true;
            }
            check("hpke refused " + n.get("name"), String.valueOf(refused), "true");
        }
    }

    private static byte[] hpkeOpen(byte[] skR, byte[] info, byte[] aad, byte[] blob) throws Exception {
        Cipher cipher = Cipher.getInstance("HPKE");
        HPKEParameterSpec spec = HPKEParameterSpec.of(
                        HPKEParameterSpec.KEM_DHKEM_X25519_HKDF_SHA256,
                        HPKEParameterSpec.KDF_HKDF_SHA256,
                        HPKEParameterSpec.AEAD_CHACHA20_POLY1305)
                .withInfo(info)
                .withEncapsulation(Arrays.copyOfRange(blob, 1, 33));
        cipher.init(Cipher.DECRYPT_MODE, x25519Private(skR), spec);
        cipher.updateAAD(aad);
        return cipher.doFinal(Arrays.copyOfRange(blob, 33, blob.length));
    }

    private static byte[] basePoint() {
        byte[] u = new byte[32];
        u[0] = 9;
        return u;
    }

    // -----------------------------------------------------------------------------------------
    // signatures.json, identity.json
    // -----------------------------------------------------------------------------------------

    private static void verifySignatures(Map<String, Object> file) throws Exception {
        for (Object o : list(file, "cases")) {
            Map<String, Object> c = map(o);
            String reason = strictVerify(bytes(c, "publicKey"), bytes(c, "message"), bytes(c, "signature"));
            check("strict ed25519 " + c.get("name"), String.valueOf(reason), String.valueOf(c.get("reason")));
        }
    }

    /** Strict Ed25519 (PROTOCOL.md §2); null when valid, else the reason. */
    private static String strictVerify(byte[] publicKey, byte[] message, byte[] blob) throws Exception {
        if (blob.length != 65 || blob[0] != 1) return "bad_signature";
        byte[] signature = Arrays.copyOfRange(blob, 1, 65);
        if (littleEndian(Arrays.copyOfRange(signature, 32, 64)).compareTo(GROUP_ORDER) >= 0) return "non_canonical_signature";
        if (yOf(Arrays.copyOf(signature, 32)).compareTo(FIELD_PRIME) >= 0) return "non_canonical_signature";
        if (yOf(publicKey).compareTo(FIELD_PRIME) >= 0) return "non_canonical_key";
        if (smallOrder(publicKey)) return "small_order_key";
        try {
            PublicKey pk = KeyFactory.getInstance("Ed25519").generatePublic(
                    new X509EncodedKeySpec(concat(HEX.parseHex("302a300506032b6570032100"), publicKey)));
            Signature verify = Signature.getInstance("Ed25519");
            verify.initVerify(pk);
            verify.update(message);
            return verify.verify(signature) ? null : "bad_signature";
        } catch (Exception e) {
            return "bad_signature";
        }
    }

    /** Whether a point is one of the eight small-order points, by its y coordinate and sign bit. */
    private static boolean smallOrder(byte[] point) {
        Set<String> encodings = Set.of(
                "0100000000000000000000000000000000000000000000000000000000000000",
                "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000080",
                "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
                "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
                "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
                "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85");
        return encodings.contains(hex(point));
    }

    private static BigInteger littleEndian(byte[] b) {
        byte[] reversed = new byte[b.length];
        for (int i = 0; i < b.length; i++) reversed[i] = b[b.length - 1 - i];
        return new BigInteger(1, reversed);
    }

    private static BigInteger yOf(byte[] point) {
        return littleEndian(point).and(BigInteger.ONE.shiftLeft(255).subtract(BigInteger.ONE));
    }

    private static void verifyIdentity(Map<String, Object> file) throws Exception {
        // §5.0: userId = UUIDv5(userNamespace, UTF-8 host user id).
        String namespace = uuidV5("6ba7b811-9dad-11d1-80b4-00c04fd430c8", "urn:cloak:v1:user".getBytes(StandardCharsets.UTF_8));
        check("user namespace", namespace, str(file, "userNamespace"));
        for (Object o : list(file, "userIds")) {
            Map<String, Object> u = map(o);
            check("user id " + str(u, "userId"), uuidV5(namespace, str(u, "hostUserId").getBytes(StandardCharsets.UTF_8)), str(u, "userId"));
        }
        for (Object o : list(file, "nodeIds")) {
            Map<String, Object> n = map(o);
            byte[] nameBytes = new Canonical().label("cloak/v1/node").uuid(str(n, "homeVaultId")).str(str(n, "nodeKey")).bytes();
            check("node name " + str(n, "nodeId"), hex(nameBytes), str(n, "name"));
            check("node id " + str(n, "nodeId"), uuidV5(str(n, "ownerUserId"), nameBytes), str(n, "nodeId"));
        }
        Map<String, Object> credentials = map(file.get("credentials"));
        Map<String, Object> signer = map(credentials.get("signer"));
        Map<String, Object> signerKeys = null;
        for (Object o : list(file, "identities")) {
            Map<String, Object> id = map(o);
            if (str(id, "userId").equals(str(signer, "userId")) && num(id, "keyVersion") == num(signer, "keyVersion")) signerKeys = id;
        }
        for (String statement : List.of("change", "deletion")) {
            Map<String, Object> s = map(credentials.get(statement));
            check("credentials " + statement + " fields", hex(canonical(list(s, "fields"))), str(s, "message"));
            check("credentials " + statement + " signature",
                    String.valueOf(strictVerify(bytes(signerKeys, "signingPublicKey"), bytes(s, "message"), bytes(s, "signature"))), "null");
        }
        for (Object o : list(file, "identities")) {
            Map<String, Object> id = map(o);
            String name = "identity " + id.get("name");
            check(name + " x25519 public", hex(x25519(bytes(id, "encryptionPrivateKey"), basePoint())), str(id, "encryptionPublicKey"));
            checkKeyPair(name + " signing key", bytes(id, "signingSeed"), bytes(id, "signingPublicKey"));
            byte[] recoverySeed = hkdf(bytes(id, "recoveryKey"), uuid(str(id, "userId")), "cloak/v1/recovery-sign");
            check(name + " recovery seed", hex(recoverySeed), str(id, "recoverySigningSeed"));
            checkKeyPair(name + " recovery key", recoverySeed, bytes(id, "recoverySigningPublicKey"));
            check(name + " keys digest", hex(sha256(fingerprintMessage(id))), str(id, "keysDigest"));
        }
        for (Object o : list(file, "statements")) {
            Map<String, Object> s = map(o);
            check("statement " + s.get("userId") + " v" + s.get("keyVersion"), String.valueOf(statementReason(s)), "null");
        }
        for (Object o : list(file, "negatives")) {
            Map<String, Object> n = map(o);
            check("statement refused " + n.get("name"), String.valueOf(statementReason(map(n.get("statement")))), str(n, "reason"));
        }
    }

    /** Checks a key statement (PROTOCOL.md §5.2); null when valid, else `bad_statement`. */
    private static String statementReason(Map<String, Object> s) throws Exception {
        long version = num(s, "keyVersion");
        Map<String, Object> id = identity(str(s, "userId"), version);
        Map<String, Object> previous = version == 1 ? null : identity(str(s, "userId"), version - 1);
        byte[] message = new Canonical().label("cloak/v1/key-statement").uuid(str(s, "userId")).u32(version)
                .raw(sha256(fingerprintMessage(id)))
                .raw(previous == null ? new byte[32] : sha256(fingerprintMessage(previous)))
                .bytes();
        if (!hex(message).equals(str(s, "message"))) return "bad_statement";
        if (strictVerify(bytes(id, "signingPublicKey"), message, bytes(s, "signature")) != null) return "bad_statement";
        if (previous == null) return s.containsKey("recoverySignature") ? "bad_statement" : null;
        if (!s.containsKey("recoverySignature")) return "bad_statement";
        return strictVerify(bytes(previous, "recoverySigningPublicKey"), message, bytes(s, "recoverySignature")) == null
                ? null : "bad_statement";
    }

    private static byte[] fingerprintMessage(Map<String, Object> id) {
        return new Canonical().label("cloak/v1/fingerprint").uuid(str(id, "userId")).u8(1).u32(num(id, "keyVersion"))
                .raw(bytes(id, "encryptionPublicKey")).raw(bytes(id, "signingPublicKey"))
                .raw(bytes(id, "recoverySigningPublicKey")).bytes();
    }

    private static Map<String, Object> identity(String userId, long keyVersion) {
        for (Object i : identities) {
            Map<String, Object> m = map(i);
            if (str(m, "userId").equals(userId) && num(m, "keyVersion") == keyVersion) return m;
        }
        return null;
    }

    /** Checks that a seed signs for the given public key. */
    private static void checkKeyPair(String name, byte[] seed, byte[] publicKey) throws Exception {
        Signature sign = Signature.getInstance("Ed25519");
        sign.initSign(KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(
                concat(HEX.parseHex("302e020100300506032b657004220420"), seed))));
        byte[] probe = "cloak key pair probe".getBytes(StandardCharsets.UTF_8);
        sign.update(probe);
        check(name, String.valueOf(strictVerify(publicKey, probe, concat(new byte[] {1}, sign.sign()))), "null");
    }

    // -----------------------------------------------------------------------------------------
    // vault-log.json
    // -----------------------------------------------------------------------------------------

    private static final Set<String> LOG_BYTE_REASONS =
            Set.of("broken_chain", "bad_signature", "bad_flag", "bad_checkpoint", "unverified_keys");

    private static void verifyVaultLog(Map<String, Object> file) throws Exception {
        String[] result = scanLog(list(file, "log"), file);
        check("vault log is valid", result == null ? "valid" : result[0] + " at " + result[1], "valid");
        for (Object o : list(file, "log")) {
            Map<String, Object> c = map(o);
            check("vault log fields #" + map(c.get("entry")).get("seq"), hex(canonical(list(c, "fields"))), str(c, "message"));
        }
        for (Object o : list(file, "negatives")) {
            Map<String, Object> n = map(o);
            String[] found = scanLog(list(n, "log"), file);
            String expected = str(n, "reason");
            if (LOG_BYTE_REASONS.contains(expected) && !(expected.equals("unverified_keys") && found == null)) {
                check("vault log refused " + n.get("name"), found == null ? "accepted" : found[0] + " at " + found[1],
                        expected + " at " + n.get("failSeq"));
            } else {
                check("vault log rule case is otherwise valid " + n.get("name"), found == null ? "valid" : found[0] + " at " + found[1], "valid");
            }
        }
    }

    /**
     * Checks everything about a log that rests on bytes: the chain, the flags, each author's keys
     * of the named version, signatures, commitments the self-committing kinds carry, and every
     * checkpoint against its leaves. Returns {reason, seq} or null.
     */
    private static String[] scanLog(List<Object> log, Map<String, Object> file) throws Exception {
        byte[] previous = new byte[32];
        Map<Long, String> commitments = new LinkedHashMap<>();
        for (Object vk : list(file, "vaultKeys")) commitments.put(num(map(vk), "keyVersion"), str(map(vk), "keyCommitment"));
        for (Object o : log) {
            Map<String, Object> c = map(o);
            Map<String, Object> e = map(c.get("entry"));
            String seq = String.valueOf(num(e, "seq"));
            if (!hex(previous).equals(str(c, "previousHash"))) return new String[] {"broken_chain", seq};
            long requestEnd = num(e, "requestEnd");
            if (requestEnd != 0 && requestEnd != 1) return new String[] {"bad_flag", seq};
            byte[] message = logMessage(e, previous);
            if (!hex(message).equals(str(c, "message")) || !hex(sha256(message)).equals(str(c, "entryHash"))) {
                return new String[] {"broken_chain", seq};
            }
            Map<String, Object> author = identity(str(e, "authorUserId"), num(e, "authorKeyVersion"));
            if (author == null) return new String[] {"unverified_keys", seq};
            String kind = str(e, "kind");
            if (kind.equals("vault_created") || kind.equals("member_keys_replaced")) {
                if (!str(e, "subjectUserId").equals(str(e, "authorUserId"))
                        || num(e, "subjectKeyVersion") != num(e, "authorKeyVersion")
                        || !str(e, "subjectKeys").equals(hex(sha256(fingerprintMessage(author))))) {
                    return new String[] {"unverified_keys", seq};
                }
            } else if (e.containsKey("subjectKeys")) {
                Map<String, Object> subject = identity(str(e, "subjectUserId"), num(e, "subjectKeyVersion"));
                if (subject == null || !str(e, "subjectKeys").equals(hex(sha256(fingerprintMessage(subject))))) {
                    return new String[] {"unverified_keys", seq};
                }
            }
            if (e.containsKey("keyCommitment") && !str(e, "keyCommitment").equals(commitments.get(num(e, "keyVersion")))) {
                return new String[] {"key_mismatch", seq};
            }
            String reason = strictVerify(bytes(author, "signingPublicKey"), message, bytes(c, "signature"));
            if (reason != null) return new String[] {reason, seq};
            if (e.containsKey("checkpoint")) {
                List<byte[]> hashes = new ArrayList<>();
                for (Object l : list(c, "checkpointLeaves")) hashes.add(leafHash(leafData(map(l))));
                if (!hex(treeHash(hashes)).equals(str(e, "checkpoint"))) return new String[] {"bad_checkpoint", seq};
            }
            previous = sha256(message);
        }
        return null;
    }

    private static byte[] logMessage(Map<String, Object> e, byte[] previousHash) {
        return new Canonical().label("cloak/v1/vault-log")
                .uuid(str(e, "vaultId"))
                .u64(BigInteger.valueOf(num(e, "seq")))
                .raw(previousHash)
                .u8(KINDS.indexOf(str(e, "kind")) + 1)
                .uuid(optional(e, "subjectUserId"))
                .u8(e.containsKey("role") ? ROLES.indexOf(str(e, "role")) + 1 : 0)
                .u32(num(e, "keyVersion"))
                .raw(optionalDigest(e, "subjectKeys"))
                .u32(e.containsKey("subjectKeyVersion") ? num(e, "subjectKeyVersion") : 0)
                .raw(optionalDigest(e, "keyCommitment"))
                .raw(optionalDigest(e, "checkpoint"))
                .u8((int) num(e, "requestEnd"))
                .uuid(str(e, "authorUserId"))
                .u32(num(e, "authorKeyVersion"))
                .uuid(optional(e, "nodeId"))
                .uuid(optional(e, "homeVaultId"))
                .str(e.containsKey("nodeKey") ? str(e, "nodeKey") : "")
                .str(e.containsKey("sections") ? str(e, "sections") : "")
                .bytes();
    }

    private static String optional(Map<String, Object> m, String key) {
        return m.containsKey(key) ? str(m, key) : NIL;
    }

    private static byte[] optionalDigest(Map<String, Object> m, String key) {
        return m.containsKey(key) ? bytes(m, key) : new byte[32];
    }

    // -----------------------------------------------------------------------------------------
    // checkpoints.json: RFC 6962 trees
    // -----------------------------------------------------------------------------------------

    private static void verifyCheckpoints(Map<String, Object> file) throws Exception {
        check("empty root", hex(treeHash(List.of())), str(file, "emptyRoot"));
        for (Object o : list(file, "trees")) {
            Map<String, Object> t = map(o);
            List<byte[]> hashes = new ArrayList<>();
            String previousKey = null;
            for (Object l : list(t, "leaves")) {
                Map<String, Object> leaf = map(l);
                byte[] data = leafData(leaf);
                check("leaf data", hex(data), str(leaf, "leafData"));
                check("leaf hash", hex(leafHash(data)), str(leaf, "leafHash"));
                String key = hex(uuid(str(leaf, "nodeId"))) + "/" + hex(str(leaf, "sectionName").getBytes(StandardCharsets.UTF_8));
                if (previousKey != null) check("leaf order", String.valueOf(previousKey.compareTo(key) < 0), "true");
                previousKey = key;
                hashes.add(leafHash(data));
            }
            byte[] root = treeHash(hashes);
            check("tree root size " + t.get("size"), hex(root), str(t, "root"));
            List<Object> leaves = list(t, "leaves");
            for (int i = 0; i < leaves.size(); i++) {
                List<byte[]> path = new ArrayList<>();
                for (Object p : list(map(leaves.get(i)), "path")) path.add(HEX.parseHex((String) p));
                check("inclusion " + t.get("size") + "/" + i, String.valueOf(verifyInclusion(i, leaves.size(), hashes.get(i), path, root)), "true");
            }
        }
        for (Object o : list(file, "negatives")) {
            Map<String, Object> n = map(o);
            List<byte[]> path = new ArrayList<>();
            for (Object p : list(n, "path")) path.add(HEX.parseHex((String) p));
            boolean ok = verifyInclusion(num(n, "index"), num(n, "size"), bytes(n, "leafHash"), path, bytes(n, "root"));
            check("inclusion refused " + n.get("name"), String.valueOf(ok), "false");
        }
    }

    private static byte[] leafData(Map<String, Object> leaf) {
        return new Canonical().uuid(str(leaf, "nodeId")).str(str(leaf, "sectionName"))
                .u64(BigInteger.valueOf(num(leaf, "dataVersion"))).raw(bytes(leaf, "writeHash")).bytes();
    }

    private static byte[] leafHash(byte[] data) throws Exception {
        return sha256(concat(new byte[] {0}, data));
    }

    /** RFC 6962 §2.1 tree hash, written as the recursive definition. */
    private static byte[] treeHash(List<byte[]> hashes) throws Exception {
        if (hashes.isEmpty()) return sha256(new byte[0]);
        if (hashes.size() == 1) return hashes.get(0);
        int k = 1;
        while (k * 2 < hashes.size()) k *= 2;
        return sha256(concat(new byte[] {1}, treeHash(hashes.subList(0, k)), treeHash(hashes.subList(k, hashes.size()))));
    }

    /** RFC 9162 §2.1.3.2 inclusion check. */
    private static boolean verifyInclusion(long index, long size, byte[] hash, List<byte[]> path, byte[] root) throws Exception {
        if (index >= size) return false;
        long fn = index;
        long sn = size - 1;
        byte[] r = hash;
        for (byte[] p : path) {
            if (sn == 0) return false;
            if ((fn & 1) == 1 || fn == sn) {
                r = sha256(concat(new byte[] {1}, p, r));
                if ((fn & 1) == 0) {
                    do {
                        fn >>= 1;
                        sn >>= 1;
                    } while ((fn & 1) == 0 && fn != 0);
                }
            } else {
                r = sha256(concat(new byte[] {1}, r, p));
            }
            fn >>= 1;
            sn >>= 1;
        }
        return sn == 0 && Arrays.equals(r, root);
    }

    // -----------------------------------------------------------------------------------------
    // sections.json
    // -----------------------------------------------------------------------------------------

    private static final Set<String> SECTION_RULE_REASONS = Set.of("not_an_editor", "wrong_key_version", "not_a_head");

    private static void verifySections(Map<String, Object> file, Map<String, Object> logFile, Map<String, Object> kdf) throws Exception {
        List<Object> log = list(logFile, "log");
        Map<String, Map<String, Object>> byName = new LinkedHashMap<>();
        for (Object o : list(file, "cases")) {
            Map<String, Object> c = map(o);
            String name = str(c, "name");
            byNameput(byName, name, c);
            Map<String, Object> w = map(c.get("write"));
            String expected = c.get("reason") == null ? "null" : str(c, "reason");
            byte[] ciphertext = c.containsKey("ciphertext") ? bytes(c, "ciphertext") : null;
            byte[] message = sectionWrite(w, ciphertext);
            check("section message " + name, hex(message), str(c, "message"));
            check("section fields " + name, hex(canonical(list(c, "fields"))), str(c, "message"));
            check("section write hash " + name, hex(sha256(message)), str(c, "writeHash"));
            check("section ciphertext hash " + name, str(w, "ciphertextHash"),
                    hex(ciphertext == null ? new byte[32] : sha256(ciphertext)));

            Map<String, Object> head = map(log.get((int) num(w, "logSeq") - 1));
            check("section head hash " + name, str(w, "logHeadHash"), str(head, "entryHash"));
            boolean isHead = num(map(head.get("entry")), "requestEnd") == 1;
            check("section cites a head " + name, String.valueOf(isHead), String.valueOf(!expected.equals("not_a_head")));

            boolean deletionShape = (num(w, "deleted") == 1) == (ciphertext == null);
            check("section deletion shape " + name, String.valueOf(deletionShape), String.valueOf(!expected.equals("bad_deletion")));
            if (!deletionShape) continue;

            Map<String, Object> writer = identity(str(w, "writerUserId"), num(w, "writerKeyVersion"));
            String signature = strictVerify(bytes(writer, "signingPublicKey"), message, bytes(c, "signature"));
            check("section signature " + name, String.valueOf(signature), expected.equals("bad_signature") ? "bad_signature" : "null");
            if (signature != null) continue;

            if (ciphertext != null) {
                long version = num(w, "vaultKeyVersion");
                byte[] contentKey = bytes(map(list(kdf, "vaultKeys").get((int) version - 1)), "contentKey");
                byte[] ad = new Canonical().label("cloak/v1/section-content").uuid(str(w, "vaultId")).uuid(str(w, "nodeId"))
                        .str(str(w, "sectionName")).u32(version).bytes();
                byte[] content = unpad(openBlob(contentKey, ad, ciphertext));
                check("section content " + name, new String(content, StandardCharsets.UTF_8), str(c, "contentUtf8"));
            }

            // §8.4 rule 6: the node derives from its owner, home and key, and lives in its home or is
            // shared into the vault, since no later than the write's head, by the log's node entries.
            // Every write names its node truthfully; a deletion is judged for nothing more.
            String nodeId = nodeIdOf(str(w, "ownerUserId"), str(w, "homeVaultId"), str(w, "nodeKey"));
            int keyBytes = str(w, "nodeKey").getBytes(StandardCharsets.UTF_8).length;
            if (keyBytes < 1 || keyBytes > 255 || !nodeId.equals(str(w, "nodeId"))) {
                check("section place " + name, "bad_node", expected);
                continue;
            }
            if (num(w, "deleted") != 1) {
                Long since = str(w, "homeVaultId").equals(str(w, "vaultId"))
                        ? createdAt(log, w)
                        : sharedSince(log, str(w, "nodeId"), str(w, "sectionName"));
                if (since == null || since > num(w, "logSeq")) {
                    check("section place " + name, "not_shared", expected);
                    continue;
                }
            }

            if (SECTION_RULE_REASONS.contains(expected)) {
                // Refused by a role or head rule; the bytes above are valid, which is what this check covers.
                continue;
            }
            // §8.4 rule 4 from the proofs: the first checkpoint after the head holds this write, and
            // the latest holds it as its section's very leaf.
            byte[] writeHash = sha256(message);
            List<Object> proofs = list(c, "checkpointProofs");
            String standing = "null";
            for (int i = 0; i < proofs.size(); i++) {
                Map<String, Object> proof = map(proofs.get(i));
                Map<String, Object> entry = map(log.get((int) num(proof, "checkpointSeq") - 1));
                byte[] root = bytes(map(entry.get("entry")), "checkpoint");
                Map<String, Object> leaf = provenLeaf(proof, w, root, name);
                boolean isThis = leaf != null && num(leaf, "dataVersion") == num(w, "dataVersion")
                        && str(leaf, "writeHash").equals(hex(writeHash));
                boolean first = i == 0;
                boolean latest = i == proofs.size() - 1;
                if (!standing.equals("null")) break;
                if (num(w, "deleted") == 1) {
                    // A deletion is never a leaf: each checkpoint after its head holds none for it.
                    if (leaf != null)
                        standing = num(leaf, "dataVersion") > num(w, "dataVersion") ? "rollback" : "not_in_checkpoint";
                    continue;
                }
                if (first && !isThis) standing = "not_in_checkpoint";
                else if (latest && !first) {
                    if (leaf == null) standing = "not_in_checkpoint";
                    else if (num(leaf, "dataVersion") > num(w, "dataVersion")) standing = "rollback";
                    else if (!isThis) standing = "fork";
                }
            }
            check("section standing " + name, standing, expected);
        }
        for (Object o : list(file, "marks")) {
            Map<String, Object> m = map(o);
            Map<String, Object> seen = map(byName.get(str(m, "seen")).get("write"));
            Map<String, Object> then = map(byName.get(str(m, "then")).get("write"));
            check("mark same data version " + m.get("name"), String.valueOf(num(seen, "dataVersion")), String.valueOf(num(then, "dataVersion")));
            check("mark other hash " + m.get("name"),
                    String.valueOf(str(byName.get(str(m, "seen")), "writeHash").equals(str(byName.get(str(m, "then")), "writeHash"))), "false");
        }
    }

    private static void byNameput(Map<String, Map<String, Object>> byName, String name, Map<String, Object> c) {
        byName.put(name, c);
    }

    /**
     * Checks a checkpoint proof against its root and returns the section's leaf, or null when the
     * proof shows the section absent; fails when the proof does not hold.
     */
    private static Map<String, Object> provenLeaf(Map<String, Object> proof, Map<String, Object> w, byte[] root, String name) throws Exception {
        long size = num(proof, "size");
        if (proof.containsKey("inclusion")) {
            Map<String, Object> inclusion = map(proof.get("inclusion"));
            Map<String, Object> leaf = map(inclusion.get("leaf"));
            check("proof address " + name, compareSections(leaf, w) == 0 ? "same" : "other", "same");
            check("proof inclusion " + name, String.valueOf(holds(inclusion, size, root)), "true");
            return leaf;
        }
        Map<String, Object> before = proof.containsKey("before") ? map(proof.get("before")) : null;
        Map<String, Object> after = proof.containsKey("after") ? map(proof.get("after")) : null;
        boolean ok = (before == null || (holds(before, size, root) && compareSections(map(before.get("leaf")), w) < 0))
                && (after == null || (holds(after, size, root) && compareSections(w, map(after.get("leaf"))) < 0))
                && (before == null ? (after == null ? size == 0 : num(after, "index") == 0)
                        : (after == null ? num(before, "index") == size - 1 : num(after, "index") == num(before, "index") + 1));
        check("proof absence " + name, String.valueOf(ok), "true");
        return null;
    }

    /** Whether a leaf proof's path reaches the root. */
    private static boolean holds(Map<String, Object> leafProof, long size, byte[] root) throws Exception {
        List<byte[]> path = new ArrayList<>();
        for (Object p : list(leafProof, "path")) path.add(HEX.parseHex((String) p));
        return verifyInclusion(num(leafProof, "index"), size, leafHash(leafData(map(leafProof.get("leaf")))), path, root);
    }

    /** Orders sections by node id bytes, then section name bytes. */
    private static int compareSections(Map<String, Object> a, Map<String, Object> b) throws Exception {
        int byNode = Arrays.compareUnsigned(uuid(str(a, "nodeId")), uuid(str(b, "nodeId")));
        if (byNode != 0) return byNode;
        return Arrays.compareUnsigned(str(a, "sectionName").getBytes(StandardCharsets.UTF_8),
                str(b, "sectionName").getBytes(StandardCharsets.UTF_8));
    }

    /** §8.1: UUIDv5 under the owner of label "cloak/v1/node", the home vault and the key. */
    private static String nodeIdOf(String owner, String home, String key) throws Exception {
        return uuidV5(owner, new Canonical().label("cloak/v1/node").uuid(home).str(key).bytes());
    }

    /** §7.7: the seq of the node_created that made the write's node, with its owner and key, if any. */
    private static Long createdAt(List<Object> log, Map<String, Object> w) {
        for (Object o : log) {
            Map<String, Object> e = map(map(o).get("entry"));
            if (str(e, "kind").equals("node_created") && str(e, "nodeId").equals(str(w, "nodeId"))
                    && str(e, "authorUserId").equals(str(w, "ownerUserId")) && str(e, "nodeKey").equals(str(w, "nodeKey"))) {
                return num(e, "seq");
            }
        }
        return null;
    }

    /** §7.7: from which seq a name is shared into the vault at the end of the log, if it is. */
    private static Long sharedSince(List<Object> log, String nodeId, String sectionName) {
        Long all = null;
        Map<String, Long> names = new LinkedHashMap<>();
        boolean shared = false;
        for (Object o : log) {
            Map<String, Object> e = map(map(o).get("entry"));
            if (!e.containsKey("nodeId") || !str(e, "nodeId").equals(nodeId)) continue;
            long seq = num(e, "seq");
            String sections = str(e, "sections");
            if (str(e, "kind").equals("node_shared")) {
                shared = true;
                if (sections.equals("*")) { if (all == null) all = seq; }
                else for (String n : sections.split(",")) if (all == null && !names.containsKey(n)) names.put(n, seq);
            } else if (str(e, "kind").equals("node_unshared")) {
                if (sections.equals("*")) { all = null; names.clear(); shared = false; }
                else for (String n : sections.split(",")) names.remove(n);
            }
        }
        if (!shared) return null;
        return names.containsKey(sectionName) ? names.get(sectionName) : all;
    }

    private static byte[] sectionWrite(Map<String, Object> w, byte[] ciphertext) throws Exception {
        return new Canonical().label("cloak/v1/section-write")
                .uuid(str(w, "vaultId"))
                .uuid(str(w, "nodeId"))
                .str(str(w, "nodeType"))
                .uuid(str(w, "homeVaultId"))
                .uuid(str(w, "ownerUserId"))
                .str(str(w, "nodeKey"))
                .str(str(w, "sectionName"))
                .u32(num(w, "vaultKeyVersion"))
                .u64(BigInteger.valueOf(num(w, "dataVersion")))
                .u8((int) num(w, "deleted"))
                .u64(BigInteger.valueOf(num(w, "logSeq")))
                .raw(bytes(w, "logHeadHash"))
                .raw(bytes(w, "previousWriteHash"))
                .uuid(str(w, "writerUserId"))
                .u32(num(w, "writerKeyVersion"))
                .raw(ciphertext == null ? new byte[32] : sha256(ciphertext))
                .bytes();
    }

    private static byte[] u32(long v) {
        return ByteBuffer.allocate(4).putInt((int) v).array();
    }

    private static byte[] hkdf(byte[] ikm, byte[] salt, String info) throws Exception {
        return hkdf(ikm, salt, info, 32);
    }

    // -----------------------------------------------------------------------------------------
    // Canonical encoding (PROTOCOL.md §3)
    // -----------------------------------------------------------------------------------------

    private static final class Canonical {
        private final java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();

        Canonical label(String s) { return str(s); }

        Canonical str(String s) {
            byte[] b = s.getBytes(StandardCharsets.UTF_8);
            out.write(b.length >>> 8);
            out.write(b.length & 0xff);
            out.writeBytes(b);
            return this;
        }

        Canonical u8(int v) { out.write(v); return this; }

        Canonical u32(long v) { out.writeBytes(ByteBuffer.allocate(4).putInt((int) v).array()); return this; }

        Canonical u64(BigInteger v) {
            byte[] b = v.toByteArray();
            byte[] fixed = new byte[8];
            int n = Math.min(8, b.length);
            System.arraycopy(b, b.length - n, fixed, 8 - n, n);
            out.writeBytes(fixed);
            return this;
        }

        Canonical uuid(String u) { out.writeBytes(VerifyVectors.uuid(u)); return this; }

        Canonical raw(byte[] b) { out.writeBytes(b); return this; }

        byte[] bytes() { return out.toByteArray(); }
    }

    private static byte[] canonical(List<Object> fields) {
        Canonical c = new Canonical();
        for (Object o : fields) {
            Map<String, Object> f = map(o);
            Object v = f.get("value");
            switch (str(f, "type")) {
                case "label", "str" -> c.str((String) v);
                case "u8" -> c.u8(((Number) v).intValue());
                case "flag" -> c.u8(((Number) v).intValue());
                case "u32" -> c.u32(((Number) v).longValue());
                case "u64" -> c.u64(new BigInteger((String) v));
                case "uuid" -> c.uuid((String) v);
                case "key32", "digest32" -> {
                    byte[] b = HEX.parseHex((String) v);
                    if (b.length != 32) throw new IllegalStateException("fixed field must be 32 bytes");
                    c.raw(b);
                }
                default -> throw new IllegalStateException("unknown field type " + f.get("type"));
            }
        }
        return c.bytes();
    }

    // -----------------------------------------------------------------------------------------
    // Crypto
    // -----------------------------------------------------------------------------------------

    private static byte[] hkdf(byte[] ikm, byte[] salt, String info, int length) throws Exception {
        HKDFParameterSpec.Builder builder = HKDFParameterSpec.ofExtract().addIKM(ikm);
        if (salt.length > 0) builder.addSalt(salt);
        return KDF.getInstance("HKDF-SHA256")
                .deriveData(builder.thenExpand(info.getBytes(StandardCharsets.UTF_8), length));
    }

    private static int rotl(int v, int c) { return (v << c) | (v >>> (32 - c)); }

    private static byte[] hchacha20(byte[] key, byte[] nonce) {
        int[] s = new int[16];
        s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
        ByteBuffer k = ByteBuffer.wrap(key).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        for (int i = 0; i < 8; i++) s[4 + i] = k.getInt();
        ByteBuffer n = ByteBuffer.wrap(nonce).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        for (int i = 0; i < 4; i++) s[12 + i] = n.getInt();
        int[][] rounds = {{0, 4, 8, 12}, {1, 5, 9, 13}, {2, 6, 10, 14}, {3, 7, 11, 15},
                {0, 5, 10, 15}, {1, 6, 11, 12}, {2, 7, 8, 13}, {3, 4, 9, 14}};
        for (int r = 0; r < 10; r++) {
            for (int[] q : rounds) {
                int a = q[0], b = q[1], c = q[2], d = q[3];
                s[a] += s[b]; s[d] = rotl(s[d] ^ s[a], 16);
                s[c] += s[d]; s[b] = rotl(s[b] ^ s[c], 12);
                s[a] += s[b]; s[d] = rotl(s[d] ^ s[a], 8);
                s[c] += s[d]; s[b] = rotl(s[b] ^ s[c], 7);
            }
        }
        ByteBuffer out = ByteBuffer.allocate(32).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        for (int w : new int[] {0, 1, 2, 3, 12, 13, 14, 15}) out.putInt(s[w]);
        return out.array();
    }

    private static byte[] xchacha(int mode, byte[] key, byte[] nonce24, byte[] ad, byte[] input) throws Exception {
        byte[] subkey = hchacha20(key, Arrays.copyOf(nonce24, 16));
        byte[] nonce12 = concat(new byte[4], Arrays.copyOfRange(nonce24, 16, 24));
        Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
        cipher.init(mode, new SecretKeySpec(subkey, "ChaCha20"), new IvParameterSpec(nonce12));
        cipher.updateAAD(ad);
        return cipher.doFinal(input);
    }

    private static PrivateKey x25519Private(byte[] raw) throws Exception {
        return KeyFactory.getInstance("X25519").generatePrivate(
                new PKCS8EncodedKeySpec(concat(HEX.parseHex("302e020100300506032b656e04220420"), raw)));
    }

    private static byte[] x25519(byte[] sk, byte[] pk) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("X25519");
        ka.init(x25519Private(sk));
        ka.doPhase(KeyFactory.getInstance("X25519").generatePublic(
                new X509EncodedKeySpec(concat(HEX.parseHex("302a300506032b656e032100"), pk))), true);
        return ka.generateSecret();
    }

    private static byte[] sha256(byte[] b) throws Exception { return MessageDigest.getInstance("SHA-256").digest(b); }

    // -----------------------------------------------------------------------------------------
    // Text
    // -----------------------------------------------------------------------------------------

    private static final String CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    private static String crockford(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        BigInteger value = new BigInteger(1, concat(new byte[] {1}, bytes));
        int bits = bytes.length * 8;
        int chars = (bits + 4) / 5;
        value = value.shiftLeft(chars * 5 - bits).clearBit(chars * 5);
        for (int i = chars - 1; i >= 0; i--) sb.append(CROCKFORD.charAt(value.shiftRight(i * 5).intValue() & 31));
        return sb.toString();
    }

    private static String group(String s, int size) {
        List<String> parts = new ArrayList<>();
        for (int i = 0; i < s.length(); i += size) parts.add(s.substring(i, Math.min(s.length(), i + size)));
        return String.join("-", parts);
    }

    private static String b64u(byte[] b) { return Base64.getUrlEncoder().withoutPadding().encodeToString(b); }

    // -----------------------------------------------------------------------------------------
    // Utilities and a minimal JSON reader
    // -----------------------------------------------------------------------------------------

    private static void check(String name, String actual, String expected) {
        checks++;
        if (!actual.equals(expected)) failures.add(name + "\n  expected " + expected + "\n  actual   " + actual);
    }

    private static byte[] uuid(String u) { return HEX.parseHex(u.replace("-", "")); }

    /** RFC 9562 §5.5 UUIDv5 of [name] under [namespace], lowercase. */
    private static String uuidV5(String namespace, byte[] name) throws Exception {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        sha1.update(uuid(namespace));
        byte[] bytes = Arrays.copyOf(sha1.digest(name), 16);
        bytes[6] = (byte) ((bytes[6] & 0x0f) | 0x50);
        bytes[8] = (byte) ((bytes[8] & 0x3f) | 0x80);
        String hex = HEX.formatHex(bytes);
        return hex.substring(0, 8) + "-" + hex.substring(8, 12) + "-" + hex.substring(12, 16) + "-" + hex.substring(16, 20) + "-" + hex.substring(20);
    }

    private static byte[] concat(byte[]... parts) {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (byte[] p : parts) out.writeBytes(p);
        return out.toByteArray();
    }

    private static String hex(byte[] b) { return HEX.formatHex(b); }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    private static List<Object> list(Map<String, Object> m, String key) { return (List<Object>) m.get(key); }

    private static String str(Map<String, Object> m, String key) { return (String) m.get(key); }

    private static long num(Map<String, Object> m, String key) { return ((Number) m.get(key)).longValue(); }

    private static byte[] bytes(Map<String, Object> m, String key) { return HEX.parseHex(str(m, key)); }

    private static Map<String, Object> read(Path dir, String name) throws Exception {
        return map(new Json(Files.readString(dir.resolve(name))).value());
    }

    private static final class Json {
        private final String s;
        private int i;

        Json(String s) { this.s = s; }

        Object value() {
            ws();
            char c = s.charAt(i);
            if (c == '{') {
                Map<String, Object> m = new LinkedHashMap<>();
                i++; ws();
                if (s.charAt(i) == '}') { i++; return m; }
                while (true) {
                    ws(); String k = string(); ws(); expect(':');
                    m.put(k, value()); ws();
                    if (s.charAt(i) == ',') { i++; continue; }
                    expect('}'); return m;
                }
            }
            if (c == '[') {
                List<Object> l = new ArrayList<>();
                i++; ws();
                if (s.charAt(i) == ']') { i++; return l; }
                while (true) {
                    l.add(value()); ws();
                    if (s.charAt(i) == ',') { i++; continue; }
                    expect(']'); return l;
                }
            }
            if (c == '"') return string();
            if (s.startsWith("true", i)) { i += 4; return Boolean.TRUE; }
            if (s.startsWith("false", i)) { i += 5; return Boolean.FALSE; }
            if (s.startsWith("null", i)) { i += 4; return null; }
            int start = i;
            while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) i++;
            return Long.parseLong(s.substring(start, i));
        }

        private String string() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (s.charAt(i) != '"') {
                char c = s.charAt(i++);
                if (c != '\\') { sb.append(c); continue; }
                char e = s.charAt(i++);
                switch (e) {
                    case 'n' -> sb.append('\n');
                    case 't' -> sb.append('\t');
                    case 'r' -> sb.append('\r');
                    case 'b' -> sb.append('\b');
                    case 'f' -> sb.append('\f');
                    case 'u' -> { sb.append((char) Integer.parseInt(s.substring(i, i + 4), 16)); i += 4; }
                    default -> sb.append(e);
                }
            }
            i++;
            return sb.toString();
        }

        private void ws() { while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++; }

        private void expect(char c) {
            if (s.charAt(i) != c) throw new IllegalStateException("expected " + c + " at " + i);
            i++;
        }
    }
}
