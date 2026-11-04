#!/usr/bin/env node
// Generates the Cloak protocol v1 test vectors from PROTOCOL.md.
//
// Reference implementation on Node.js >= 24 built-ins only (no npm dependencies):
// X25519, Ed25519, ChaCha20-Poly1305, HKDF-SHA256, HMAC-SHA256, SHA-256 and Argon2id come
// from node:crypto; HChaCha20 (for XChaCha20-Poly1305) and HPKE are written out here and are
// checked against published known-answer tests before any vector is produced.
//
// Usage: node generate-vectors.mjs [output-directory]
// Default output: ../test-vectors/v1 next to this script.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const outDir = path.resolve(process.argv[2] ?? path.join(here, '..', 'test-vectors', 'v1'));

// ---------------------------------------------------------------------------------------------
// Byte helpers
// ---------------------------------------------------------------------------------------------

const hex = (b) => Buffer.from(b).toString('hex');
const fromHex = (h) => Buffer.from(h, 'hex');
const b64u = (b) => Buffer.from(b).toString('base64url');
const utf8 = (s) => Buffer.from(s, 'utf8');
const EMPTY = Buffer.alloc(0);

function assert(condition, message) {
  if (!condition) throw new Error(`Assertion failed: ${message}`);
}

function u16(n) {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n);
  return b;
}

/** Deterministic pseudo-random bytes for vector inputs: SHA-256 chain over a label. */
function fixture(label, length) {
  const out = [];
  let counter = 0;
  while (Buffer.concat(out).length < length) {
    out.push(sha256(utf8(`cloak test vector:${label}:${counter++}`)));
  }
  return Buffer.concat(out).subarray(0, length);
}

function uuidBytes(uuid) {
  const b = fromHex(uuid.replaceAll('-', ''));
  assert(b.length === 16, `uuid ${uuid}`);
  return b;
}

// ---------------------------------------------------------------------------------------------
// Hashes and KDFs
// ---------------------------------------------------------------------------------------------

const sha256 = (data) => crypto.createHash('sha256').update(data).digest();
const hmacSha256 = (key, data) => crypto.createHmac('sha256', key).update(data).digest();

/** HKDF-SHA256 (RFC 5869) in one call. An empty salt means HashLen zero bytes. */
function hkdf(ikm, salt, info, length = 32) {
  return Buffer.from(crypto.hkdfSync('sha256', ikm, salt, info, length));
}

/** HKDF-Extract; an empty salt is HashLen zero bytes. */
function hkdfExtract(salt, ikm) {
  return hmacSha256(salt.length === 0 ? Buffer.alloc(32) : salt, ikm);
}

/** HKDF-Expand. */
function hkdfExpand(prk, info, length) {
  const blocks = [];
  let previous = EMPTY;
  for (let i = 1; Buffer.concat(blocks).length < length; i++) {
    previous = hmacSha256(prk, Buffer.concat([previous, info, Buffer.from([i])]));
    blocks.push(previous);
  }
  return Buffer.concat(blocks).subarray(0, length);
}

/** Argon2id with suite-1 constraints: parallelism 1, 32-byte output. */
function argon2id(password, salt, memoryKib, iterations) {
  return Buffer.from(
    crypto.argon2Sync('argon2id', {
      message: password,
      nonce: salt,
      parallelism: 1,
      tagLength: 32,
      memory: memoryKib,
      passes: iterations,
    }),
  );
}


// ---------------------------------------------------------------------------------------------
// Canonical encoding (PROTOCOL.md §3)
// ---------------------------------------------------------------------------------------------

/**
 * Builds a canonical message and records its typed fields, so vectors can show both.
 * Field types: label/str (u16 length + UTF-8), u8, u32, u64 (big-endian), flag (one byte, 0 or
 * 1), uuid (16 bytes), key32 and digest32 (exactly 32 raw bytes).
 */
class Canonical {
  constructor() {
    this.parts = [];
    this.fields = [];
  }

  #push(type, value, bytes) {
    this.parts.push(bytes);
    this.fields.push({ type, value });
    return this;
  }

  str(type, s) {
    const b = utf8(s);
    assert(b.length <= 0xffff, 'string too long');
    return this.#push(type, s, Buffer.concat([u16(b.length), b]));
  }

  label(s) {
    assert(s.startsWith('cloak/v1/'), `label ${s}`);
    return this.str('label', s);
  }

  text(s) {
    return this.str('str', s);
  }

  u8(n) {
    assert(Number.isInteger(n) && n >= 0 && n <= 0xff, 'u8');
    return this.#push('u8', n, Buffer.from([n]));
  }

  /** A flag; `unchecked` lets a negative vector carry an invalid value. */
  flag(n, unchecked = false) {
    assert(unchecked || n === 0 || n === 1, 'flag');
    return this.#push('flag', n, Buffer.from([n]));
  }

  u32(n) {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(n);
    return this.#push('u32', n, b);
  }

  u64(n) {
    const b = Buffer.alloc(8);
    b.writeBigUInt64BE(BigInt(n));
    return this.#push('u64', String(n), b);
  }

  uuid(u) {
    return this.#push('uuid', u, uuidBytes(u));
  }

  key32(b) {
    assert(b.length === 32, 'key32');
    return this.#push('key32', hex(b), Buffer.from(b));
  }

  digest32(b) {
    assert(b.length === 32, 'digest32');
    return this.#push('digest32', hex(b), Buffer.from(b));
  }

  bytes() {
    return Buffer.concat(this.parts);
  }
}

const SUITE = 1;
const ROLE = { viewer: 1, editor: 2, admin: 3, owner: 4 };
const KIND = {
  vault_created: 1, member_added: 2, member_role_set: 3, member_removed: 4, member_keys_replaced: 5, key_rotated: 6,
  node_created: 7, node_shared: 8, node_unshared: 9, vault_deleted: 10,
};
const NIL_UUID = '00000000-0000-0000-0000-000000000000';
const ZERO32 = Buffer.alloc(32);

const u32 = (n) => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n);
  return b;
};

const u64 = (n) => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return b;
};

/** `str` encoding: u16 length, then UTF-8. */
const strBytes = (s) => Buffer.concat([u16(utf8(s).length), utf8(s)]);

const bundleAd = (label, userId, keyVersion) =>
  new Canonical().label(label).uuid(userId).u8(SUITE).u32(keyVersion);

const fingerprintMessage = (id) =>
  new Canonical()
    .label('cloak/v1/fingerprint')
    .uuid(id.userId)
    .u8(SUITE)
    .u32(id.keyVersion)
    .key32(id.encryptionPublicKey)
    .key32(id.signingPublicKey)
    .key32(id.recoverySigningPublicKey);

const keysDigest = (id) => sha256(fingerprintMessage(id).bytes());

const keyStatementMessage = (id, previousKeysDigest) =>
  new Canonical()
    .label('cloak/v1/key-statement')
    .uuid(id.userId)
    .u32(id.keyVersion)
    .digest32(keysDigest(id))
    .digest32(previousKeysDigest ?? ZERO32);

/** Envelope context (PROTOCOL.md §6.3). */
const envelopeContext = (vaultId, keyVersion, userId, userKeyVersion) =>
  new Canonical().label('cloak/v1/vault-key').uuid(vaultId).u32(keyVersion).uuid(userId).u32(userKeyVersion);

/** AD of a vault key's previous version (PROTOCOL.md §6.2). */
const previousAd = (vaultId, version) => new Canonical().label('cloak/v1/vault-previous').uuid(vaultId).u32(version);

const sectionContentAd = (vaultId, nodeId, sectionName, vaultKeyVersion) =>
  new Canonical()
    .label('cloak/v1/section-content')
    .uuid(vaultId)
    .uuid(nodeId)
    .text(sectionName)
    .u32(vaultKeyVersion);

const localRecordAd = (recordName) => new Canonical().label('cloak/v1/local-state').text(recordName);

/** A vault log entry's signed message (PROTOCOL.md §7.1); absent values are nil, zero or 0. */
const logMessage = (e) =>
  new Canonical()
    .label('cloak/v1/vault-log')
    .uuid(e.vaultId)
    .u64(e.seq)
    .digest32(e.previousHash)
    .u8(KIND[e.kind])
    .uuid(e.subjectUserId ?? NIL_UUID)
    .u8(e.role === undefined ? 0 : ROLE[e.role])
    .u32(e.keyVersion)
    .digest32(e.subjectKeys ?? ZERO32)
    .u32(e.subjectKeyVersion ?? 0)
    .digest32(e.keyCommitment ?? ZERO32)
    .digest32(e.checkpoint ?? ZERO32)
    .flag(e.requestEnd, true)
    .uuid(e.authorUserId)
    .u32(e.authorKeyVersion)
    .uuid(e.nodeId ?? NIL_UUID)
    .uuid(e.homeVaultId ?? NIL_UUID)
    .text(e.nodeKey ?? '')
    .text(e.sections ?? '');

/** A section write's signed message (PROTOCOL.md §8.2). */
const sectionWriteMessage = (w) =>
  new Canonical()
    .label('cloak/v1/section-write')
    .uuid(w.vaultId)
    .uuid(w.nodeId)
    .text(w.nodeType)
    .uuid(w.homeVaultId)
    .uuid(w.ownerUserId)
    .text(w.nodeKey)
    .text(w.sectionName)
    .u32(w.vaultKeyVersion)
    .u64(w.dataVersion)
    .flag(w.deleted)
    .u64(w.logSeq)
    .digest32(w.logHeadHash)
    .digest32(w.previousWriteHash ?? ZERO32)
    .uuid(w.writerUserId)
    .u32(w.writerKeyVersion)
    .digest32(w.ciphertext === undefined ? ZERO32 : sha256(w.ciphertext));

/** Keys derived from a vault key (PROTOCOL.md §6.1). */
const contentKeyOf = (vaultKey, vaultId) => hkdf(vaultKey, uuidBytes(vaultId), utf8('cloak/v1/vault-content'));
const wrapKeyOf = (vaultKey, vaultId) => hkdf(vaultKey, uuidBytes(vaultId), utf8('cloak/v1/vault-wrap'));
const keyCommitmentOf = (vaultKey, vaultId, version) =>
  hkdf(vaultKey, Buffer.concat([uuidBytes(vaultId), u32(version)]), utf8('cloak/v1/vault-key-commit'));

// ---------------------------------------------------------------------------------------------
// Checkpoints: RFC 6962 Merkle trees (PROTOCOL.md §7.5)
// ---------------------------------------------------------------------------------------------

/** Leaf data of one section's latest write. */
const leafData = (leaf) =>
  Buffer.concat([uuidBytes(leaf.nodeId), strBytes(leaf.sectionName), u64(leaf.dataVersion), leaf.writeHash]);

const leafHash = (data) => sha256(Buffer.concat([Buffer.from([0x00]), data]));
const nodeHash = (left, right) => sha256(Buffer.concat([Buffer.from([0x01]), left, right]));

/** Largest power of two below n (n > 1). */
const splitPoint = (n) => {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
};

/** RFC 6962 §2.1 Merkle tree hash over leaf hashes. */
function treeHash(hashes) {
  if (hashes.length === 0) return sha256(EMPTY);
  if (hashes.length === 1) return hashes[0];
  const k = splitPoint(hashes.length);
  return nodeHash(treeHash(hashes.slice(0, k)), treeHash(hashes.slice(k)));
}

/** The same tree hash computed bottom-up, as an independent check of `treeHash`. */
function treeHashIterative(hashes) {
  if (hashes.length === 0) return sha256(EMPTY);
  // Split into perfect subtrees from the left, as RFC 6962's recursion does, then fold right to left.
  const subtrees = [];
  let start = 0;
  let remaining = hashes.length;
  while (remaining > 0) {
    let size = 1;
    while (size * 2 <= remaining) size *= 2;
    let level = hashes.slice(start, start + size);
    while (level.length > 1) {
      const next = [];
      for (let i = 0; i < level.length; i += 2) next.push(nodeHash(level[i], level[i + 1]));
      level = next;
    }
    subtrees.push(level[0]);
    start += size;
    remaining -= size;
  }
  let root = subtrees[subtrees.length - 1];
  for (let i = subtrees.length - 2; i >= 0; i--) root = nodeHash(subtrees[i], root);
  return root;
}

/** RFC 6962 §2.1.1 audit path of leaf m. */
function auditPath(m, hashes) {
  const n = hashes.length;
  if (n <= 1) return [];
  const k = splitPoint(n);
  return m < k
    ? [...auditPath(m, hashes.slice(0, k)), treeHash(hashes.slice(k))]
    : [...auditPath(m - k, hashes.slice(k)), treeHash(hashes.slice(0, k))];
}

/** RFC 9162 §2.1.3.2 inclusion check. */
function verifyInclusion(index, size, hash, path, root) {
  if (index >= size) return false;
  let fn = index;
  let sn = size - 1;
  let r = hash;
  for (const p of path) {
    if (sn === 0) return false;
    if ((fn & 1) === 1 || fn === sn) {
      r = nodeHash(p, r);
      if ((fn & 1) === 0) {
        do {
          fn >>= 1;
          sn >>= 1;
        } while ((fn & 1) === 0 && fn !== 0);
      }
    } else {
      r = nodeHash(r, p);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 && r.equals(root);
}

/** Orders sections by node id bytes, then section name bytes. */
const compareSections = (a, b) =>
  Buffer.compare(uuidBytes(a.nodeId), uuidBytes(b.nodeId)) || Buffer.compare(utf8(a.sectionName), utf8(b.sectionName));

/** A checkpoint over the latest writes of a vault's sections. */
function checkpointOf(leaves) {
  const sorted = [...leaves].sort(compareSections);
  return { leaves: sorted, root: treeHash(sorted.map((l) => leafHash(leafData(l)))) };
}
// ---------------------------------------------------------------------------------------------
// XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha-03) over Node's ChaCha20-Poly1305
// ---------------------------------------------------------------------------------------------

function hchacha20(key, nonce16) {
  assert(key.length === 32 && nonce16.length === 16, 'hchacha20 input');
  const s = new Uint32Array(16);
  s[0] = 0x61707865;
  s[1] = 0x3320646e;
  s[2] = 0x79622d32;
  s[3] = 0x6b206574;
  for (let i = 0; i < 8; i++) s[4 + i] = key.readUInt32LE(i * 4);
  for (let i = 0; i < 4; i++) s[12 + i] = nonce16.readUInt32LE(i * 4);
  const rotl = (v, c) => ((v << c) | (v >>> (32 - c))) >>> 0;
  const qr = (a, b, c, d) => {
    s[a] += s[b]; s[d] = rotl(s[d] ^ s[a], 16);
    s[c] += s[d]; s[b] = rotl(s[b] ^ s[c], 12);
    s[a] += s[b]; s[d] = rotl(s[d] ^ s[a], 8);
    s[c] += s[d]; s[b] = rotl(s[b] ^ s[c], 7);
  };
  for (let i = 0; i < 10; i++) {
    qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15);
    qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14);
  }
  const out = Buffer.alloc(32);
  [0, 1, 2, 3, 12, 13, 14, 15].forEach((word, i) => out.writeUInt32LE(s[word], i * 4));
  return out;
}

function chachaPolySeal(key, nonce12, aad, plaintext) {
  const cipher = crypto.createCipheriv('chacha20-poly1305', key, nonce12, { authTagLength: 16 });
  cipher.setAAD(aad, { plaintextLength: plaintext.length });
  return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
}

function chachaPolyOpen(key, nonce12, aad, sealed) {
  const decipher = crypto.createDecipheriv('chacha20-poly1305', key, nonce12, { authTagLength: 16 });
  decipher.setAAD(aad, { plaintextLength: sealed.length - 16 });
  decipher.setAuthTag(sealed.subarray(sealed.length - 16));
  return Buffer.concat([decipher.update(sealed.subarray(0, sealed.length - 16)), decipher.final()]);
}

function xchachaSeal(key, nonce24, aad, plaintext) {
  const subkey = hchacha20(key, nonce24.subarray(0, 16));
  const nonce12 = Buffer.concat([Buffer.alloc(4), nonce24.subarray(16)]);
  return chachaPolySeal(subkey, nonce12, aad, plaintext);
}

function xchachaOpen(key, nonce24, aad, sealed) {
  const subkey = hchacha20(key, nonce24.subarray(0, 16));
  const nonce12 = Buffer.concat([Buffer.alloc(4), nonce24.subarray(16)]);
  return chachaPolyOpen(subkey, nonce12, aad, sealed);
}

/** Encrypted blob, format 1: 0x01 || nonce (24) || ciphertext || tag (16). */
function encryptBlob(key, nonce24, aad, plaintext) {
  return Buffer.concat([Buffer.from([1]), nonce24, xchachaSeal(key, nonce24, aad, plaintext)]);
}

function decryptBlob(key, aad, blob) {
  assert(blob[0] === 1 && blob.length >= 41, 'encrypted blob format');
  return xchachaOpen(key, blob.subarray(1, 25), aad, blob.subarray(25));
}

// ---------------------------------------------------------------------------------------------
// Padding (ISO/IEC 7816-4 to a multiple of 256 bytes)
// ---------------------------------------------------------------------------------------------

const PAD_BLOCK = 256;

function pad(data) {
  const length = (Math.floor((data.length + 1 + PAD_BLOCK - 1) / PAD_BLOCK)) * PAD_BLOCK;
  const out = Buffer.alloc(length);
  data.copy(out);
  out[data.length] = 0x80;
  return out;
}

function unpad(data) {
  let i = data.length - 1;
  while (i >= 0 && data[i] === 0) i--;
  assert(i >= 0 && data[i] === 0x80 && data.length % PAD_BLOCK === 0, 'padding');
  return data.subarray(0, i);
}

// ---------------------------------------------------------------------------------------------
// X25519, Ed25519
// ---------------------------------------------------------------------------------------------

const X25519_PKCS8 = fromHex('302e020100300506032b656e04220420');
const X25519_SPKI = fromHex('302a300506032b656e032100');
const ED25519_PKCS8 = fromHex('302e020100300506032b657004220420');

const x25519Private = (raw) =>
  crypto.createPrivateKey({ key: Buffer.concat([X25519_PKCS8, raw]), format: 'der', type: 'pkcs8' });

const x25519Public = (raw) =>
  crypto.createPublicKey({ key: Buffer.concat([X25519_SPKI, raw]), format: 'der', type: 'spki' });

const x25519PublicFromPrivate = (raw) =>
  crypto.createPublicKey(x25519Private(raw)).export({ format: 'der', type: 'spki' }).subarray(-32);

const x25519 = (skRaw, pkRaw) =>
  crypto.diffieHellman({ privateKey: x25519Private(skRaw), publicKey: x25519Public(pkRaw) });

const ed25519Private = (seed) =>
  crypto.createPrivateKey({ key: Buffer.concat([ED25519_PKCS8, seed]), format: 'der', type: 'pkcs8' });

const ed25519PublicFromSeed = (seed) =>
  crypto.createPublicKey(ed25519Private(seed)).export({ format: 'der', type: 'spki' }).subarray(-32);

/** Signature blob, format 1: 0x01 || Ed25519 signature (64). */
const signBlob = (seed, message) => Buffer.concat([Buffer.from([1]), crypto.sign(null, message, ed25519Private(seed))]);

// ---------------------------------------------------------------------------------------------
// HPKE (RFC 9180), mode_base, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305
// ---------------------------------------------------------------------------------------------

const HPKE_V1 = utf8('HPKE-v1');
const KEM_SUITE_ID = Buffer.concat([utf8('KEM'), u16(0x0020)]);
const HPKE_SUITE_ID = Buffer.concat([utf8('HPKE'), u16(0x0020), u16(0x0001), u16(0x0003)]);

const labeledExtract = (suiteId, salt, label, ikm) =>
  hkdfExtract(salt, Buffer.concat([HPKE_V1, suiteId, utf8(label), ikm]));

const labeledExpand = (suiteId, prk, label, info, length) =>
  hkdfExpand(prk, Buffer.concat([u16(length), HPKE_V1, suiteId, utf8(label), info]), length);

function hpkeDeriveKeyPair(ikm) {
  const prk = labeledExtract(KEM_SUITE_ID, EMPTY, 'dkp_prk', ikm);
  const sk = labeledExpand(KEM_SUITE_ID, prk, 'sk', EMPTY, 32);
  return { sk, pk: x25519PublicFromPrivate(sk) };
}

function hpkeSharedSecret(dh, enc, pkR) {
  const prk = labeledExtract(KEM_SUITE_ID, EMPTY, 'eae_prk', dh);
  return labeledExpand(KEM_SUITE_ID, prk, 'shared_secret', Buffer.concat([enc, pkR]), 32);
}

function hpkeKeySchedule(sharedSecret, info) {
  const pskIdHash = labeledExtract(HPKE_SUITE_ID, EMPTY, 'psk_id_hash', EMPTY);
  const infoHash = labeledExtract(HPKE_SUITE_ID, EMPTY, 'info_hash', info);
  const context = Buffer.concat([Buffer.from([0x00]), pskIdHash, infoHash]);
  const secret = labeledExtract(HPKE_SUITE_ID, sharedSecret, 'secret', EMPTY);
  return {
    key: labeledExpand(HPKE_SUITE_ID, secret, 'key', context, 32),
    nonce: labeledExpand(HPKE_SUITE_ID, secret, 'base_nonce', context, 12),
  };
}

/** Single-shot HPKE seal with the ephemeral key derived from `ikmE` (random in production). */
function hpkeSeal(pkR, info, aad, plaintext, ikmE) {
  const { sk: skE, pk: enc } = hpkeDeriveKeyPair(ikmE);
  const sharedSecret = hpkeSharedSecret(x25519(skE, pkR), enc, pkR);
  const { key, nonce } = hpkeKeySchedule(sharedSecret, info);
  return { enc, ciphertext: chachaPolySeal(key, nonce, aad, plaintext), skE };
}

function hpkeOpen(skR, enc, info, aad, ciphertext) {
  const pkR = x25519PublicFromPrivate(skR);
  const sharedSecret = hpkeSharedSecret(x25519(skR, enc), enc, pkR);
  const { key, nonce } = hpkeKeySchedule(sharedSecret, info);
  return chachaPolyOpen(key, nonce, aad, ciphertext);
}

/** Sealed blob, format 1: 0x01 || enc (32) || ciphertext || tag (16). */
function sealBlob(pkR, info, aad, plaintext, ikmE) {
  const { enc, ciphertext } = hpkeSeal(pkR, info, aad, plaintext, ikmE);
  return Buffer.concat([Buffer.from([1]), enc, ciphertext]);
}

function openBlob(skR, info, aad, blob) {
  assert(blob[0] === 1 && blob.length >= 49, 'sealed blob format');
  return hpkeOpen(skR, blob.subarray(1, 33), info, aad, blob.subarray(33));
}

// ---------------------------------------------------------------------------------------------
// Crockford base32 and human-readable codes
// ---------------------------------------------------------------------------------------------

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

function crockford(bytes) {
  let out = '';
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = ((buffer << 8) | byte) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      out += CROCKFORD[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += CROCKFORD[(buffer << (5 - bits)) & 31];
  return out;
}

const groups = (s, size) => s.match(new RegExp(`.{1,${size}}`, 'g')).join('-');

const secretKeyCode = (secretKey) =>
  `CS1-${groups(crockford(Buffer.concat([secretKey, sha256(secretKey).subarray(0, 1)])), 4)}`;

const recoveryKeyCode = (recoveryKey) =>
  `CR1-${groups(crockford(Buffer.concat([recoveryKey, sha256(recoveryKey).subarray(0, 3)])), 4)}`;

const fingerprintCode = (digest) => groups(crockford(digest.subarray(0, 20)), 4);


// ---------------------------------------------------------------------------------------------
// Known-answer self-tests for the primitives written out above
// ---------------------------------------------------------------------------------------------

function selfTest() {
  // draft-irtf-cfrg-xchacha-03 §2.2.1
  const hKey = fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
  const hNonce = fromHex('000000090000004a0000000031415927');
  assert(
    hex(hchacha20(hKey, hNonce)) === '82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc',
    'HChaCha20 KAT',
  );

  // draft-irtf-cfrg-xchacha-03 §A.3.1
  const sealed = xchachaSeal(
    fromHex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'),
    fromHex('404142434445464748494a4b4c4d4e4f5051525354555657'),
    fromHex('50515253c0c1c2c3c4c5c6c7'),
    utf8("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."),
  );
  assert(hex(sealed).startsWith('bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb'), 'XChaCha20-Poly1305 KAT ciphertext');
  assert(hex(sealed).endsWith('c0875924c1c7987947deafd8780acf49'), 'XChaCha20-Poly1305 KAT tag');

  // RFC 5869 test case 1 (manual extract + expand)
  const prk = hkdfExtract(fromHex('000102030405060708090a0b0c'), Buffer.alloc(22, 0x0b));
  assert(
    hex(hkdfExpand(prk, fromHex('f0f1f2f3f4f5f6f7f8f9'), 42)) ===
      '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
    'HKDF KAT',
  );

  // RFC 8032 §7.1 test 1
  const seed = fromHex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
  assert(hex(ed25519PublicFromSeed(seed)) === 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', 'Ed25519 KAT');

  // RFC 7748 §6.1 (Alice's key pair)
  assert(
    hex(x25519PublicFromPrivate(fromHex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'))) ===
      '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a',
    'X25519 KAT',
  );

  // RFC 9106 §5.3 Argon2id (exercises node:crypto directly, with secret and associated data)
  const tag = crypto.argon2Sync('argon2id', {
    message: Buffer.alloc(32, 1), nonce: Buffer.alloc(16, 2), secret: Buffer.alloc(8, 3),
    associatedData: Buffer.alloc(12, 4), parallelism: 4, tagLength: 32, memory: 32, passes: 3,
  });
  assert(hex(tag) === '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659', 'Argon2id KAT');

  // Crockford: 'f' (0x66) -> bits 01100 110 -> "CR"
  assert(crockford(utf8('f')) === 'CR', 'Crockford base32');

  // Round trips
  const k = fixture('selftest-key', 32);
  const n = fixture('selftest-nonce', 24);
  assert(hex(xchachaOpen(k, n, utf8('ad'), xchachaSeal(k, n, utf8('ad'), utf8('hello')))) === hex(utf8('hello')), 'XChaCha round trip');
  const recipient = fixture('selftest-recipient', 32);
  const blob = sealBlob(x25519PublicFromPrivate(recipient), utf8('info'), utf8('aad'), utf8('hi'), fixture('selftest-ikm', 32));
  assert(openBlob(recipient, utf8('info'), utf8('aad'), blob).toString() === 'hi', 'HPKE round trip');
  assert(hex(unpad(pad(utf8('x')))) === hex(utf8('x')) && pad(Buffer.alloc(255)).length === 256 && pad(Buffer.alloc(256)).length === 512, 'padding');
}

// ---------------------------------------------------------------------------------------------
// Strict checks shared by the reference verifier below (PROTOCOL.md §2, §8.1, §10)
// ---------------------------------------------------------------------------------------------

const GROUP_ORDER = 2n ** 252n + 27742317777372353535851937790883648493n;
const FIELD_PRIME = 2n ** 255n - 19n;

/** Encodings of the eight small-order points of edwards25519. */
const SMALL_ORDER = [
  '0100000000000000000000000000000000000000000000000000000000000000',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0000000000000000000000000000000000000000000000000000000000000080',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
];

const littleEndian = (b) => BigInt(`0x${hex(Buffer.from(b).reverse()) || '0'}`);
const yOf = (point) => littleEndian(point) & ((1n << 255n) - 1n);

/** Strict Ed25519 check; returns null when valid, else the reason. */
function strictVerify(publicKey, message, signatureBlob) {
  if (signatureBlob.length !== 65 || signatureBlob[0] !== 1) return 'bad_signature';
  const signature = signatureBlob.subarray(1);
  if (littleEndian(signature.subarray(32)) >= GROUP_ORDER) return 'non_canonical_signature';
  if (yOf(signature.subarray(0, 32)) >= FIELD_PRIME) return 'non_canonical_signature';
  if (yOf(publicKey) >= FIELD_PRIME) return 'non_canonical_key';
  if (SMALL_ORDER.includes(hex(publicKey))) return 'small_order_key';
  const key = crypto.createPublicKey({ key: Buffer.concat([fromHex('302a300506032b6570032100'), publicKey]), format: 'der', type: 'spki' });
  return crypto.verify(null, message, key, signature) ? null : 'bad_signature';
}

/** Strict unpadding (PROTOCOL.md §8.1); returns the content or throws `bad_padding`. */
function strictUnpad(data) {
  if (data.length === 0 || data.length % PAD_BLOCK !== 0) throw new Error('bad_padding');
  let i = data.length - 1;
  while (i >= 0 && data[i] === 0) i--;
  if (i < 0 || data[i] !== 0x80 || data.length - i > PAD_BLOCK) throw new Error('bad_padding');
  return data.subarray(0, i);
}

/** Strict decoding of a prefixed code (PROTOCOL.md §10); returns the bytes or throws `bad_code`. */
function decodeCode(prefix, code, length, checksumLength) {
  const fail = () => {
    throw new Error('bad_code');
  };
  const normalized = code.toUpperCase().replace(/[\s-]/g, '');
  if (!normalized.startsWith(prefix.replace('-', ''))) fail();
  const body = normalized.slice(prefix.replace('-', '').length).replace(/O/g, '0').replace(/[IL]/g, '1');
  const total = length + checksumLength;
  if (body.length !== Math.ceil((total * 8) / 5)) fail();
  let value = 0n;
  for (const char of body) {
    const digit = CROCKFORD.indexOf(char);
    if (digit < 0) fail();
    value = (value << 5n) | BigInt(digit);
  }
  const padding = BigInt(body.length * 5 - total * 8);
  if ((value & ((1n << padding) - 1n)) !== 0n) fail();
  value >>= padding;
  const bytes = Buffer.from(value.toString(16).padStart(total * 2, '0'), 'hex');
  const data = bytes.subarray(0, length);
  if (!sha256(data).subarray(0, checksumLength).equals(bytes.subarray(length))) fail();
  return data;
}

// ---------------------------------------------------------------------------------------------
// Fixtures shared by all vectors
// ---------------------------------------------------------------------------------------------

const OWNER_ID = '0192f5a4-7c3e-7b1a-9d2e-5f6a7b8c9d0e';
const BOB_ID = '0192f5a4-7c3e-7b1a-9d2e-5f6a7b8c9d1f';
const CAROL_ID = '0192f5a4-7c3e-7b1a-9d2e-5f6a7b8c9d2a';
const DAVE_ID = '0192f5a4-7c3e-7b1a-9d2e-5f6a7b8c9d3b';
const VAULT_ID = '0192f5a3-0000-7aaa-8bbb-0123456789ab';
/** A node's id (PROTOCOL.md §8.1): UUIDv5 under its owner of its home vault and key. */
function nodeIdOf(ownerUserId, homeVaultId, nodeKey) {
  return uuidV5(ownerUserId, new Canonical().label('cloak/v1/node').uuid(homeVaultId).text(nodeKey).bytes());
}
/** Another vault, home of the node the scenario shares into its vault. */
const OTHER_VAULT_ID = '0192f5a3-0000-7aaa-8bbb-0123456789cd';
const NODE_KEY = 'server-1';
const NODE_ID = nodeIdOf(OWNER_ID, VAULT_ID, NODE_KEY);
const SHARED_NODE_KEY = 'server-2';
const SHARED_NODE_ID = nodeIdOf(OWNER_ID, OTHER_VAULT_ID, SHARED_NODE_KEY);
const NODE_TYPE = 'compute.vps';

function identity(name, userId, keyVersion) {
  const encryptionPrivateKey = fixture(`${name}-v${keyVersion}-x25519`, 32);
  const signingSeed = fixture(`${name}-v${keyVersion}-ed25519`, 32);
  const recoveryKey = fixture(`${name}-v${keyVersion}-recovery-key`, 32);
  const recoverySigningSeed = hkdf(recoveryKey, uuidBytes(userId), utf8('cloak/v1/recovery-sign'));
  return {
    name: `${name}-v${keyVersion}`,
    userId,
    keyVersion,
    encryptionPrivateKey,
    signingSeed,
    recoveryKey,
    recoverySigningSeed,
    encryptionPublicKey: x25519PublicFromPrivate(encryptionPrivateKey),
    signingPublicKey: ed25519PublicFromSeed(signingSeed),
    recoverySigningPublicKey: ed25519PublicFromSeed(recoverySigningSeed),
  };
}

const ownerV1 = identity('owner', OWNER_ID, 1);
const ownerV2 = identity('owner', OWNER_ID, 2);
const bob = identity('bob', BOB_ID, 1);
const carol = identity('carol', CAROL_ID, 1);
const dave = identity('dave', DAVE_ID, 1);
const allIdentities = [ownerV1, ownerV2, bob, carol, dave];

/** The server's key store: public keys per user and version. */
const directory = (userId, keyVersion) =>
  allIdentities.find((id) => id.userId === userId && id.keyVersion === keyVersion);

const identityJson = (id) => ({
  name: id.name,
  userId: id.userId,
  keyVersion: id.keyVersion,
  encryptionPrivateKey: hex(id.encryptionPrivateKey),
  encryptionPublicKey: hex(id.encryptionPublicKey),
  signingSeed: hex(id.signingSeed),
  signingPublicKey: hex(id.signingPublicKey),
  recoveryKey: hex(id.recoveryKey),
  recoverySigningSeed: hex(id.recoverySigningSeed),
  recoverySigningPublicKey: hex(id.recoverySigningPublicKey),
  keysDigest: hex(keysDigest(id)),
});

const localStateKeys = [fixture('owner-local-state-key-1', 32), fixture('owner-local-state-key-2', 32)];
const vaultKeys = [fixture('vault-key-v1', 32), fixture('vault-key-v2', 32), fixture('vault-key-v3', 32)];

const canonicalCase = (name, c) => ({ name, fields: c.fields, expected: hex(c.bytes()) });

// ---------------------------------------------------------------------------------------------
// Key statements (PROTOCOL.md §5.2)
// ---------------------------------------------------------------------------------------------

function statement(id, previous, recoverySigner = previous) {
  const message = keyStatementMessage(id, previous === undefined ? undefined : keysDigest(previous));
  return {
    userId: id.userId,
    keyVersion: id.keyVersion,
    keysDigest: hex(keysDigest(id)),
    previousKeysDigest: hex(previous === undefined ? ZERO32 : keysDigest(previous)),
    fields: message.fields,
    message: hex(message.bytes()),
    signature: hex(signBlob(id.signingSeed, message.bytes())),
    ...(previous === undefined ? {} : { recoverySignature: hex(signBlob(recoverySigner.recoverySigningSeed, message.bytes())) }),
  };
}

/** Checks one statement against the version it follows; returns null when valid, else the reason. */
function verifyStatement(s, previous) {
  const id = directory(s.userId, s.keyVersion);
  if (id === undefined || hex(keysDigest(id)) !== s.keysDigest) return 'bad_statement';
  const message = keyStatementMessage(id, previous === undefined ? undefined : keysDigest(previous)).bytes();
  if (hex(message) !== s.message) return 'bad_statement';
  if (strictVerify(id.signingPublicKey, message, fromHex(s.signature)) !== null) return 'bad_statement';
  if (previous === undefined) return s.recoverySignature === undefined ? null : 'bad_statement';
  if (s.recoverySignature === undefined) return 'bad_statement';
  return strictVerify(previous.recoverySigningPublicKey, message, fromHex(s.recoverySignature)) === null ? null : 'bad_statement';
}

// ---------------------------------------------------------------------------------------------
// Reference vault log and section verifier (PROTOCOL.md §7.6, §8.4)
// ---------------------------------------------------------------------------------------------

const roleAtLeast = (role, needed) => role !== undefined && ROLE[role] >= ROLE[needed];
const isZero = (b) => b === undefined || b.equals(ZERO32);

const SECTION_NAME = /^[a-z][a-z0-9_]{0,63}$/;
/** Most names one share may hold (PROTOCOL.md §7.7). */
const MAX_SHARE_NAMES = 1000;

/** A node entry's `sections` (PROTOCOL.md §7.1): `*`, or names ascending, unique, comma-joined. */
function parseScope(sections) {
  if (sections === '*') return '*';
  if (typeof sections !== 'string' || sections === '') return undefined;
  const names = sections.split(',');
  const sorted = names.every((name, i) => SECTION_NAME.test(name) && (i === 0 || Buffer.compare(utf8(names[i - 1]), utf8(name)) < 0));
  return sorted ? names : undefined;
}

/** Whether a node key has 1 to 255 bytes (PROTOCOL.md §8.1). */
const validNodeKey = (key) => typeof key === 'string' && utf8(key).length >= 1 && utf8(key).length <= 255;

/** Replays a log; returns { ok, reason, failSeq, state } where state holds per-seq snapshots. */
function replayLog(entries, trustedVersions) {
  const fail = (reason, seq) => ({ ok: false, reason, failSeq: seq });
  let members = new Map();
  let keyVersion = 0;
  const commitments = new Map();
  const snapshots = [];
  const checkpoints = [];
  let previousHash = ZERO32;
  let request = null;
  // Nodes shared into the vault (§7.7): owner, and the seq from which `*` and each name is shared.
  const shares = new Map();
  // Nodes created here, their home (§7.7): owner, key and the seq of `node_created`.
  const created = new Map();
  let deleted = false;

  for (const [index, e] of entries.entries()) {
    const seq = index + 1;
    if (e.seq !== seq || !e.previousHash.equals(previousHash)) return fail('broken_chain', seq);
    if (deleted) return fail('vault_deleted', seq);
    if (e.requestEnd !== 0 && e.requestEnd !== 1) return fail('bad_flag', seq);
    const message = logMessage(e).bytes();
    const hash = sha256(message);
    if (e.entryHash !== undefined && !e.entryHash.equals(hash)) return fail('broken_chain', seq);

    // Who signs, with which committed keys (§7.3, §7.6 rule 2).
    const author = directory(e.authorUserId, e.authorKeyVersion);
    if (author === undefined) return fail('unverified_keys', seq);
    const selfCommitting = e.kind === 'vault_created' || e.kind === 'member_keys_replaced';
    if (selfCommitting) {
      if (e.subjectUserId !== e.authorUserId || e.subjectKeyVersion !== e.authorKeyVersion || !keysDigest(author).equals(e.subjectKeys)) {
        return fail('unverified_keys', seq);
      }
    } else {
      const membership = members.get(e.authorUserId);
      if (membership === undefined || membership.keyVersion !== e.authorKeyVersion || !membership.digest.equals(keysDigest(author))) {
        return fail('unverified_keys', seq);
      }
    }
    const signatureReason = strictVerify(author.signingPublicKey, message, e.signature);
    if (signatureReason !== null) return fail(signatureReason, seq);

    // Requests: one author; rights from the state before the request (§7.3).
    if (request === null) request = { author: e.authorUserId, before: members, kinds: [] };
    else if (request.author !== e.authorUserId) return fail('bad_request_shape', seq);
    request.kinds.push({ kind: e.kind, self: e.subjectUserId === e.authorUserId });
    const rights = request.before.get(e.authorUserId)?.role;

    const has = {
      subject: e.subjectUserId !== undefined, role: e.role !== undefined, subjectKeys: !isZero(e.subjectKeys),
      keyCommitment: !isZero(e.keyCommitment), checkpoint: !isZero(e.checkpoint),
      // Absent is the nil UUID or the empty string (§3, §7.1), whatever the JSON says.
      node: (e.nodeId ?? NIL_UUID) !== NIL_UUID, home: (e.homeVaultId ?? NIL_UUID) !== NIL_UUID,
      nodeKey: (e.nodeKey ?? '') !== '', sections: (e.sections ?? '') !== '',
    };
    const expectFields = (wanted) => {
      for (const [field, present] of Object.entries(has)) {
        if (field === 'checkpoint') continue;
        if (present !== wanted.includes(field)) return false;
      }
      return true;
    };
    const next = new Map(members);
    const subject = members.get(e.subjectUserId);
    const committed = (s) => s !== undefined && s.digest.equals(e.subjectKeys) && s.keyVersion === e.subjectKeyVersion;
    const keepsOwner = (map) => [...map.values()].some((m) => m.role === 'owner');

    switch (e.kind) {
      case 'vault_created':
        if (seq !== 1 || e.role !== 'owner' || e.keyVersion !== 1 || has.checkpoint) return fail('bad_request_shape', seq);
        if (!expectFields(['subject', 'role', 'subjectKeys', 'keyCommitment'])) return fail('unexpected_field', seq);
        next.set(e.authorUserId, { role: 'owner', keyVersion: e.subjectKeyVersion, digest: e.subjectKeys });
        keyVersion = 1;
        commitments.set(1, e.keyCommitment);
        break;
      case 'member_added':
        if (!expectFields(['subject', 'role', 'subjectKeys']) || has.checkpoint) return fail('unexpected_field', seq);
        if (e.keyVersion !== keyVersion) return fail('bad_request_shape', seq);
        if (subject !== undefined) return fail('invalid_entry', seq);
        if (!roleAtLeast(rights, e.role === 'owner' ? 'owner' : 'admin')) return fail('not_authorized', seq);
        if (directory(e.subjectUserId, e.subjectKeyVersion) === undefined ||
          !keysDigest(directory(e.subjectUserId, e.subjectKeyVersion)).equals(e.subjectKeys)) return fail('unverified_keys', seq);
        next.set(e.subjectUserId, { role: e.role, keyVersion: e.subjectKeyVersion, digest: e.subjectKeys });
        break;
      case 'member_role_set': {
        if (!expectFields(['subject', 'role', 'subjectKeys'])) return fail('unexpected_field', seq);
        if (e.keyVersion !== keyVersion) return fail('bad_request_shape', seq);
        if (!committed(subject) || subject.role === e.role) return fail('invalid_entry', seq);
        const lowersSelf = e.subjectUserId === e.authorUserId && ROLE[e.role] < ROLE[subject.role];
        const needed = subject.role === 'owner' || e.role === 'owner' ? 'owner' : 'admin';
        if (!lowersSelf && !roleAtLeast(rights, needed)) return fail('not_authorized', seq);
        const losesWrite = roleAtLeast(subject.role, 'editor') && !roleAtLeast(e.role, 'editor');
        if (losesWrite && !has.checkpoint) return fail('missing_checkpoint', seq);
        if (!losesWrite && has.checkpoint) return fail('unexpected_field', seq);
        next.set(e.subjectUserId, { ...subject, role: e.role });
        if (!keepsOwner(next)) return fail('no_owner', seq);
        break;
      }
      case 'member_removed': {
        if (!expectFields(['subject', 'subjectKeys'])) return fail('unexpected_field', seq);
        if (e.keyVersion !== keyVersion) return fail('bad_request_shape', seq);
        if (!committed(subject)) return fail('invalid_entry', seq);
        const leaving = e.subjectUserId === e.authorUserId;
        if (leaving) {
          const needsCheckpoint = roleAtLeast(subject.role, 'editor');
          if (needsCheckpoint && !has.checkpoint) return fail('missing_checkpoint', seq);
          if (!needsCheckpoint && has.checkpoint) return fail('unexpected_field', seq);
        } else {
          if (has.checkpoint) return fail('unexpected_field', seq);
          if (!roleAtLeast(rights, subject.role === 'owner' ? 'owner' : 'admin')) return fail('not_authorized', seq);
        }
        next.delete(e.subjectUserId);
        if (!keepsOwner(next)) return fail('no_owner', seq);
        // A share ends when its owner stops being a member (§7.7).
        for (const [nodeId, share] of shares) if (share.owner === e.subjectUserId) shares.delete(nodeId);
        break;
      }
      case 'member_keys_replaced': {
        if (!expectFields(['subject', 'subjectKeys'])) return fail('unexpected_field', seq);
        if (e.keyVersion !== keyVersion) return fail('bad_request_shape', seq);
        const current = members.get(e.authorUserId);
        if (current === undefined) return fail('invalid_entry', seq);
        const versions = trustedVersions.get(e.authorUserId) ?? new Set();
        for (let v = current.keyVersion + 1; v <= e.subjectKeyVersion; v++) {
          if (!versions.has(v)) return fail('unverified_keys', seq);
        }
        if (e.subjectKeyVersion <= current.keyVersion) return fail('unverified_keys', seq);
        const needsCheckpoint = roleAtLeast(current.role, 'editor');
        if (needsCheckpoint && !has.checkpoint) return fail('missing_checkpoint', seq);
        if (!needsCheckpoint && has.checkpoint) return fail('unexpected_field', seq);
        next.set(e.authorUserId, { ...current, keyVersion: e.subjectKeyVersion, digest: e.subjectKeys });
        break;
      }
      case 'key_rotated':
        if (!expectFields(['keyCommitment'])) return fail('unexpected_field', seq);
        if (e.keyVersion !== keyVersion + 1) return fail('bad_request_shape', seq);
        if (!has.checkpoint) return fail('missing_checkpoint', seq);
        if (!roleAtLeast(rights, 'admin')) return fail('not_authorized', seq);
        keyVersion += 1;
        commitments.set(keyVersion, e.keyCommitment);
        break;
      case 'node_created': {
        if (!expectFields(['node', 'nodeKey']) || has.checkpoint) return fail('unexpected_field', seq);
        if (e.keyVersion !== keyVersion) return fail('bad_request_shape', seq);
        if (!validNodeKey(e.nodeKey) || created.has(e.nodeId)) return fail('invalid_entry', seq);
        if (!roleAtLeast(rights, 'editor') || nodeIdOf(e.authorUserId, e.vaultId, e.nodeKey) !== e.nodeId) {
          return fail('not_authorized', seq);
        }
        created.set(e.nodeId, { owner: e.authorUserId, nodeKey: e.nodeKey, seq });
        break;
      }
      case 'node_shared': {
        if (!expectFields(['node', 'home', 'nodeKey', 'sections']) || has.checkpoint) return fail('unexpected_field', seq);
        if (e.keyVersion !== keyVersion) return fail('bad_request_shape', seq);
        const scope = parseScope(e.sections);
        if (scope === undefined || e.homeVaultId === e.vaultId || !validNodeKey(e.nodeKey)) return fail('invalid_entry', seq);
        const sharedNames = new Set(shares.get(e.nodeId)?.names.keys() ?? []);
        if (scope !== '*' && shares.get(e.nodeId)?.all === undefined) for (const name of scope) sharedNames.add(name);
        if (sharedNames.size > MAX_SHARE_NAMES) return fail('invalid_entry', seq);
        if (!roleAtLeast(rights, 'admin') || nodeIdOf(e.authorUserId, e.homeVaultId, e.nodeKey) !== e.nodeId) {
          return fail('not_authorized', seq);
        }
        const share = shares.get(e.nodeId) ??
          { owner: e.authorUserId, homeVaultId: e.homeVaultId, nodeKey: e.nodeKey, all: undefined, names: new Map() };
        if (scope === '*') share.all ??= seq;
        else for (const name of scope) if (share.all === undefined && !share.names.has(name)) share.names.set(name, seq);
        shares.set(e.nodeId, share);
        break;
      }
      case 'node_unshared': {
        if (!expectFields(['node', 'sections']) || has.checkpoint) return fail('unexpected_field', seq);
        if (e.keyVersion !== keyVersion) return fail('bad_request_shape', seq);
        const scope = parseScope(e.sections);
        const share = shares.get(e.nodeId);
        if (scope === undefined || share === undefined) return fail('invalid_entry', seq);
        if (!roleAtLeast(rights, 'admin') && e.authorUserId !== share.owner) return fail('not_authorized', seq);
        if (scope === '*') {
          shares.delete(e.nodeId);
          break;
        }
        if (share.all !== undefined || scope.some((name) => !share.names.has(name))) return fail('invalid_entry', seq);
        for (const name of scope) share.names.delete(name);
        if (share.names.size === 0) shares.delete(e.nodeId);
        break;
      }
      case 'vault_deleted':
        if (!expectFields([]) || has.checkpoint) return fail('unexpected_field', seq);
        if (e.keyVersion !== keyVersion) return fail('bad_request_shape', seq);
        if (!roleAtLeast(rights, 'owner')) return fail('not_authorized', seq);
        deleted = true;
        break;
      default:
        return fail('invalid_entry', seq);
    }

    if (has.checkpoint) {
      if (e.checkpointLeaves !== undefined && !checkpointOf(e.checkpointLeaves).root.equals(e.checkpoint)) {
        return fail('bad_checkpoint', seq);
      }
      checkpoints.push({ seq, root: e.checkpoint, leaves: e.checkpointLeaves });
    }

    if (e.requestEnd === 1) {
      const kinds = request.kinds;
      const last = kinds[kinds.length - 1];
      const single = kinds.length === 1 &&
        (['vault_created', 'member_added', 'member_role_set', 'member_keys_replaced', 'node_created', 'node_shared',
          'node_unshared', 'vault_deleted'].includes(last.kind) ||
          (last.kind === 'member_removed' && last.self));
      const rotation = last.kind === 'key_rotated' &&
        kinds.slice(0, -1).every((k) => k.kind === 'member_removed' && !k.self);
      if (!single && !rotation) return fail('bad_request_shape', seq);
      request = null;
    }

    members = next;
    previousHash = hash;
    // `vault_deleted` is no head: nothing may cite it (§12.3).
    snapshots.push({ seq, hash, head: e.requestEnd === 1 && e.kind !== 'vault_deleted', keyVersion, members: new Map(members) });
  }
  if (request !== null) return fail('unfinished_request', entries.length);
  return { ok: true, state: { snapshots, checkpoints, commitments, shares, created, deleted } };
}

/** Checks one write against a verified log; returns null when accepted, else the reason. */
function verifyWrite(w, log) {
  // §8.4: a deleted vault's writes first, then rules 1, 2, 3, 6 and 4 in this order; content last.
  if (log.deleted) return 'vault_deleted';
  const snapshot = log.snapshots[w.logSeq - 1];
  if (snapshot === undefined || !snapshot.head) return 'not_a_head';
  if (!snapshot.hash.equals(w.logHeadHash)) return 'fork';
  if (w.vaultKeyVersion !== snapshot.keyVersion) return 'wrong_key_version';
  if ((w.deleted === 1) !== (w.ciphertext === undefined)) return 'bad_deletion';
  const writer = directory(w.writerUserId, w.writerKeyVersion);
  const membership = snapshot.members.get(w.writerUserId);
  if (writer === undefined || membership === undefined || membership.keyVersion !== w.writerKeyVersion ||
    !membership.digest.equals(keysDigest(writer)) || !roleAtLeast(membership.role, 'editor')) return 'not_an_editor';
  const message = sectionWriteMessage(w).bytes();
  const signatureReason = strictVerify(writer.signingPublicKey, message, w.signature);
  if (signatureReason !== null) return signatureReason;

  // Rule 6: every write names its node truthfully; one with content stands only where the node
  // lives, as the owner's entries recorded it.
  if (!validNodeKey(w.nodeKey) || nodeIdOf(w.ownerUserId, w.homeVaultId, w.nodeKey) !== w.nodeId) return 'bad_node';
  if (w.deleted !== 1) {
    const matches = (entry) => entry !== undefined && entry.owner === w.ownerUserId && entry.nodeKey === w.nodeKey;
    if (w.homeVaultId === w.vaultId) {
      const node = log.created.get(w.nodeId);
      if (!matches(node) || node.seq > w.logSeq) return 'not_shared';
    } else {
      const share = log.shares.get(w.nodeId);
      const since = share === undefined ? undefined : (share.names.get(w.sectionName) ?? share.all);
      if (!matches(share) || share.homeVaultId !== w.homeVaultId || since === undefined || since > w.logSeq) return 'not_shared';
    }
  }

  // Rule 4: in the first checkpoint after the head, and the very leaf of the latest one.
  const later = log.checkpoints.filter((c) => c.seq > w.logSeq);
  const writeHash = sha256(message);
  const leafOf = (c) => c.leaves.find((l) => l.nodeId === w.nodeId && l.sectionName === w.sectionName);
  if (w.deleted === 1) {
    // A deletion is never a leaf: every checkpoint after its head must hold none for the section.
    for (const c of [later[0], later.at(-1)]) {
      const leaf = c === undefined ? undefined : leafOf(c);
      if (leaf === undefined) continue;
      return leaf.dataVersion > w.dataVersion ? 'rollback' : 'not_in_checkpoint';
    }
    return null;
  }
  const isThis = (l) => l !== undefined && l.dataVersion === w.dataVersion && l.writeHash.equals(writeHash);
  const first = later[0];
  const latest = later.at(-1);
  if (first !== undefined && !isThis(leafOf(first))) return 'not_in_checkpoint';
  if (latest !== undefined && latest !== first) {
    const leaf = leafOf(latest);
    if (leaf === undefined) return 'not_in_checkpoint';
    if (leaf.dataVersion > w.dataVersion) return 'rollback';
    if (!isThis(leaf)) return 'fork';
  }

  // Content, of a write that stands.
  const key = contentKeyOf(vaultKeys[w.vaultKeyVersion - 1], w.vaultId);
  if (!keyCommitmentOf(vaultKeys[w.vaultKeyVersion - 1], w.vaultId, w.vaultKeyVersion).equals(log.commitments.get(w.vaultKeyVersion))) {
    return 'key_mismatch';
  }
  try {
    strictUnpad(decryptBlob(key, sectionContentAd(w.vaultId, w.nodeId, w.sectionName, w.vaultKeyVersion).bytes(), w.ciphertext));
  } catch (error) {
    return error.message === 'bad_padding' ? 'bad_padding' : 'decryption_failed';
  }
  return null;
}

/** What checkpoint [c] holds for a section: the leaf with its path, or the neighbours that show it absent. */
function checkpointProofOf(c, section) {
  const hashes = c.leaves.map((l) => leafHash(leafData(l)));
  const leafProof = (i) => {
    const path = auditPath(i, hashes);
    assert(verifyInclusion(i, hashes.length, hashes[i], path, c.root), `proof ${c.seq}/${i}`);
    const l = c.leaves[i];
    return {
      index: i,
      leaf: { nodeId: l.nodeId, sectionName: l.sectionName, dataVersion: l.dataVersion, writeHash: hex(l.writeHash) },
      path: path.map(hex),
    };
  };
  const index = c.leaves.findIndex((l) => compareSections(l, section) === 0);
  if (index >= 0) return { checkpointSeq: c.seq, size: hashes.length, inclusion: leafProof(index) };
  const insertion = c.leaves.findIndex((l) => compareSections(l, section) > 0);
  const at = insertion < 0 ? c.leaves.length : insertion;
  return {
    checkpointSeq: c.seq,
    size: hashes.length,
    ...(at > 0 ? { before: leafProof(at - 1) } : {}),
    ...(at < c.leaves.length ? { after: leafProof(at) } : {}),
  };
}

// ---------------------------------------------------------------------------------------------
// The scenario of vault-log.json and sections.json
// ---------------------------------------------------------------------------------------------

/**
 * One vault: the owner creates it and adds Bob (editor) and Carol (viewer); Bob writes; Bob is
 * lowered to viewer; Carol is removed with a rotation; the owner writes; the owner replaces their
 * keys; the owner writes and deletes with the new keys; Bob leaves.
 */
function scenario() {
  const entries = [];
  const writes = new Map();
  let nonceCounter = 0;

  const append = (fields, signer) => {
    const previous = entries[entries.length - 1];
    const e = {
      vaultId: VAULT_ID,
      seq: entries.length + 1,
      previousHash: previous === undefined ? ZERO32 : previous.entryHash,
      keyVersion: fields.keyVersion,
      requestEnd: 1,
      authorUserId: signer.userId,
      authorKeyVersion: signer.keyVersion,
      ...fields,
    };
    const message = logMessage(e).bytes();
    e.entryHash = sha256(message);
    e.signature = signBlob(signer.signingSeed, message);
    entries.push(e);
    return e;
  };

  const write = (name, fields, signer, content) => {
    const head = entries[fields.logSeq - 1];
    const w = {
      vaultId: VAULT_ID,
      nodeId: NODE_ID,
      nodeType: NODE_TYPE,
      homeVaultId: VAULT_ID,
      ownerUserId: OWNER_ID,
      nodeKey: NODE_KEY,
      deleted: 0,
      logHeadHash: head.entryHash,
      writerUserId: signer.userId,
      writerKeyVersion: signer.keyVersion,
      ...fields,
    };
    if (content !== undefined) {
      const key = contentKeyOf(vaultKeys[w.vaultKeyVersion - 1], VAULT_ID);
      const ad = sectionContentAd(VAULT_ID, w.nodeId, w.sectionName, w.vaultKeyVersion).bytes();
      w.content = content;
      w.ciphertext = encryptBlob(key, fixture(`write-nonce-${nonceCounter++}`, 24), ad, pad(utf8(JSON.stringify(content))));
    }
    const message = sectionWriteMessage(w).bytes();
    w.writeHash = sha256(message);
    w.signature = signBlob(signer.signingSeed, message);
    writes.set(name, w);
    return w;
  };

  const leafOf = (w) => ({ nodeId: w.nodeId, sectionName: w.sectionName, dataVersion: w.dataVersion, writeHash: w.writeHash });

  const e1 = append({
    kind: 'vault_created', subjectUserId: OWNER_ID, role: 'owner', keyVersion: 1, subjectKeys: keysDigest(ownerV1),
    subjectKeyVersion: 1, keyCommitment: keyCommitmentOf(vaultKeys[0], VAULT_ID, 1),
  }, ownerV1);
  // The node the scenario writes is created here, its home, by its owner (§7.7).
  append({ kind: 'node_created', keyVersion: 1, nodeId: NODE_ID, nodeKey: NODE_KEY }, ownerV1);
  append({ kind: 'member_added', subjectUserId: BOB_ID, role: 'editor', keyVersion: 1, subjectKeys: keysDigest(bob), subjectKeyVersion: 1 }, ownerV1);
  append({ kind: 'member_added', subjectUserId: CAROL_ID, role: 'viewer', keyVersion: 1, subjectKeys: keysDigest(carol), subjectKeyVersion: 1 }, ownerV1);

  const w1 = write('owner-general-1', { sectionName: 'general', vaultKeyVersion: 1, dataVersion: 1, logSeq: 4 }, ownerV1, { name: 'db-1' });
  const w2 = write('bob-secrets-1', { sectionName: 'secrets', vaultKeyVersion: 1, dataVersion: 1, logSeq: 4 }, bob, { password: 'hunter2' });
  const w3 = write('bob-general-2', { sectionName: 'general', vaultKeyVersion: 1, dataVersion: 2, logSeq: 4, previousWriteHash: w1.writeHash }, bob, { name: 'db-1', host: '10.0.0.5' });

  const demotion = checkpointOf([leafOf(w3), leafOf(w2)]);
  append({
    kind: 'member_role_set', subjectUserId: BOB_ID, role: 'viewer', keyVersion: 1, subjectKeys: keysDigest(bob), subjectKeyVersion: 1,
    checkpoint: demotion.root, checkpointLeaves: demotion.leaves,
  }, ownerV1);

  append({ kind: 'member_removed', subjectUserId: CAROL_ID, keyVersion: 1, subjectKeys: keysDigest(carol), subjectKeyVersion: 1, requestEnd: 0 }, ownerV1);
  const rotation = checkpointOf([leafOf(w3), leafOf(w2)]);
  append({
    kind: 'key_rotated', keyVersion: 2, keyCommitment: keyCommitmentOf(vaultKeys[1], VAULT_ID, 2),
    checkpoint: rotation.root, checkpointLeaves: rotation.leaves,
  }, ownerV1);

  const w4 = write('owner-general-3', { sectionName: 'general', vaultKeyVersion: 2, dataVersion: 3, logSeq: 7, previousWriteHash: w3.writeHash }, ownerV1, { name: 'db-1', host: '10.0.0.6' });

  const replacement = checkpointOf([leafOf(w4), leafOf(w2)]);
  append({
    kind: 'member_keys_replaced', subjectUserId: OWNER_ID, keyVersion: 2, subjectKeys: keysDigest(ownerV2), subjectKeyVersion: 2,
    checkpoint: replacement.root, checkpointLeaves: replacement.leaves,
  }, ownerV2);

  const w5 = write('owner-secrets-2', { sectionName: 'secrets', vaultKeyVersion: 2, dataVersion: 2, logSeq: 8, previousWriteHash: w2.writeHash }, ownerV2, { password: 'correct horse' });
  write('owner-general-deleted', { sectionName: 'general', vaultKeyVersion: 2, dataVersion: 4, deleted: 1, logSeq: 8, previousWriteHash: w4.writeHash }, ownerV2);
  append({ kind: 'member_removed', subjectUserId: BOB_ID, keyVersion: 2, subjectKeys: keysDigest(bob), subjectKeyVersion: 1 }, bob);

  // A checkpoint holds live sections only: the deleted 'general' is not a leaf (§7.5).
  const renewal = checkpointOf([leafOf(w5)]);
  append({
    kind: 'key_rotated', keyVersion: 3, keyCommitment: keyCommitmentOf(vaultKeys[2], VAULT_ID, 3),
    checkpoint: renewal.root, checkpointLeaves: renewal.leaves,
  }, ownerV2);

  // A node homed in another vault, shared here by its owner: two names, then one taken back (§7.7).
  const shared = { nodeId: SHARED_NODE_ID, homeVaultId: OTHER_VAULT_ID, nodeKey: SHARED_NODE_KEY };
  append({ kind: 'node_shared', keyVersion: 3, ...shared, sections: 'notes,secrets' }, ownerV2);
  write('owner-shared-notes-early', { ...shared, sectionName: 'notes', vaultKeyVersion: 3, dataVersion: 1, logSeq: 10 }, ownerV2, { note: 'before' });
  write('owner-shared-notes', { ...shared, sectionName: 'notes', vaultKeyVersion: 3, dataVersion: 1, logSeq: 11 }, ownerV2, { note: 'shared' });
  const sharedSecrets = write('owner-shared-secrets', { ...shared, sectionName: 'secrets', vaultKeyVersion: 3, dataVersion: 1, logSeq: 11 }, ownerV2, { password: 'gone' });
  append({ kind: 'node_unshared', keyVersion: 3, nodeId: SHARED_NODE_ID, sections: 'secrets' }, ownerV2);
  write('owner-shared-other-name', { ...shared, sectionName: 'billing', vaultKeyVersion: 3, dataVersion: 1, logSeq: 12 }, ownerV2, { plan: 'x' });
  write('owner-wrong-node', { ...shared, nodeKey: 'server-3', sectionName: 'notes', vaultKeyVersion: 3, dataVersion: 1, logSeq: 12 }, ownerV2, { note: 'x' });
  write('owner-unshared-node', { nodeId: nodeIdOf(OWNER_ID, OTHER_VAULT_ID, 'server-4'), homeVaultId: OTHER_VAULT_ID, nodeKey: 'server-4', sectionName: 'notes', vaultKeyVersion: 3, dataVersion: 1, logSeq: 12 }, ownerV2, { note: 'x' });
  write('owner-deletes-unshared', { ...shared, sectionName: 'secrets', vaultKeyVersion: 3, dataVersion: 2, deleted: 1, logSeq: 12, previousWriteHash: sharedSecrets.writeHash }, ownerV2);
  write('owner-deletes-wrong-node', { ...shared, nodeKey: 'server-3', sectionName: 'notes', vaultKeyVersion: 3, dataVersion: 1, deleted: 1, logSeq: 12 }, ownerV2);
  write('owner-uncreated-node', { nodeId: nodeIdOf(OWNER_ID, VAULT_ID, 'server-9'), nodeKey: 'server-9', sectionName: 'notes', vaultKeyVersion: 3, dataVersion: 1, logSeq: 12 }, ownerV2, { note: 'x' });
  write('owner-before-node-created', { sectionName: 'billing', vaultKeyVersion: 1, dataVersion: 1, logSeq: 1 }, ownerV1, { plan: 'x' });

  // Writes every reader must refuse.
  write('bob-backdated', { sectionName: 'general', vaultKeyVersion: 1, dataVersion: 4, logSeq: 4, previousWriteHash: w4.writeHash }, bob, { name: 'evil' });
  write('bob-after-demotion', { sectionName: 'secrets', vaultKeyVersion: 1, dataVersion: 2, logSeq: 5, previousWriteHash: w2.writeHash }, bob, { password: 'evil' });
  write('carol-viewer', { sectionName: 'general', vaultKeyVersion: 1, dataVersion: 2, logSeq: 4, previousWriteHash: w1.writeHash }, carol, { name: 'evil' });
  write('owner-not-a-head', { sectionName: 'general', vaultKeyVersion: 1, dataVersion: 3, logSeq: 6, previousWriteHash: w3.writeHash }, ownerV1, { name: 'x' });
  write('bob-backdated-deletion', { sectionName: 'secrets', vaultKeyVersion: 1, dataVersion: 2, deleted: 1, logSeq: 4, previousWriteHash: w2.writeHash }, bob);
  write('owner-general-deleted-stale', { sectionName: 'general', vaultKeyVersion: 2, dataVersion: 2, deleted: 1, logSeq: 7, previousWriteHash: w1.writeHash }, ownerV1);
  write('owner-stale-key', { sectionName: 'general', vaultKeyVersion: 1, dataVersion: 3, logSeq: 7, previousWriteHash: w3.writeHash }, ownerV1, { name: 'x' });
  write('owner-replaced-keys', { sectionName: 'secrets', vaultKeyVersion: 2, dataVersion: 2, logSeq: 8, previousWriteHash: w2.writeHash }, ownerV1, { password: 'thief' });
  const forked = write('bob-general-2-fork', { sectionName: 'general', vaultKeyVersion: 1, dataVersion: 2, logSeq: 4, previousWriteHash: w1.writeHash }, bob, { name: 'other' });
  const tampered = { ...w5, ciphertext: Buffer.from(w5.ciphertext) };
  tampered.ciphertext[tampered.ciphertext.length - 1] ^= 1;
  writes.set('owner-tampered', tampered);
  const deletedWithContent = write('owner-deleted-with-content', { sectionName: 'secrets', vaultKeyVersion: 2, dataVersion: 3, deleted: 1, logSeq: 8, previousWriteHash: w5.writeHash }, ownerV2, { x: 1 });
  assert(deletedWithContent.ciphertext !== undefined && forked !== undefined && e1 !== undefined, 'scenario');

  return { entries, writes };
}

// ---------------------------------------------------------------------------------------------
// Vector files
// ---------------------------------------------------------------------------------------------

const entryJson = (e) => ({
  entry: {
    vaultId: e.vaultId,
    seq: e.seq,
    kind: e.kind,
    ...(e.subjectUserId === undefined ? {} : { subjectUserId: e.subjectUserId }),
    ...(e.role === undefined ? {} : { role: e.role }),
    keyVersion: e.keyVersion,
    ...(isZero(e.subjectKeys) ? {} : { subjectKeys: hex(e.subjectKeys), subjectKeyVersion: e.subjectKeyVersion }),
    ...(isZero(e.keyCommitment) ? {} : { keyCommitment: hex(e.keyCommitment) }),
    ...(isZero(e.checkpoint) ? {} : { checkpoint: hex(e.checkpoint) }),
    requestEnd: e.requestEnd,
    authorUserId: e.authorUserId,
    authorKeyVersion: e.authorKeyVersion,
    ...(e.nodeId === undefined ? {} : { nodeId: e.nodeId }),
    ...(e.homeVaultId === undefined ? {} : { homeVaultId: e.homeVaultId }),
    ...(e.nodeKey === undefined ? {} : { nodeKey: e.nodeKey }),
    ...(e.sections === undefined ? {} : { sections: e.sections }),
  },
  previousHash: hex(e.previousHash),
  fields: logMessage(e).fields,
  message: hex(logMessage(e).bytes()),
  entryHash: hex(sha256(logMessage(e).bytes())),
  signature: hex(e.signature),
  ...(e.checkpointLeaves === undefined ? {} : {
    checkpointLeaves: e.checkpointLeaves.map((l) => ({ ...l, writeHash: hex(l.writeHash), leafData: hex(leafData(l)) })),
  }),
});

function encodingVectors() {
  const write = {
    vaultId: VAULT_ID, nodeId: NODE_ID, nodeType: NODE_TYPE, homeVaultId: VAULT_ID, ownerUserId: OWNER_ID, nodeKey: NODE_KEY,
    sectionName: 'general', vaultKeyVersion: 2, dataVersion: 7, deleted: 0,
    logSeq: 9, logHeadHash: fixture('encoding-head', 32), previousWriteHash: fixture('encoding-previous-write', 32),
    writerUserId: BOB_ID, writerKeyVersion: 1, ciphertext: fixture('encoding-ciphertext', 297),
  };
  return {
    description: 'Canonical encoding (PROTOCOL.md §3). Encode `fields` in order and compare with `expected`.',
    cases: [
      canonicalCase('private-key-bundle-ad', bundleAd('cloak/v1/private-key-bundle', OWNER_ID, 2)),
      canonicalCase('recovery-key-bundle-ad', bundleAd('cloak/v1/recovery-key-bundle', OWNER_ID, 1)),
      canonicalCase('fingerprint-message', fingerprintMessage(ownerV1)),
      canonicalCase('key-statement-v2', keyStatementMessage(ownerV2, keysDigest(ownerV1))),
      canonicalCase('envelope-context', envelopeContext(VAULT_ID, 2, BOB_ID, 1)),
      canonicalCase('vault-previous-ad', previousAd(VAULT_ID, 2)),
      canonicalCase('section-content-ad', sectionContentAd(VAULT_ID, NODE_ID, 'billing', 3)),
      canonicalCase('local-record-ad', localRecordAd(`cloak/v1/${OWNER_ID}/pins`)),
      canonicalCase('section-write-message', sectionWriteMessage(write)),
      canonicalCase('vault-log-message', logMessage({
        vaultId: VAULT_ID, seq: 5, previousHash: fixture('encoding-previous-hash', 32), kind: 'key_rotated', keyVersion: 2,
        keyCommitment: fixture('encoding-commitment', 32), checkpoint: fixture('encoding-checkpoint', 32), requestEnd: 1,
        authorUserId: OWNER_ID, authorKeyVersion: 1,
      })),
      canonicalCase('nil-and-zero', new Canonical().label('cloak/v1/test').uuid(NIL_UUID).digest32(ZERO32).flag(0)),
      canonicalCase('unicode-string', new Canonical().label('cloak/v1/test').text('Привет, 世界')),
      canonicalCase('u64-large', new Canonical().label('cloak/v1/test').u64('18446744073709551615')),
    ],
  };
}

function textVectors() {
  const secretKey = fixture('owner-secret-key', 16);
  const recoveryKey = ownerV1.recoveryKey;
  const secretCode = secretKeyCode(secretKey);
  const recoveryCode = recoveryKeyCode(recoveryKey);
  assert(decodeCode('CS1-', secretCode, 16, 1).equals(secretKey), 'secret code round trip');
  assert(decodeCode('CR1-', recoveryCode, 32, 3).equals(recoveryKey), 'recovery code round trip');

  // A code whose last character carries non-zero padding bits: 17 bytes = 136 bits in 28 characters.
  const body = secretCode.slice(4).replaceAll('-', '');
  const last = CROCKFORD.indexOf(body[body.length - 1]);
  const paddedBits = groups(body.slice(0, -1) + CROCKFORD[last | 1], 4);
  const swapped = CROCKFORD[(CROCKFORD.indexOf(secretCode[5]) + 1) % 32];
  const badChecksum = `${secretCode.slice(0, 5)}${swapped}${secretCode.slice(6)}`;
  const negatives = [
    { name: 'secret-bad-checksum', kind: 'secretKey', code: badChecksum },
    { name: 'secret-padding-bits', kind: 'secretKey', code: `CS1-${paddedBits}` },
    { name: 'secret-no-prefix', kind: 'secretKey', code: secretCode.slice(4) },
    { name: 'secret-wrong-prefix', kind: 'secretKey', code: `CR1-${secretCode.slice(4)}` },
    { name: 'recovery-too-short', kind: 'recoveryKey', code: recoveryCode.slice(0, -2) },
  ];
  for (const n of negatives) {
    const [prefix, length, checksum] = n.kind === 'secretKey' ? ['CS1-', 16, 1] : ['CR1-', 32, 3];
    let refused = false;
    try {
      decodeCode(prefix, n.code, length, checksum);
    } catch {
      refused = true;
    }
    assert(refused, `text negative ${n.name}`);
    n.reason = 'bad_code';
  }

  const digest = keysDigest(ownerV1);
  return {
    description: 'Human-readable codes (PROTOCOL.md §10): Crockford base32, secret key, recovery key, fingerprint. ' +
      'Every negative must be refused with `reason`.',
    crockford: [
      { input: '', expected: crockford(EMPTY) },
      { input: '66', expected: crockford(utf8('f')) },
      { input: '666f6f626172', expected: crockford(utf8('foobar')) },
      { input: 'ffffffffff', expected: crockford(fromHex('ffffffffff')) },
    ],
    secretKey: { bytes: hex(secretKey), code: secretCode, lowercase: secretCode.toLowerCase() },
    recoveryKey: { bytes: hex(recoveryKey), code: recoveryCode },
    fingerprint: {
      identity: identityJson(ownerV1),
      message: hex(fingerprintMessage(ownerV1).bytes()),
      digest: hex(digest),
      code: fingerprintCode(digest),
    },
    negatives,
  };
}

function kdfVectors() {
  const password = 'correct horse battery staple ✓';
  const salt = fixture('owner-kdf-salt', 16);
  const secretKey = fixture('owner-secret-key', 16);
  const memoryKib = 65536;
  const iterations = 2;
  const passwordKey = argon2id(utf8(password.normalize('NFKC')), salt, memoryKib, iterations);
  const secretKeyMaterial = hkdf(secretKey, uuidBytes(OWNER_ID), utf8('cloak/v1/secret-key'));
  const masterKey = Buffer.from(passwordKey.map((b, i) => b ^ secretKeyMaterial[i]));

  const wrongKey = fixture('vault-key-wrong', 32);
  return {
    description: 'Key derivation (PROTOCOL.md §5, §6.1, §15).',
    masterKey: {
      userId: OWNER_ID,
      password,
      passwordNfkcUtf8: hex(utf8(password.normalize('NFKC'))),
      kdf: { algorithm: 'argon2id', salt: hex(salt), memoryKib, iterations, parallelism: 1 },
      secretKey: hex(secretKey),
      passwordKey: hex(passwordKey),
      secretKeyMaterial: hex(secretKeyMaterial),
      masterKey: hex(masterKey),
      privateKeyBundleKey: hex(hkdf(masterKey, EMPTY, utf8('cloak/v1/private-key-bundle'))),
    },
    kdfLimits: {
      accept: [{ memoryKib: 65536, iterations: 2 }, { memoryKib: 1048576, iterations: 10 }],
      refuse: [{ memoryKib: 65535, iterations: 2 }, { memoryKib: 65536, iterations: 1 }, { memoryKib: 1048577, iterations: 2 }, { memoryKib: 65536, iterations: 11 }],
    },
    recoveryKeys: [ownerV1, ownerV2].map((id) => ({
      userId: id.userId,
      keyVersion: id.keyVersion,
      recoveryKey: hex(id.recoveryKey),
      recoveryKeyBundleKey: hex(hkdf(id.recoveryKey, uuidBytes(id.userId), utf8('cloak/v1/recovery-key-bundle'))),
      recoverySigningSeed: hex(id.recoverySigningSeed),
      recoverySigningPublicKey: hex(id.recoverySigningPublicKey),
    })),
    vaultKeys: vaultKeys.map((key, index) => ({
      vaultId: VAULT_ID,
      keyVersion: index + 1,
      vaultKey: hex(key),
      contentKey: hex(contentKeyOf(key, VAULT_ID)),
      wrapKey: hex(wrapKeyOf(key, VAULT_ID)),
      keyCommitment: hex(keyCommitmentOf(key, VAULT_ID, index + 1)),
    })),
    keyMismatch: {
      note: 'A key opened for version 2 that is not the committed one must be refused with key_mismatch.',
      vaultId: VAULT_ID,
      keyVersion: 2,
      openedKey: hex(wrongKey),
      itsCommitment: hex(keyCommitmentOf(wrongKey, VAULT_ID, 2)),
      committed: hex(keyCommitmentOf(vaultKeys[1], VAULT_ID, 2)),
      reason: 'key_mismatch',
    },
    localState: localStateKeys.map((key) => ({
      userId: OWNER_ID,
      localStateKey: hex(key),
      recordKey: hex(hkdf(key, uuidBytes(OWNER_ID), utf8('cloak/v1/local-state'))),
    })),
  };
}

function aeadVectors(kdf) {
  const cases = [];
  const add = (name, key, nonce, ad, plaintext, extra = {}) => {
    const adBytes = ad.bytes ? ad.bytes() : ad;
    const blob = encryptBlob(key, nonce, adBytes, plaintext);
    assert(decryptBlob(key, adBytes, blob).equals(plaintext), `${name} round trip`);
    cases.push({ name, key: hex(key), nonce: hex(nonce), ad: hex(adBytes), plaintext: hex(plaintext), blob: hex(blob), ...extra });
    return blob;
  };

  const bundleV1 = Buffer.concat([Buffer.from([1]), ownerV1.encryptionPrivateKey, ownerV1.signingSeed, localStateKeys[0], ZERO32]);
  const bundleV2 = Buffer.concat([Buffer.from([1]), ownerV2.encryptionPrivateKey, ownerV2.signingSeed, localStateKeys[1], localStateKeys[0], ownerV1.encryptionPrivateKey]);
  add('private-key-bundle-v1', fromHex(kdf.masterKey.privateKeyBundleKey), fixture('nonce-bundle-v1', 24),
    bundleAd('cloak/v1/private-key-bundle', OWNER_ID, 1), bundleV1, {
      note: 'plaintext = 0x01 || X25519 private key || Ed25519 seed || localStateKey || previousLocalStateKey (zero)',
    });
  add('private-key-bundle-v2', fromHex(kdf.masterKey.privateKeyBundleKey), fixture('nonce-bundle-v2', 24),
    bundleAd('cloak/v1/private-key-bundle', OWNER_ID, 2), bundleV2, {
      note: 'version 2 carries the previous localStateKey and the version-1 X25519 private key',
    });
  add('recovery-key-bundle-v1', fromHex(kdf.recoveryKeys[0].recoveryKeyBundleKey), fixture('nonce-recovery-v1', 24),
    bundleAd('cloak/v1/recovery-key-bundle', OWNER_ID, 1), bundleV1);

  const content = utf8(JSON.stringify({ name: 'db-1', host: '10.0.0.5' }));
  const contentKey = fromHex(kdf.vaultKeys[0].contentKey);
  const sectionBlob = add('section-content', contentKey, fixture('nonce-section', 24),
    sectionContentAd(VAULT_ID, NODE_ID, 'general', 1), pad(content), { contentUtf8: content.toString('utf8') });
  add('vault-previous', fromHex(kdf.vaultKeys[1].wrapKey), fixture('nonce-vault-previous', 24),
    previousAd(VAULT_ID, 2), vaultKeys[0], { note: 'key = vaultKeys[2].wrapKey; plaintext = vault key v1' });
  add('local-record', fromHex(kdf.localState[0].recordKey), fixture('nonce-local-record', 24),
    localRecordAd(`cloak/v1/${OWNER_ID}/pins`), utf8('{"pins":[]}'));

  const wrongAd = sectionContentAd(VAULT_ID, NODE_ID, 'general', 2).bytes();
  let refused = false;
  try {
    decryptBlob(contentKey, wrongAd, sectionBlob);
  } catch {
    refused = true;
  }
  assert(refused, 'wrong AD refused');

  const paddingNegatives = [
    { name: 'two-blocks-of-padding', input: Buffer.concat([utf8('x'), Buffer.from([0x80]), Buffer.alloc(510)]) },
    { name: 'no-marker', input: Buffer.alloc(256) },
    { name: 'byte-after-marker', input: Buffer.concat([utf8('x'), Buffer.from([0x80, 0x01]), Buffer.alloc(253)]) },
    { name: 'not-whole-blocks', input: Buffer.concat([utf8('x'), Buffer.from([0x80]), Buffer.alloc(10)]) },
    { name: 'empty', input: EMPTY },
  ].map((n) => {
    let reason = null;
    try {
      strictUnpad(n.input);
    } catch (error) {
      reason = error.message;
    }
    assert(reason === 'bad_padding', `padding negative ${n.name}`);
    return { name: n.name, input: hex(n.input), reason };
  });

  return {
    description: 'Encrypted blobs: XChaCha20-Poly1305 (PROTOCOL.md §4, §5.4, §6, §8.1, §15). blob = 0x01 || nonce || ciphertext || tag.',
    hchacha20: {
      key: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
      nonce: '000000090000004a0000000031415927',
      subkey: '82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc',
      source: 'draft-irtf-cfrg-xchacha-03 §2.2.1',
    },
    padding: [0, 1, 255, 256, 300].map((n) => {
      const data = fixture(`pad-${n}`, n);
      return { input: hex(data), padded: hex(pad(data)) };
    }),
    paddingNegatives,
    cases,
    negatives: [{
      name: 'section-content-wrong-ad',
      key: hex(contentKey),
      ad: hex(wrongAd),
      blob: hex(sectionBlob),
      reason: 'decryption_failed',
      note: 'the section-content blob opened with the associated data of key version 2',
    }],
  };
}

function hpkeVectors() {
  const cases = [];
  const info = utf8('cloak/v1/vault-key');
  const add = (name, recipient, keyVersion, ikmE) => {
    const ad = envelopeContext(VAULT_ID, keyVersion, recipient.userId, recipient.keyVersion);
    const plaintext = vaultKeys[keyVersion - 1];
    const { enc, ciphertext, skE } = hpkeSeal(recipient.encryptionPublicKey, info, ad.bytes(), plaintext, ikmE);
    const blob = Buffer.concat([Buffer.from([1]), enc, ciphertext]);
    assert(openBlob(recipient.encryptionPrivateKey, info, ad.bytes(), blob).equals(plaintext), `${name} round trip`);
    cases.push({
      name, recipient: recipient.name, skR: hex(recipient.encryptionPrivateKey), pkR: hex(recipient.encryptionPublicKey),
      ikmE: hex(ikmE), skE: hex(skE), enc: hex(enc), info: hex(info), aad: hex(ad.bytes()), plaintext: hex(plaintext), blob: hex(blob),
    });
    return { blob, recipient };
  };
  add('vault-key-v1-to-owner-v1', ownerV1, 1, fixture('ikmE-owner-v1', 32));
  add('vault-key-v1-to-bob', bob, 1, fixture('ikmE-bob', 32));
  const toV2 = add('vault-key-v2-to-owner-v2', ownerV2, 2, fixture('ikmE-owner-v2', 32));

  const wrongContext = envelopeContext(VAULT_ID, 2, OWNER_ID, 1).bytes();
  let refused = false;
  try {
    openBlob(ownerV2.encryptionPrivateKey, info, wrongContext, toV2.blob);
  } catch {
    refused = true;
  }
  assert(refused, 'envelope wrong context refused');

  return {
    description:
      'Envelopes: HPKE RFC 9180 mode_base, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305 (PROTOCOL.md §4, §6.3). ' +
      'blob = 0x01 || enc || ciphertext || tag. ikmE/skE make these vectors reproducible; every implementation must open each blob with skR.',
    suite: { kemId: '0x0020', kdfId: '0x0001', aeadId: '0x0003' },
    cases,
    negatives: [{
      name: 'envelope-wrong-user-key-version',
      skR: hex(ownerV2.encryptionPrivateKey),
      info: hex(info),
      aad: hex(wrongContext),
      blob: hex(toV2.blob),
      reason: 'decryption_failed',
    }],
  };
}

function signatureVectors() {
  const message = new Canonical().label('cloak/v1/test').text('strict Ed25519').bytes();
  const valid = signBlob(ownerV1.signingSeed, message);
  const sValue = littleEndian(valid.subarray(33));
  const unreduced = Buffer.from(valid);
  const sPlusL = sValue + GROUP_ORDER;
  Buffer.from(sPlusL.toString(16).padStart(64, '0'), 'hex').reverse().copy(unreduced, 33);
  const nonCanonicalR = Buffer.from(valid);
  Buffer.alloc(32, 0xff).copy(nonCanonicalR, 1);
  nonCanonicalR[32] = 0x7f;
  const identityPoint = fromHex(SMALL_ORDER[0]);
  const smallOrderSignature = Buffer.concat([Buffer.from([1]), identityPoint, Buffer.alloc(32)]);

  const cases = [
    { name: 'valid', publicKey: ownerV1.signingPublicKey, signature: valid, message },
    { name: 's-not-reduced', publicKey: ownerV1.signingPublicKey, signature: unreduced, message },
    { name: 'r-not-canonical', publicKey: ownerV1.signingPublicKey, signature: nonCanonicalR, message },
    { name: 'small-order-key', publicKey: identityPoint, signature: smallOrderSignature, message },
    { name: 'wrong-message', publicKey: ownerV1.signingPublicKey, signature: valid, message: Buffer.concat([message, Buffer.from([0])]) },
  ].map((c) => ({
    name: c.name,
    publicKey: hex(c.publicKey),
    message: hex(c.message),
    signature: hex(c.signature),
    reason: strictVerify(c.publicKey, c.message, c.signature),
  }));
  assert(cases[0].reason === null && cases.slice(1).every((c) => c.reason !== null), 'signature cases');

  return {
    description: 'Strict Ed25519 (PROTOCOL.md §2, §11). signature = 0x01 || R || S. `reason` null means valid; otherwise it must be refused for that reason.',
    smallOrderPoints: SMALL_ORDER,
    cases,
  };
}

function identityVectors() {
  const statements = [
    statement(ownerV1), statement(ownerV2, ownerV1), statement(bob), statement(carol), statement(dave),
  ];
  statements.forEach((s, i) => {
    const previous = s.keyVersion === 1 ? undefined : directory(s.userId, s.keyVersion - 1);
    assert(verifyStatement(s, previous) === null, `statement ${i}`);
  });

  const wrongRecovery = statement(ownerV2, ownerV1, ownerV2);
  const bySigningKey = { ...statement(ownerV2, ownerV1), recoverySignature: hex(signBlob(ownerV1.signingSeed, fromHex(statement(ownerV2, ownerV1).message))) };
  const noRecovery = { ...statement(ownerV2, ownerV1) };
  delete noRecovery.recoverySignature;
  const negatives = [
    { name: 'recovery-signature-by-new-recovery-key', statement: wrongRecovery },
    { name: 'recovery-signature-by-old-signing-key', statement: bySigningKey },
    { name: 'no-recovery-signature', statement: noRecovery },
  ].map((n) => {
    const reason = verifyStatement(n.statement, ownerV1);
    assert(reason === 'bad_statement', `statement negative ${n.name}`);
    return { ...n, reason };
  });

  return {
    description: 'Identity keys and key statements (PROTOCOL.md §5.1, §5.2). Version 1 is signed by its signing key; version n + 1 also by the recovery signing key of version n. ' +
      '`userIds` derives each Cloak user id from a host user id (§5.0): UUIDv5 under `userNamespace`, over the host id\'s UTF-8 bytes.',
    identities: allIdentities.map(identityJson),
    statements,
    negatives,
    userNamespace: USER_NAMESPACE,
    userIds: [
      'alice',
      'user@example.com',
      '0192f5a4-7c3e-7b1a-9d2e-5f6a7b8c9d0e',
      '0192F5A4-7C3E-7B1A-9D2E-5F6A7B8C9D0E',
      'auth0|64b7f1c2e4',
      ' padded ',
      'Ünïcødé 用户',
      'x'.repeat(255),
    ].map((hostUserId) => ({ hostUserId, userId: uuidV5(USER_NAMESPACE, utf8(hostUserId)) })),
    nodeIds: [
      [OWNER_ID, VAULT_ID, NODE_KEY],
      [OWNER_ID, OTHER_VAULT_ID, SHARED_NODE_KEY],
      [BOB_ID, VAULT_ID, NODE_KEY],
      [OWNER_ID, VAULT_ID, 'Ünïcødé ресурс'],
      [OWNER_ID, VAULT_ID, 'k'.repeat(255)],
    ].map(([ownerUserId, homeVaultId, nodeKey]) => {
      const name = new Canonical().label('cloak/v1/node').uuid(homeVaultId).text(nodeKey);
      return { ownerUserId, homeVaultId, nodeKey, name: hex(name.bytes()), nodeId: nodeIdOf(ownerUserId, homeVaultId, nodeKey) };
    }),
    credentials: credentialStatements(),
  };
}

/**
 * Signed changes to an identity (PROTOCOL.md §5.4, §5.7): a new private key bundle and a deletion,
 * each signed with the current version's signing key.
 */
function credentialStatements() {
  const bundle = fixture('credentials-bundle', 145);
  const salt = fixture('credentials-salt', 16);
  const change = new Canonical()
    .label('cloak/v1/credentials').uuid(OWNER_ID).u32(2).u32(3)
    .digest32(sha256(bundle)).digest32(sha256(salt)).u32(65_536).u32(3).u8(1);
  const notAfter = 1_793_000_000;
  const deletion = new Canonical().label('cloak/v1/identity-deletion').uuid(OWNER_ID).u32(2).u32(3).u64(notAfter);
  const signed = (message) => {
    const signature = signBlob(ownerV2.signingSeed, message.bytes());
    assert(strictVerify(ownerV2.signingPublicKey, message.bytes(), signature) === null, 'credentials signature');
    return { fields: message.fields, message: hex(message.bytes()), signature: hex(signature) };
  };
  return {
    signer: { userId: OWNER_ID, keyVersion: 2 },
    change: { privateKeyBundle: hex(bundle), kdf: { salt: hex(salt), memoryKib: 65_536, iterations: 3, parallelism: 1 }, credentialsVersion: 3, ...signed(change) },
    deletion: { credentialsVersion: 3, notAfter, ...signed(deletion) },
  };
}

/** The namespace of Cloak user ids (§5.0): UUIDv5 of NameSpace_URL and `urn:cloak:v1:user`. */
const USER_NAMESPACE = uuidV5('6ba7b811-9dad-11d1-80b4-00c04fd430c8', utf8('urn:cloak:v1:user'));

/** RFC 9562 §5.5 UUIDv5 of [name] bytes under [namespace], lowercase. */
function uuidV5(namespace, name) {
  const hash = crypto.createHash('sha1').update(uuidBytes(namespace)).update(name).digest();
  const bytes = Buffer.from(hash.subarray(0, 16));
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** The scenario's log with the owner's `vault_deleted` appended (§12.3). */
function deletedLog(entries) {
  return variant([...entries, {}], entries.length + 1, {
    vaultId: VAULT_ID, kind: 'vault_deleted', keyVersion: 3, requestEnd: 1, authorUserId: OWNER_ID, authorKeyVersion: 2,
  }, ownerV2);
}

/** Rebuilds a log with one entry changed and later entries dropped, re-signed by `signer`. */
function variant(entries, seq, changes, signer) {
  const prefix = entries.slice(0, seq - 1).map((e) => ({ ...e }));
  const previous = prefix[prefix.length - 1];
  const base = entries[seq - 1] ?? {};
  const e = { ...base, ...changes, seq, previousHash: previous === undefined ? ZERO32 : previous.entryHash };
  delete e.entryHash;
  if (changes.checkpoint === undefined && base.checkpoint !== undefined && changes.keepCheckpoint !== true) {
    delete e.checkpoint;
    delete e.checkpointLeaves;
  }
  delete e.keepCheckpoint;
  const message = logMessage(e).bytes();
  e.entryHash = sha256(message);
  e.signature = signBlob(signer.signingSeed, message);
  return [...prefix, e];
}

function vaultLogVectors(entries, trusted) {
  const replay = replayLog(entries, trusted);
  assert(replay.ok, `scenario log: ${replay.reason} at ${replay.failSeq}`);

  const at = (seq) => entries[seq - 1];
  const negatives = [];
  const negative = (name, log, reason, failSeq, note) => {
    const result = replayLog(log, trusted);
    assert(!result.ok && result.reason === reason && result.failSeq === failSeq,
      `log negative ${name}: got ${result.reason} at ${result.failSeq}`);
    negatives.push({ name, reason, failSeq, note, log: log.map(entryJson) });
  };

  const brokenChain = entries.slice(0, 2).map((e) => ({ ...e }));
  brokenChain[1] = { ...brokenChain[1], previousHash: fixture('wrong-previous', 32) };
  {
    const message = logMessage(brokenChain[1]).bytes();
    brokenChain[1].entryHash = sha256(message);
    brokenChain[1].signature = signBlob(ownerV1.signingSeed, message);
  }
  negative('broken-chain', brokenChain, 'broken_chain', 2, 'entry 2 names a previous hash that is not entry 1');

  negative('bad-signature', variant(entries, 2, {}, bob), 'bad_signature', 2, 'entry 2 signed by Bob, authored by the owner');
  negative('editor-adds-member', variant(entries, 5, {
    kind: 'member_added', subjectUserId: DAVE_ID, role: 'viewer', keyVersion: 1, subjectKeys: keysDigest(dave), subjectKeyVersion: 1,
    authorUserId: BOB_ID, authorKeyVersion: 1, checkpoint: undefined,
  }, bob), 'not_authorized', 5, 'an editor cannot add members');
  negative('removal-outside-rotation', variant(entries, 5, {
    kind: 'member_removed', subjectUserId: CAROL_ID, role: undefined, keyVersion: 1, subjectKeys: keysDigest(carol), subjectKeyVersion: 1,
  }, ownerV1), 'bad_request_shape', 5, 'removing someone else needs a rotation request');
  negative('rotation-without-checkpoint', variant(entries, 5, {
    kind: 'key_rotated', subjectUserId: undefined, role: undefined, keyVersion: 2, subjectKeys: undefined, subjectKeyVersion: undefined,
    keyCommitment: keyCommitmentOf(vaultKeys[1], VAULT_ID, 2),
  }, ownerV1), 'missing_checkpoint', 5);
  negative('demotion-without-checkpoint', variant(entries, 5, {}, ownerV1), 'missing_checkpoint', 5,
    'Bob loses the right to write, so the entry needs a checkpoint');
  negative('unfinished-request', variant(entries, 6, {}, ownerV1), 'unfinished_request', 6,
    'the log ends inside a rotation request');
  negative('bad-flag', variant(entries, 2, { requestEnd: 2 }, ownerV1), 'bad_flag', 2);
  negative('unexpected-field', variant(entries, 7, { role: 'viewer', keepCheckpoint: true }, ownerV1), 'unexpected_field', 7,
    'key_rotated must not set a role');
  negative('no-owner', variant(entries, 5, {
    kind: 'member_role_set', subjectUserId: OWNER_ID, role: 'admin', keyVersion: 1, subjectKeys: keysDigest(ownerV1), subjectKeyVersion: 1,
  }, ownerV1), 'no_owner', 5, 'the owner lowers their own role and leaves the vault without an owner');
  negative('unchained-key-replacement', variant(entries, 5, {
    kind: 'member_keys_replaced', subjectUserId: BOB_ID, role: undefined, keyVersion: 1, subjectKeys: keysDigest(identity('bob', BOB_ID, 2)),
    subjectKeyVersion: 2, authorUserId: BOB_ID, authorKeyVersion: 2, checkpoint: fixture('some-checkpoint', 32),
  }, identity('bob', BOB_ID, 2)), 'unverified_keys', 5, 'no key statement makes these keys Bob\'s version 2');
  negative('created-version-mismatch', variant(entries, 1, { authorKeyVersion: 2 }, ownerV2), 'unverified_keys', 1);
  negative('replaced-keys-sign', variant(entries, 9, {
    kind: 'member_added', subjectUserId: DAVE_ID, role: 'viewer', keyVersion: 2, subjectKeys: keysDigest(dave), subjectKeyVersion: 1,
    authorUserId: OWNER_ID, authorKeyVersion: 1,
  }, ownerV1), 'unverified_keys', 9, 'after member_keys_replaced, the owner\'s version-1 keys carry no rights');

  // Node entries (§7.7) and deletion (§12.3): seq 11 shares, 12 takes back, 13 deletes.
  const sharedNode = { homeVaultId: OTHER_VAULT_ID, nodeKey: SHARED_NODE_KEY };
  negative('share-someone-elses-node', variant(entries, 11, { nodeId: nodeIdOf(BOB_ID, OTHER_VAULT_ID, SHARED_NODE_KEY) }, ownerV2),
    'not_authorized', 11, 'only the node\'s owner, whose id it derives from, may share it');
  negative('share-into-home', variant(entries, 11, {
    nodeId: nodeIdOf(OWNER_ID, VAULT_ID, SHARED_NODE_KEY), homeVaultId: VAULT_ID,
  }, ownerV2), 'invalid_entry', 11, 'a node is valid in its home already and is never shared into it');
  negative('share-unsorted-names', variant(entries, 11, { ...sharedNode, sections: 'secrets,notes' }, ownerV2),
    'invalid_entry', 11, 'names are listed in ascending byte order, without repeats');
  negative('unshare-what-is-not-shared', variant(entries, 12, { sections: 'billing' }, ownerV2), 'invalid_entry', 12);
  negative('create-someone-elses-node', variant(entries, 2, { nodeId: nodeIdOf(BOB_ID, VAULT_ID, NODE_KEY) }, ownerV1),
    'not_authorized', 2, 'a node derives from its creator, so nobody creates another\'s');
  negative('create-a-node-twice', variant([...entries, {}], entries.length + 1, {
    vaultId: VAULT_ID, kind: 'node_created', keyVersion: 3, nodeId: NODE_ID, nodeKey: NODE_KEY, requestEnd: 1,
    authorUserId: OWNER_ID, authorKeyVersion: 2,
  }, ownerV2), 'invalid_entry', entries.length + 1, 'a node is created in its home once');
  const deleted = deletedLog(entries);
  negative('entry-after-deletion', [...deleted, ...variant([...deleted, {}], deleted.length + 1, {
    vaultId: VAULT_ID, kind: 'node_unshared', keyVersion: 3, nodeId: SHARED_NODE_ID, sections: 'notes', requestEnd: 1,
    authorUserId: OWNER_ID, authorKeyVersion: 2,
  }, ownerV2).slice(deleted.length)], 'vault_deleted', deleted.length + 1, 'nothing follows vault_deleted');

  const checkpointTampered = entries.slice(0, 7).map((e) => ({ ...e }));
  checkpointTampered[4] = { ...checkpointTampered[4], checkpointLeaves: checkpointTampered[4].checkpointLeaves.slice(0, 1) };
  negative('checkpoint-leaves-mismatch', checkpointTampered, 'bad_checkpoint', 5, 'the served leaves do not give the signed root');

  return {
    description:
      'Vault log (PROTOCOL.md §7). Rebuild each message from `entry` and `previousHash`, compare with `message`, check the chain, ' +
      'the signature with the author\'s keys of `authorKeyVersion` (identity.json), the rules of §7.2 and §7.3, and each checkpoint ' +
      'root against its leaves. Every negative log must be refused at `failSeq` with `reason`; its entries are otherwise validly signed.',
    vaultId: VAULT_ID,
    vaultKeys: vaultKeys.map((k, i) => ({ keyVersion: i + 1, vaultKey: hex(k), keyCommitment: hex(keyCommitmentOf(k, VAULT_ID, i + 1)) })),
    log: entries.map(entryJson),
    negatives,
    enumerations: { role: ROLE, kind: KIND },
  };
}

function sectionVectors(entries, writes, trusted) {
  const replay = replayLog(entries, trusted);
  const log = replay.state;
  const expectations = {
    'owner-general-1': 'not_in_checkpoint',
    'bob-secrets-1': 'rollback',
    // Superseded and then deleted: the latest checkpoint holds no 'general' at all.
    'bob-general-2': 'not_in_checkpoint',
    'owner-general-3': 'not_in_checkpoint',
    'owner-secrets-2': null,
    'owner-general-deleted': null,
    'bob-backdated': 'not_in_checkpoint',
    'bob-backdated-deletion': 'not_in_checkpoint',
    'owner-general-deleted-stale': 'rollback',
    'bob-after-demotion': 'not_an_editor',
    'carol-viewer': 'not_an_editor',
    'owner-not-a-head': 'not_a_head',
    'owner-stale-key': 'wrong_key_version',
    'owner-replaced-keys': 'not_an_editor',
    'bob-general-2-fork': 'not_in_checkpoint',
    'owner-tampered': 'bad_signature',
    'owner-deleted-with-content': 'bad_deletion',
    'owner-shared-notes-early': 'not_shared',
    'owner-shared-notes': null,
    'owner-shared-secrets': 'not_shared',
    'owner-shared-other-name': 'not_shared',
    'owner-wrong-node': 'bad_node',
    'owner-unshared-node': 'not_shared',
    'owner-deletes-unshared': null,
    'owner-deletes-wrong-node': 'bad_node',
    'owner-uncreated-node': 'not_shared',
    'owner-before-node-created': 'not_shared',
  };
  const cases = [...writes.entries()].map(([name, w]) => {
    const reason = verifyWrite(w, log);
    assert(name in expectations && expectations[name] === reason, `section ${name}: got ${reason}`);
    const message = sectionWriteMessage(w);
    const writeHash = sha256(message.bytes());
    const later = log.checkpoints.filter((c) => c.seq > w.logSeq);
    const judgedBy = [...new Set([later[0], later.at(-1)].filter((c) => c !== undefined))];
    const proofs = judgedBy.map((c) => checkpointProofOf(c, w));
    return {
      name,
      write: {
        vaultId: w.vaultId, nodeId: w.nodeId, nodeType: w.nodeType, homeVaultId: w.homeVaultId, ownerUserId: w.ownerUserId,
        nodeKey: w.nodeKey, sectionName: w.sectionName, vaultKeyVersion: w.vaultKeyVersion,
        dataVersion: w.dataVersion, deleted: w.deleted, logSeq: w.logSeq, logHeadHash: hex(w.logHeadHash),
        previousWriteHash: hex(w.previousWriteHash ?? ZERO32), writerUserId: w.writerUserId, writerKeyVersion: w.writerKeyVersion,
        ciphertextHash: hex(w.ciphertext === undefined ? ZERO32 : sha256(w.ciphertext)),
      },
      ...(w.ciphertext === undefined ? {} : { ciphertext: hex(w.ciphertext) }),
      ...(w.content === undefined ? {} : { contentUtf8: JSON.stringify(w.content) }),
      fields: message.fields,
      message: hex(message.bytes()),
      writeHash: hex(writeHash),
      signature: hex(w.signature),
      checkpointProofs: proofs,
      reason,
    };
  });

  // §8.4: once the log ends in vault_deleted, no write of the vault stands, not even one that did.
  const afterDeletion = deletedLog(entries);
  const deletedReplay = replayLog(afterDeletion, trusted);
  assert(deletedReplay.ok && deletedReplay.state.deleted, 'deleted log');
  const standing = writes.get('owner-shared-notes');
  assert(verifyWrite(standing, log) === null && verifyWrite(standing, deletedReplay.state) === 'vault_deleted', 'deleted vault');

  // Section marks (§15): after seeing one write, another with the same dataVersion is a fork.
  const seen = writes.get('bob-general-2');
  const other = writes.get('bob-general-2-fork');
  assert(seen.dataVersion === other.dataVersion && !seen.writeHash.equals(other.writeHash), 'fork pair');

  return {
    description:
      'Section writes (PROTOCOL.md §8). Each write cites a head of the log in vault-log.json. Rebuild `message` from `write`, ' +
      'check the signature, decrypt `ciphertext` with the content key of `vaultKeyVersion` (kdf.json), and apply §8.4. `reason` ' +
      'null means accepted. `write.ciphertextHash` is the header\'s digest (zeros for a deletion). `checkpointProofs` shows what the first ' +
      'and the latest checkpoint after the write\'s head hold for its section: the leaf with its path, or the neighbours that show it absent.',
    vaultId: VAULT_ID,
    cases,
    afterDeletion: { entry: entryJson(afterDeletion.at(-1)), write: 'owner-shared-notes', reason: 'vault_deleted' },
    marks: [{
      name: 'same-version-other-hash',
      seen: 'bob-general-2',
      then: 'bob-general-2-fork',
      reason: 'fork',
      note: 'both are validly signed, but a device that saw one must refuse the other',
    }],
  };
}

function checkpointVectors() {
  const trees = [];
  for (let n = 0; n <= 8; n++) {
    const leaves = Array.from({ length: n }, (_, i) => ({
      nodeId: `0192f5a5-0000-7000-8000-${String(i).padStart(12, '0')}`,
      sectionName: i % 2 === 0 ? 'general' : 'secrets',
      dataVersion: i + 1,
      writeHash: fixture(`checkpoint-write-${n}-${i}`, 32),
    }));
    const sorted = checkpointOf(leaves);
    const hashes = sorted.leaves.map((l) => leafHash(leafData(l)));
    assert(treeHash(hashes).equals(treeHashIterative(hashes)), `tree ${n}`);
    trees.push({
      size: n,
      leaves: sorted.leaves.map((l, i) => {
        const path = auditPath(i, hashes);
        assert(verifyInclusion(i, n, hashes[i], path, sorted.root), `inclusion ${n}/${i}`);
        return { ...l, writeHash: hex(l.writeHash), leafData: hex(leafData(l)), leafHash: hex(hashes[i]), path: path.map(hex) };
      }),
      root: hex(sorted.root),
    });
  }

  const tree = trees[7];
  const leafAt = (i) => fromHex(tree.leaves[i].leafHash);
  const pathAt = (i) => tree.leaves[i].path.map(fromHex);
  const root = fromHex(tree.root);
  const negatives = [
    { name: 'wrong-sibling', index: 3, size: 7, leafHash: leafAt(3), path: [fixture('wrong-sibling', 32), ...pathAt(3).slice(1)] },
    { name: 'wrong-index', index: 4, size: 7, leafHash: leafAt(3), path: pathAt(3) },
    { name: 'wrong-size', index: 3, size: 4, leafHash: leafAt(3), path: pathAt(3) },
    { name: 'index-past-size', index: 7, size: 7, leafHash: leafAt(3), path: pathAt(3) },
    { name: 'short-path', index: 3, size: 7, leafHash: leafAt(3), path: pathAt(3).slice(1) },
  ].map((c) => {
    assert(!verifyInclusion(c.index, c.size, c.leafHash, c.path, root), `checkpoint negative ${c.name}`);
    return { name: c.name, index: c.index, size: c.size, leafHash: hex(c.leafHash), path: c.path.map(hex), root: tree.root, reason: 'bad_proof' };
  });

  return {
    description:
      'Checkpoints (PROTOCOL.md §7.5): RFC 6962 Merkle trees over leaf = SHA-256(0x00 || leafData), node = SHA-256(0x01 || left || right), ' +
      'leaves ordered by node id bytes then section name bytes. Each leaf\'s path verifies with RFC 9162 §2.1.3.2; every negative must fail.',
    emptyRoot: hex(sha256(EMPTY)),
    trees,
    negatives,
  };
}

// ---------------------------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------------------------

selfTest();

const trustedVersions = new Map([[OWNER_ID, new Set([1, 2])], [BOB_ID, new Set([1])], [CAROL_ID, new Set([1])], [DAVE_ID, new Set([1])]]);
const { entries, writes } = scenario();
const kdf = kdfVectors();
const files = {
  'encoding.json': encodingVectors(),
  'text.json': textVectors(),
  'kdf.json': kdf,
  'aead.json': aeadVectors(kdf),
  'hpke.json': hpkeVectors(),
  'signatures.json': signatureVectors(),
  'identity.json': identityVectors(),
  'vault-log.json': vaultLogVectors(entries, trustedVersions),
  'checkpoints.json': checkpointVectors(),
  'sections.json': sectionVectors(entries, writes, trustedVersions),
};

fs.mkdirSync(outDir, { recursive: true });
for (const stale of fs.readdirSync(outDir)) {
  if (stale.endsWith('.json') && !(stale in files)) fs.rmSync(path.join(outDir, stale));
}
for (const [name, content] of Object.entries(files)) {
  const body = { protocolVersion: 1, cryptoSuite: SUITE, generator: 'cloak-protocol/tools/generate-vectors.mjs', ...content };
  fs.writeFileSync(path.join(outDir, name), `${JSON.stringify(body, null, 2)}\n`);
}
console.log(`Self-tests passed. Wrote ${Object.keys(files).length} files to ${outDir}`);
