// SPDX-License-Identifier: Apache-2.0
/**
 * RC4 cipher suites for node-forge TLS.
 *
 * Registers TLS_RSA_WITH_RC4_128_MD5 (0x0004) and TLS_RSA_WITH_RC4_128_SHA
 * (0x0005) with node-forge's TLS framework.  Required for EKENG's ca.gov.am
 * which only accepts TLS 1.0 + RC4 -- a cipher suite removed from OpenSSL 3.x.
 *
 * Import this module for side effects before creating a legacy TLS connection:
 *
 *   import "./rc4-cipher-suite.js";
 *
 * Security note: RC4 is cryptographically broken (RFC 7465).  This code
 * exists solely for backward compatibility with a single government appliance.
 */

import * as forgeNamespace from "node-forge";

// -- CJS/ESM interop ---------------------------------------------------------
// node-forge is CJS. When loaded via dynamic import() chain, named exports
// (forge.tls, forge.hmac, forge.util) may be undefined — only
// forge.default.* is available. Resolve the actual module object once.

const forge: typeof forgeNamespace =
  (forgeNamespace as Record<string, unknown>).tls !== undefined
    ? forgeNamespace
    : ((forgeNamespace as Record<string, unknown>).default as typeof forgeNamespace);

// -- Node-forge internal types -----------------------------------------------
// node-forge's TLS internals are not exposed in @types/node-forge.
// These types mirror the actual runtime shapes used by aesCipherSuites.js.

// node-forge TLS internals (CipherSuites, BulkCipherAlgorithm, etc.)
// are not exposed in @types/node-forge. Runtime access is required.
// biome-ignore lint/suspicious/noExplicitAny: node-forge TLS internals have no type definitions
const tls: Record<string, any> = forge.tls as Record<string, unknown>;

if (!tls?.CipherSuites) {
  throw new Error(
    "node-forge TLS internals not available. " + "Ensure node-forge is installed and compatible.",
  );
}

// ConnectionEnd.client === 1 in node-forge
const CLIENT_ENTITY = 1;

interface SeqNum extends Array<number> {
  0: number;
  1: number;
}

interface TlsRecord {
  type: number;
  version: { major: number; minor: number };
  length: number;
  fragment: forgeNamespace.util.ByteStringBuffer;
}

interface CipherState {
  rc4: RC4;
}

interface ConnectionMode {
  sequenceNumber: SeqNum;
  macKey: string;
  macLength: number;
  macFunction: MacFunction | null;
  cipherState: CipherState | null;
  cipherFunction: (record: TlsRecord, s: ConnectionMode) => boolean;
  updateSequenceNumber: () => void;
}

interface SecurityParams {
  bulk_cipher_algorithm: number;
  cipher_type: number;
  enc_key_length: number;
  block_length: number;
  fixed_iv_length: number;
  record_iv_length: number;
  mac_algorithm: number;
  mac_length: number;
  mac_key_length: number;
  keys: {
    client_write_key: string;
    server_write_key: string;
    client_write_MAC_key: string;
    server_write_MAC_key: string;
  };
}

interface ConnectionState {
  read: ConnectionMode;
  write: ConnectionMode;
}

type MacFunction = (key: string, seqNum: SeqNum, record: TlsRecord) => string;

// -- RC4 stream cipher -------------------------------------------------------

class RC4 {
  private S: number[];
  private i = 0;
  private j = 0;

  constructor(key: string) {
    const S = new Array<number>(256);
    for (let i = 0; i < 256; i++) S[i] = i;

    let j = 0;
    for (let i = 0; i < 256; i++) {
      j = (j + (S[i] ?? 0) + key.charCodeAt(i % key.length)) & 0xff;
      const si = S[i] ?? 0;
      const sj = S[j] ?? 0;
      S[i] = sj;
      S[j] = si;
    }

    this.S = S;
  }

  /** XOR input with RC4 keystream (encrypt and decrypt are identical). */
  process(input: string): string {
    const S = this.S;
    const out: string[] = [];

    for (let n = 0; n < input.length; n++) {
      this.i = (this.i + 1) & 0xff;
      this.j = (this.j + (S[this.i] ?? 0)) & 0xff;
      const si = S[this.i] ?? 0;
      const sj = S[this.j] ?? 0;
      S[this.i] = sj;
      S[this.j] = si;
      const k = S[((S[this.i] ?? 0) + (S[this.j] ?? 0)) & 0xff] ?? 0;
      out.push(String.fromCharCode(input.charCodeAt(n) ^ k));
    }

    return out.join("");
  }
}

// -- MAC functions -----------------------------------------------------------

function buildMac(algo: "md5" | "sha1", key: string, seqNum: SeqNum, record: TlsRecord): string {
  const hmac = forge.hmac.create();
  hmac.start(algo, key);
  const b = forge.util.createBuffer();
  b.putInt32(seqNum[0]);
  b.putInt32(seqNum[1]);
  b.putByte(record.type);
  b.putByte(record.version.major);
  b.putByte(record.version.minor);
  b.putInt16(record.length);
  b.putBytes(record.fragment.bytes());
  hmac.update(b.getBytes());
  return hmac.digest().getBytes();
}

const hmacMd5: MacFunction = (key, seqNum, record) => buildMac("md5", key, seqNum, record);

const hmacSha1: MacFunction = (key, seqNum, record) => buildMac("sha1", key, seqNum, record);

// -- Constant-time MAC comparison (mirrors aesCipherSuites.js) ---------------

function compareMacs(key: string, mac1: string, mac2: string): boolean {
  const h1 = forge.hmac.create();
  h1.start("sha1", key);
  h1.update(mac1);

  const h2 = forge.hmac.create();
  h2.start("sha1", key);
  h2.update(mac2);

  return h1.digest().getBytes() === h2.digest().getBytes();
}

// -- Stream cipher encrypt/decrypt -------------------------------------------

function encryptRc4(record: TlsRecord, s: ConnectionMode): boolean {
  if (!s.macFunction || !s.cipherState) return false;

  const mac = s.macFunction(s.macKey, s.sequenceNumber, record);
  record.fragment.putBytes(mac);
  s.updateSequenceNumber();

  const plaintext = record.fragment.getBytes();
  const ciphertext = s.cipherState.rc4.process(plaintext);
  record.fragment = forge.util.createBuffer(ciphertext);
  record.length = record.fragment.length();

  return true;
}

function decryptRc4(record: TlsRecord, s: ConnectionMode): boolean {
  if (!s.macFunction || !s.cipherState) return false;

  const ciphertext = record.fragment.getBytes();
  const decrypted = s.cipherState.rc4.process(ciphertext);

  const macLen = s.macLength;
  if (decrypted.length < macLen) {
    return false;
  }

  const payload = decrypted.slice(0, decrypted.length - macLen);
  const receivedMac = decrypted.slice(decrypted.length - macLen);

  record.fragment = forge.util.createBuffer(payload);
  record.length = payload.length;

  const expectedMac = s.macFunction(s.macKey, s.sequenceNumber, record);
  s.updateSequenceNumber();

  return compareMacs(s.macKey, receivedMac, expectedMac);
}

// -- Connection state initialization -----------------------------------------

function initRc4State(
  state: ConnectionState,
  c: { entity: number },
  sp: SecurityParams,
  macFn: MacFunction,
): void {
  const isClient = c.entity === CLIENT_ENTITY;

  const readKey = isClient ? sp.keys.server_write_key : sp.keys.client_write_key;
  const writeKey = isClient ? sp.keys.client_write_key : sp.keys.server_write_key;

  state.read.cipherState = { rc4: new RC4(readKey) };
  state.write.cipherState = { rc4: new RC4(writeKey) };

  state.read.cipherFunction = decryptRc4;
  state.write.cipherFunction = encryptRc4;

  state.read.macLength = sp.mac_length;
  state.write.macLength = sp.mac_length;
  state.read.macFunction = macFn;
  state.write.macFunction = macFn;
}

// -- Cipher suite registration -----------------------------------------------

// TLS_RSA_WITH_RC4_128_MD5 (0x0004)
tls.CipherSuites.TLS_RSA_WITH_RC4_128_MD5 = {
  id: [0x00, 0x04],
  name: "TLS_RSA_WITH_RC4_128_MD5",
  initSecurityParameters(sp: SecurityParams) {
    sp.bulk_cipher_algorithm = tls.BulkCipherAlgorithm.rc4;
    sp.cipher_type = tls.CipherType.stream;
    sp.enc_key_length = 16;
    sp.block_length = 0;
    sp.fixed_iv_length = 0;
    sp.record_iv_length = 0;
    sp.mac_algorithm = tls.MACAlgorithm.hmac_md5;
    sp.mac_length = 16;
    sp.mac_key_length = 16;
  },
  initConnectionState(state: ConnectionState, c: { entity: number }, sp: SecurityParams) {
    initRc4State(state, c, sp, hmacMd5);
  },
};

// TLS_RSA_WITH_RC4_128_SHA (0x0005)
tls.CipherSuites.TLS_RSA_WITH_RC4_128_SHA = {
  id: [0x00, 0x05],
  name: "TLS_RSA_WITH_RC4_128_SHA",
  initSecurityParameters(sp: SecurityParams) {
    sp.bulk_cipher_algorithm = tls.BulkCipherAlgorithm.rc4;
    sp.cipher_type = tls.CipherType.stream;
    sp.enc_key_length = 16;
    sp.block_length = 0;
    sp.fixed_iv_length = 0;
    sp.record_iv_length = 0;
    sp.mac_algorithm = tls.MACAlgorithm.hmac_sha1;
    sp.mac_length = 20;
    sp.mac_key_length = 20;
  },
  initConnectionState(state: ConnectionState, c: { entity: number }, sp: SecurityParams) {
    initRc4State(state, c, sp, hmacSha1);
  },
};
