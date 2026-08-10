/**
 * Tests for server key pinning.
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { describe, expect, it } from "vitest";
import { TLSError } from "../src/errors.js";
import { checkServerPin, spkiFingerprint } from "../src/network/tls-pinning.js";

function fixture(name: string): Uint8Array {
  return new Uint8Array(
    readFileSync(
      new URL(`../../rust/crates/revenant-sign-core/src/pki/testdata/${name}`, import.meta.url),
    ),
  );
}

/** Pull the SubjectPublicKeyInfo out of a DER certificate. */
function spkiOf(certDer: Uint8Array): Uint8Array {
  const asn1 = asn1js.fromBER(
    certDer.buffer.slice(certDer.byteOffset, certDer.byteOffset + certDer.byteLength),
  );
  const cert = new pkijs.Certificate({ schema: asn1.result });
  return new Uint8Array(cert.subjectPublicKeyInfo.toSchema().toBER(false));
}

const SPKI = spkiOf(fixture("test_signer_cert.der"));
const PIN = spkiFingerprint(SPKI);

const OTHER_SPKI = spkiOf(fixture("leaf.der"));

describe("spkiFingerprint", () => {
  it("is the sha256 of the subject public key info", () => {
    expect(PIN).toBe(createHash("sha256").update(SPKI).digest("hex"));
  });

  it("is stable across calls", () => {
    expect(spkiFingerprint(SPKI)).toBe(PIN);
  });

  it("differs for a different key", () => {
    expect(spkiFingerprint(OTHER_SPKI)).not.toBe(PIN);
  });
});

describe("checkServerPin", () => {
  it("accepts a matching pin", () => {
    expect(() => checkServerPin(SPKI, [PIN], "appliance.example", 8080)).not.toThrow();
  });

  it("ignores case and colons in the configured pin", () => {
    const formatted = (PIN.match(/../g) ?? []).join(":").toUpperCase();
    expect(() => checkServerPin(SPKI, [formatted], "appliance.example", 8080)).not.toThrow();
  });

  it("accepts any of several pins", () => {
    expect(() =>
      checkServerPin(SPKI, ["00".repeat(32), PIN], "appliance.example", 8080),
    ).not.toThrow();
  });

  it("refuses a different key and names both sides", () => {
    let message = "";
    try {
      checkServerPin(OTHER_SPKI, [PIN], "appliance.example", 8080);
    } catch (err) {
      expect(err).toBeInstanceOf(TLSError);
      message = err instanceof Error ? err.message : "";
    }
    // Both sides are named so the operator can tell a rotation from an attack.
    expect(message).toContain(spkiFingerprint(OTHER_SPKI));
    expect(message).toContain(PIN);
  });

  it("refuses when no pin is configured and reports what was presented", () => {
    expect(() => checkServerPin(SPKI, [], "appliance.example", 8080)).toThrow(
      "No pinned key configured",
    );
    expect(() => checkServerPin(SPKI, [], "appliance.example", 8080)).toThrow(PIN);
  });
});
