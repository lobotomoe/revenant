/**
 * Tests for changing the account password.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/network/soap-transport.js", () => ({
  changePassword: vi.fn(),
  enumCertificates: vi.fn(),
  SoapSigningTransport: class {
    constructor(public url: string) {}
  },
}));

import * as api from "../src/api.js";
import {
  changePassword,
  checkNewPassword,
  shorterThanObservedMinimum,
} from "../src/core/password.js";
import { AuthError, ConfigError, RevenantError, ServerError, TLSError } from "../src/errors.js";
import {
  buildChangePasswordEnvelope,
  buildEnumCertificatesEnvelope,
  buildSignEnvelope,
  buildSignHashEnvelope,
} from "../src/network/soap-envelope.js";
import {
  parseChangePasswordResponse,
  parseEnumCertificatesResponse,
} from "../src/network/soap-parsers.js";
import {
  enumCertificates,
  changePassword as sendChangePassword,
} from "../src/network/soap-transport.js";

const URL = "https://example.com/SAPIWS/DSS.asmx";
const CERTS = [new Uint8Array([0x30])];

function response(major: string, message?: string): string {
  const messageXml = message ? `<ResultMessage>${message}</ResultMessage>` : "";
  return (
    '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>' +
    "<DssSignResponse><DssSignResult><Result>" +
    `<ResultMajor>urn:oasis:names:tc:dss:1.0:resultmajor:${major}</ResultMajor>` +
    "<ResultMinor>urn:oasis:names:tc:dss:1.0:resultminor:GeneralError</ResultMinor>" +
    `${messageXml}</Result></DssSignResult></DssSignResponse></soap:Body></soap:Envelope>`
  );
}

beforeEach(() => {
  vi.mocked(sendChangePassword).mockReset();
  vi.mocked(enumCertificates).mockReset();
});

describe("change-password envelope", () => {
  it("adds the new password after the current one", () => {
    const envelope = buildChangePasswordEnvelope("alice", "old", "n<w");
    expect(envelope).toContain(
      "<arx:LogonPassword>old</arx:LogonPassword>\n" +
        "              <arx:NewLogonPassword>n&lt;w</arx:NewLogonPassword>",
    );
    expect(envelope).toContain("enum-certificates</SignatureType>");
  });

  it("is the only request that carries a new password", () => {
    const requests = [
      buildSignEnvelope("u", "p", "urn:ietf:rfc:3369", "ZA=="),
      buildSignHashEnvelope("u", "p", "urn:ietf:rfc:3369", "aGFzaA=="),
      buildEnumCertificatesEnvelope("u", "p"),
    ];
    for (const request of requests) {
      expect(request).not.toContain("NewLogonPassword");
    }
  });
});

describe("parseChangePasswordResponse", () => {
  it("accepts a success response", () => {
    expect(() => parseChangePasswordResponse(response("Success"))).not.toThrow();
  });

  // Both messages below are the appliance's own, captured live.
  it("reports a wrong current password as an auth error", () => {
    const xml = response("ResponderError", "Failed to verify user name and password");
    expect(() => parseChangePasswordResponse(xml)).toThrow(AuthError);
    expect(() => parseEnumCertificatesResponse(xml)).toThrow(AuthError);
  });

  it("reports a refused new password as a server error, not bad credentials", () => {
    const xml = response("ResponderError", "Error changing password err 90020150");
    expect(() => parseChangePasswordResponse(xml)).toThrow(ServerError);
    expect(() => parseChangePasswordResponse(xml)).toThrow(/90020150/);
  });
});

describe("checkNewPassword", () => {
  it.each([
    ["", false, "empty"],
    ["old", false, "same-as-current"],
    [" new", false, "surrounding-whitespace"],
    ["new\n", false, "surrounding-whitespace"],
    ["\u043f\u0430\u0440\u043e\u043b\u044c", true, "non-ascii"],
    ["\u043f\u0430\u0440\u043e\u043b\u044c", false, null],
    ["new pass-1", true, null],
  ])("checks %j (asciiOnly=%s)", (next, asciiOnly, expected) => {
    expect(checkNewPassword("old", next, asciiOnly)).toBe(expected);
  });
});

describe("shorterThanObservedMinimum", () => {
  it("explains a refusal only when the password is too short", () => {
    expect(shorterThanObservedMinimum("abcde", 6)).toBe(6);
    expect(shorterThanObservedMinimum("abcdef", 6)).toBeNull();
    expect(shorterThanObservedMinimum("abc", null)).toBeNull();
  });
});

describe("changePassword", () => {
  const run = () => changePassword(URL, "user", "old", "new", 30);

  it("confirms an accepted change with the new password", async () => {
    vi.mocked(enumCertificates).mockResolvedValue(CERTS);
    await expect(run()).resolves.toEqual({ confirmed: true });
    expect(sendChangePassword).toHaveBeenCalledExactlyOnceWith(URL, "user", "old", "new", 30);
    expect(enumCertificates).toHaveBeenCalledExactlyOnceWith(URL, "user", "new", 30);
  });

  it("reports a wrong current password without a second logon", async () => {
    vi.mocked(sendChangePassword).mockRejectedValue(new AuthError("bad"));
    await expect(run()).rejects.toThrow(AuthError);
    expect(enumCertificates).not.toHaveBeenCalled();
  });

  it("reports a refused new password without a second logon", async () => {
    vi.mocked(sendChangePassword).mockRejectedValue(new ServerError("refused"));
    await expect(run()).rejects.toThrow(ServerError);
    expect(enumCertificates).not.toHaveBeenCalled();
  });

  it("treats success from a server that ignored the new password as an error", async () => {
    vi.mocked(enumCertificates).mockRejectedValue(new AuthError("bad"));
    await expect(run()).rejects.toThrow(ServerError);
  });

  it("is unconfirmed when an accepted change cannot be checked", async () => {
    vi.mocked(enumCertificates).mockRejectedValue(new TLSError("timed out"));
    await expect(run()).resolves.toEqual({ confirmed: false, reason: "timed out" });
  });

  it("counts a lost response to an applied change as changed", async () => {
    vi.mocked(sendChangePassword).mockRejectedValue(new TLSError("timed out"));
    vi.mocked(enumCertificates).mockResolvedValue(CERTS);
    await expect(run()).resolves.toEqual({ confirmed: true });
  });

  it("rethrows the request error when the change was not applied", async () => {
    vi.mocked(sendChangePassword).mockRejectedValue(new TLSError("timed out"));
    vi.mocked(enumCertificates).mockRejectedValue(new AuthError("bad"));
    await expect(run()).rejects.toThrow(TLSError);
  });

  it("is unconfirmed when a failed request cannot be checked either", async () => {
    vi.mocked(sendChangePassword).mockRejectedValue(new TLSError("request timed out"));
    vi.mocked(enumCertificates).mockRejectedValue(new TLSError("still down"));
    await expect(run()).resolves.toEqual({ confirmed: false, reason: "request timed out" });
  });
});

describe("api.changePassword", () => {
  it("refuses a bad new password before sending", async () => {
    await expect(api.changePassword("user", "old", "old", { url: URL })).rejects.toThrow(
      /same as the current/,
    );
    await expect(
      api.changePassword("user", "old", "\u043f\u0430\u0440\u043e\u043b\u044c", {
        profile: "ekeng",
      }),
    ).rejects.toThrow(/Latin/);
    await expect(api.changePassword("user", "old", "", { url: URL })).rejects.toThrow(
      RevenantError,
    );
    expect(sendChangePassword).not.toHaveBeenCalled();
  });

  it("rejects profile and url together", async () => {
    await expect(
      api.changePassword("user", "old", "new", { profile: "ekeng", url: URL }),
    ).rejects.toThrow(ConfigError);
  });

  it("resolves the server and changes the password", async () => {
    vi.mocked(enumCertificates).mockResolvedValue(CERTS);
    const outcome = await api.changePassword("user", "old", "new-pass", { url: URL, timeout: 7 });
    expect(outcome).toEqual({ confirmed: true });
    expect(sendChangePassword).toHaveBeenCalledExactlyOnceWith(URL, "user", "old", "new-pass", 7);
  });
});
