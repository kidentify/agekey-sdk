import { describe, it, expect } from "vitest";
import {
  AgeKey,
  AccessDeniedError,
  InvalidTokenError,
  InvalidRequestError,
  ServerError,
  StateMismatchError,
  NonceMismatchError,
} from "../src";

const client = () =>
  new AgeKey({
    clientId: "ak_test_123456",
    redirectUri: "https://example.com/callback",
  }).useAgeKey;

const claimsOf = (url: string) =>
  JSON.parse(new URL(url).searchParams.get("claims") || "{}");

const jwt = (payload: Record<string, unknown>) =>
  `${btoa('{"alg":"RS256"}')}.${btoa(JSON.stringify(payload))}.sig`;

const future = () => Math.floor(Date.now() / 1000) + 3600;

describe("getAuthorizationUrl claims", () => {
  it("omits optional claims when not requested", () => {
    const c = claimsOf(client().getAuthorizationUrl({ ageThresholds: [18] }).url);
    expect(c).toEqual({ age_thresholds: [18] });
  });

  it("omits empty allowedMethods, overrides and provenance lists", () => {
    const c = claimsOf(
      client().getAuthorizationUrl({
        ageThresholds: [18],
        allowedMethods: [],
        overrides: {},
        provenance: { allowed: [], denied: [] },
      }).url
    );
    expect(c).toEqual({ age_thresholds: [18] });
  });

  it("includes provenance allowed only", () => {
    const c = claimsOf(
      client().getAuthorizationUrl({
        ageThresholds: [18],
        provenance: { allowed: ["/a"] },
      }).url
    );
    expect(c.provenance).toEqual({ allowed: ["/a"] });
  });

  it("includes provenance denied only", () => {
    const c = claimsOf(
      client().getAuthorizationUrl({
        ageThresholds: [18],
        provenance: { denied: ["/b"] },
      }).url
    );
    expect(c.provenance).toEqual({ denied: ["/b"] });
  });

  it("includes both provenance lists", () => {
    const c = claimsOf(
      client().getAuthorizationUrl({
        ageThresholds: [18],
        provenance: { allowed: ["/a"], denied: ["/b"] },
      }).url
    );
    expect(c.provenance).toEqual({ allowed: ["/a"], denied: ["/b"] });
  });

  it("accepts facial_age_estimation override with age_thresholds", () => {
    const c = claimsOf(
      client().getAuthorizationUrl({
        ageThresholds: [18],
        overrides: { facial_age_estimation: { age_thresholds: [21] } },
      }).url
    );
    expect(c.overrides.facial_age_estimation.age_thresholds).toEqual([21]);
  });

  it("accepts facial_age_estimation override with min_age 0", () => {
    const c = claimsOf(
      client().getAuthorizationUrl({
        ageThresholds: [18],
        overrides: { facial_age_estimation: { min_age: 0 } },
      }).url
    );
    expect(c.overrides.facial_age_estimation.min_age).toBe(0);
  });

  it("passes overrides for other methods without facial check", () => {
    const c = claimsOf(
      client().getAuthorizationUrl({
        ageThresholds: [18],
        overrides: { id_doc_scan: { min_age: 21 } },
      } as never).url
    );
    expect(c.overrides).toEqual({ id_doc_scan: { min_age: 21 } });
  });

  it("rejects facial_age_estimation override with neither min_age nor age_thresholds", () => {
    const run = (facial: unknown) => () =>
      client().getAuthorizationUrl({
        ageThresholds: [18],
        overrides: { facial_age_estimation: facial },
      } as never);
    expect(run({})).toThrow(InvalidRequestError);
    expect(run({})).toThrow(
      "overrides.facial_age_estimation requires either min_age or age_thresholds (per request-claims schema)"
    );
    expect(run({ age_thresholds: [] })).toThrow(InvalidRequestError);
    expect(run({ min_age: "21" })).toThrow(InvalidRequestError);
  });

  it("uses the live endpoint when configured live", () => {
    const { url } = new AgeKey({
      clientId: "ak_live_123456",
      redirectUri: "https://example.com/callback",
    }).useAgeKey.getAuthorizationUrl({ ageThresholds: [18] });
    expect(url.startsWith("https://api.agekey.org/v1/oidc/use?")).toBe(true);
  });
});

describe("handleCallback errors", () => {
  const v = { state: "s", nonce: "n" };
  const base = "https://example.com/callback";

  it("maps access_denied with description", () => {
    let err: unknown;
    try {
      client().handleCallback(`${base}?error=access_denied&error_description=x`, v);
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(AccessDeniedError);
    expect((err as AccessDeniedError).errorDescription).toBe("x");
    expect((err as AccessDeniedError).message).toBe("x");
  });

  it("maps access_denied without description to undefined description", () => {
    let err: unknown;
    try {
      client().handleCallback(`${base}?error=access_denied`, v);
    } catch (e) {
      err = e;
    }
    expect((err as AccessDeniedError).errorDescription).toBeUndefined();
  });

  it("reads errors from the fragment", () => {
    expect(() =>
      client().handleCallback(`${base}#error=server_error&error_description=boom`, v)
    ).toThrow(ServerError);
  });

  it("checks error before state", () => {
    expect(() =>
      client().handleCallback(`${base}?error=access_denied&state=other`, v)
    ).toThrow(AccessDeniedError);
  });

  it("throws StateMismatchError when state missing", () => {
    expect(() => client().handleCallback(`${base}?id_token=x`, v)).toThrow(
      StateMismatchError
    );
  });

  it("throws 'No ID token in callback'", () => {
    const run = () => client().handleCallback(`${base}?state=s`, v);
    expect(run).toThrow(InvalidTokenError);
    expect(run).toThrow("No ID token in callback");
  });

  it("throws 'Failed to decode ID token' on malformed JWT", () => {
    const run = () => client().handleCallback(`${base}?state=s&id_token=notajwt`, v);
    expect(run).toThrow(InvalidTokenError);
    expect(run).toThrow("Failed to decode ID token");
  });

  it("throws NonceMismatchError when nonce is not a string", () => {
    const t = jwt({ nonce: 5, exp: future(), age_thresholds: {} });
    expect(() => client().handleCallback(`${base}?state=s&id_token=${t}`, v)).toThrow(
      NonceMismatchError
    );
  });

  it("throws 'ID token has expired' when exp missing", () => {
    const t = jwt({ nonce: "n", age_thresholds: {} });
    const run = () => client().handleCallback(`${base}?state=s&id_token=${t}`, v);
    expect(run).toThrow("ID token has expired");
  });

  it("treats exp equal to now as expired", () => {
    const t = jwt({ nonce: "n", exp: 1, age_thresholds: {} });
    expect(() => client().handleCallback(`${base}?state=s&id_token=${t}`, v)).toThrow(
      "ID token has expired"
    );
  });

  it("throws 'No age_thresholds in ID token' when missing or null", () => {
    for (const at of [undefined, null, "x"]) {
      const t = jwt({ nonce: "n", exp: future(), age_thresholds: at });
      expect(() =>
        client().handleCallback(`${base}?state=s&id_token=${t}`, v)
      ).toThrow("No age_thresholds in ID token");
    }
  });

  it("returns subject undefined when sub is not a string, code undefined, and raw payload", () => {
    const payload = { nonce: "n", exp: future(), sub: 5, age_thresholds: { "18": true } };
    const t = jwt(payload);
    const r = client().handleCallback(`${base}?state=s&id_token=${t}`, v);
    expect(r.subject).toBeUndefined();
    expect(r.code).toBeUndefined();
    expect(r.raw).toEqual(payload);
  });

  it("bare '#' fragment does not hide query params", () => {
    const t = jwt({ nonce: "n", exp: future(), age_thresholds: { "18": true } });
    const r = client().handleCallback(`${base}?state=s&id_token=${t}#`, v);
    expect(r.ageThresholds).toEqual({ "18": true });
  });

  it("fragment params take precedence over query params", () => {
    const t = jwt({ nonce: "n", exp: future(), age_thresholds: { "18": true } });
    const r = client().handleCallback(
      `${base}?state=wrong&id_token=bad#state=s&id_token=${t}`,
      v
    );
    expect(r.ageThresholds).toEqual({ "18": true });
  });

  it("a single-char fragment is ignored, two chars are parsed", () => {
    expect(
      client().parseCallback(`${base}?state=q#x`).state
    ).toBe("q");
    expect(client().parseCallback(`${base}?state=q#state=f`).state).toBe("f");
  });
});

describe("parseCallback", () => {
  it("returns nulls for empty url params", () => {
    expect(client().parseCallback("https://example.com/callback")).toEqual({
      idToken: null,
      code: null,
      state: null,
      error: null,
      errorDescription: null,
    });
  });

  it("returns every field", () => {
    expect(
      client().parseCallback(
        "https://example.com/cb#id_token=i&code=c&state=s&error=e&error_description=d"
      )
    ).toEqual({ idToken: "i", code: "c", state: "s", error: "e", errorDescription: "d" });
  });
});
