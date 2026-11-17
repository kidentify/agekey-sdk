import { describe, it, expect, vi, afterEach } from "vitest";
import {
  AgeKey,
  InvalidRequestError,
  NetworkError,
} from "../src";

const make = (secret?: string) =>
  new AgeKey({
    clientId: "ak_test_123456",
    redirectUri: "https://example.com/callback",
    ...(secret ? { clientSecret: secret } : {}),
  });

const resp = (status: number, body: unknown, jsonFails = false) => ({
  ok: status >= 200 && status < 300,
  status,
  json: jsonFails
    ? () => Promise.reject(new Error("bad json"))
    : () => Promise.resolve(body),
});

const mockFetch = (r: unknown) => {
  const f = vi.fn().mockResolvedValue(r);
  vi.stubGlobal("fetch", f);
  return f;
};

afterEach(() => vi.unstubAllGlobals());

describe("exchangeCode", () => {
  it("requires a client secret", async () => {
    const f = mockFetch(resp(200, {}));
    const p = make().upgradeDirect.exchangeCode("c");
    await expect(p).rejects.toBeInstanceOf(InvalidRequestError);
    await expect(p).rejects.toThrow(
      "Client secret is required for token exchange. This method must be called server-side."
    );
    expect(f).not.toHaveBeenCalled();
  });

  it("posts basic-auth form and returns the token", async () => {
    const f = mockFetch(
      resp(200, { access_token: "at", token_type: "MAC", expires_in: 60 })
    );
    const r = await make("sk_test_s").upgradeDirect.exchangeCode("the code");
    expect(r).toEqual({ accessToken: "at", tokenType: "MAC", expiresIn: 60 });
    const [url, init] = f.mock.calls[0];
    expect(url).toBe("https://api-test.agekey.org/v1/oidc/use/token");
    expect(init.method).toBe("POST");
    expect(init.headers["Content-Type"]).toBe("application/x-www-form-urlencoded");
    expect(init.headers.Authorization).toBe(
      `Basic ${btoa("ak_test_123456:sk_test_s")}`
    );
    const body = new URLSearchParams(init.body);
    expect(body.get("grant_type")).toBe("authorization_code");
    expect(body.get("code")).toBe("the code");
  });

  it("defaults tokenType to Bearer and expiresIn to 0", async () => {
    mockFetch(resp(200, { access_token: "at" }));
    expect(await make("s").upgradeDirect.exchangeCode("c")).toEqual({
      accessToken: "at",
      tokenType: "Bearer",
      expiresIn: 0,
    });
  });

  it("wraps fetch failures in NetworkError with cause", async () => {
    const cause = new Error("offline");
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(cause));
    const p = make("s").upgradeDirect.exchangeCode("c");
    await expect(p).rejects.toBeInstanceOf(NetworkError);
    await expect(p).rejects.toThrow("Failed to connect to AgeKey token endpoint");
    await expect(p).rejects.toMatchObject({ cause });
  });

  it("wraps invalid JSON in NetworkError", async () => {
    mockFetch(resp(200, null, true));
    await expect(make("s").upgradeDirect.exchangeCode("c")).rejects.toBeInstanceOf(
      NetworkError
    );
  });

  it("wraps non-Error rejections in NetworkError", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue("str"));
    await expect(make("s").upgradeDirect.exchangeCode("c")).rejects.toBeInstanceOf(
      NetworkError
    );
  });
});

describe("upgrade", () => {
  const opts = {
    method: "id_doc_scan" as const,
    age: { age_at_least_years: 18 } as never,
    verifiedAt: new Date("2024-05-06T07:08:09.000Z"),
    verificationId: "v-1",
    provenance: "/prov",
  };

  it("posts authorization_details with bearer token and returns success", async () => {
    const f = mockFetch(resp(200, {}));
    const r = await make().upgradeDirect.upgrade("tok", {
      ...opts,
      attributes: { a: 1 } as never,
    });
    expect(r).toEqual({ success: true });
    const [url, init] = f.mock.calls[0];
    expect(url).toBe("https://api-test.agekey.org/v1/agekey/upgrade");
    expect(init.method).toBe("POST");
    expect(init.headers["Content-Type"]).toBe("application/json");
    expect(init.headers.Authorization).toBe("Bearer tok");
    const outer = JSON.parse(init.body);
    expect(Object.keys(outer)).toEqual(["authorization_details"]);
    expect(typeof outer.authorization_details).toBe("string");
    expect(JSON.parse(outer.authorization_details)).toEqual([
      {
        type: "age_verification",
        method: "id_doc_scan",
        age: { age_at_least_years: 18 },
        verified_at: "2024-05-06T07:08:09.000Z",
        verification_id: "v-1",
        provenance: "/prov",
        attributes: { a: 1 },
      },
    ]);
  });

  it("omits attributes when not given", async () => {
    const f = mockFetch(resp(200, {}));
    await make().upgradeDirect.upgrade("tok", opts);
    const details = JSON.parse(JSON.parse(f.mock.calls[0][1].body).authorization_details);
    expect("attributes" in details[0]).toBe(false);
  });

  it("wraps fetch failures in NetworkError with cause", async () => {
    const cause = new Error("offline");
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(cause));
    const p = make().upgradeDirect.upgrade("t", opts);
    await expect(p).rejects.toBeInstanceOf(NetworkError);
    await expect(p).rejects.toThrow("Failed to connect to AgeKey upgrade endpoint");
    await expect(p).rejects.toMatchObject({ cause });
  });
});
