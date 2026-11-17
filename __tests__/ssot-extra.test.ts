import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  clearSsotCache,
  fetchProvenanceConfig,
  fetchAuthorizationDetailSchema,
  DEFAULT_PROVENANCE_CONFIG_URL,
  DEFAULT_AUTHORIZATION_DETAIL_SCHEMA_URL,
  verificationMethodsFromAuthorizationDetailSchema,
  digitalCredentialPlatformsFromAuthorizationDetailSchema,
  provenancePathsFromAuthorizationDetailSchema,
  activeProviderPathsFromProvenanceConfig,
  providerEntryFromProvenanceConfig,
  providerPathsForMethodFromProvenanceConfig,
  methodsForProviderPathFromProvenanceConfig,
  verificationMethodKeysFromProvenanceConfig,
} from "../src/ssot";

const ok = (body: unknown) =>
  vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(body) });

beforeEach(() => clearSsotCache());

describe("fetching", () => {
  it("default URLs point at schemas.agekey.org", async () => {
    expect(DEFAULT_PROVENANCE_CONFIG_URL).toBe(
      "https://schemas.agekey.org/provenance/current/provenance-config.json"
    );
    expect(DEFAULT_AUTHORIZATION_DETAIL_SCHEMA_URL).toBe(
      "https://schemas.agekey.org/authorization-schemas/current/authorization-detail.schema.json"
    );
    const f1 = ok({});
    await fetchProvenanceConfig({ fetchImpl: f1 });
    expect(f1.mock.calls[0][0]).toBe(DEFAULT_PROVENANCE_CONFIG_URL);
    const f2 = ok({});
    await fetchAuthorizationDetailSchema({ fetchImpl: f2 });
    expect(f2.mock.calls[0][0]).toBe(DEFAULT_AUTHORIZATION_DETAIL_SCHEMA_URL);
  });

  it("uses global fetch by default", async () => {
    const f = ok({ version: 1 });
    vi.stubGlobal("fetch", f);
    try {
      expect(await fetchProvenanceConfig({ url: "https://g.test/p" })).toEqual({
        version: 1,
      });
      expect(f).toHaveBeenCalledTimes(1);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("serves the second call from cache (schema)", async () => {
    const f = ok({ a: 1 });
    const o = { url: "https://c.test/s", fetchImpl: f };
    const a = await fetchAuthorizationDetailSchema(o);
    const b = await fetchAuthorizationDetailSchema(o);
    expect(f).toHaveBeenCalledTimes(1);
    expect(b).toBe(a);
  });

  it("caches per URL", async () => {
    const f = ok({});
    await fetchProvenanceConfig({ url: "https://c.test/1", fetchImpl: f });
    await fetchProvenanceConfig({ url: "https://c.test/2", fetchImpl: f });
    expect(f).toHaveBeenCalledTimes(2);
  });

  it("provenance and schema caches are separate", async () => {
    const f = ok({});
    await fetchProvenanceConfig({ url: "https://c.test/same", fetchImpl: f });
    await fetchAuthorizationDetailSchema({ url: "https://c.test/same", fetchImpl: f });
    expect(f).toHaveBeenCalledTimes(2);
  });

  it("clearSsotCache forces a refetch of both caches", async () => {
    const f = ok({});
    const p = { url: "https://c.test/p", fetchImpl: f };
    const s = { url: "https://c.test/s", fetchImpl: f };
    await fetchProvenanceConfig(p);
    await fetchAuthorizationDetailSchema(s);
    clearSsotCache();
    await fetchProvenanceConfig(p);
    await fetchAuthorizationDetailSchema(s);
    expect(f).toHaveBeenCalledTimes(4);
  });

  it("rejects on non-OK status with label, status and text, and does not cache it", async () => {
    const bad = vi
      .fn()
      .mockResolvedValue({ ok: false, status: 500, statusText: "Server Down" });
    await expect(
      fetchProvenanceConfig({ url: "https://e.test/p", fetchImpl: bad })
    ).rejects.toThrow("provenance-config fetch failed: 500 Server Down");
    await expect(
      fetchAuthorizationDetailSchema({ url: "https://e.test/s", fetchImpl: bad })
    ).rejects.toThrow("authorization-detail.schema fetch failed: 500 Server Down");

    const good = ok({ version: 3 });
    expect(
      await fetchProvenanceConfig({ url: "https://e.test/p", fetchImpl: good })
    ).toEqual({ version: 3 });
    expect(good).toHaveBeenCalledTimes(1);
  });

  it("missing fetch error names fetchImpl", async () => {
    vi.stubGlobal("fetch", undefined);
    try {
      await expect(fetchAuthorizationDetailSchema({ url: "https://x" })).rejects.toThrow(
        "fetch is not available; pass fetchImpl in options (Node < 18 or restricted environments)."
      );
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

describe("helpers", () => {
  it("schema helpers filter non-strings and tolerate missing parts", () => {
    const schema = {
      $defs: {
        methods: { enum: ["a", 1, "b", null] },
        digital_credential_platforms: { enum: ["p", {}] },
      },
      properties: { provenance: { enum: ["/x", 2] } },
    };
    expect(verificationMethodsFromAuthorizationDetailSchema(schema)).toEqual(["a", "b"]);
    expect(digitalCredentialPlatformsFromAuthorizationDetailSchema(schema)).toEqual(["p"]);
    expect(provenancePathsFromAuthorizationDetailSchema(schema)).toEqual(["/x"]);
    expect(verificationMethodsFromAuthorizationDetailSchema({})).toEqual([]);
    expect(digitalCredentialPlatformsFromAuthorizationDetailSchema({})).toEqual([]);
    expect(provenancePathsFromAuthorizationDetailSchema({})).toEqual([]);
    expect(
      verificationMethodsFromAuthorizationDetailSchema({ $defs: { methods: {} } })
    ).toEqual([]);
    expect(
      provenancePathsFromAuthorizationDetailSchema({ properties: { provenance: {} } })
    ).toEqual([]);
  });

  const cfg = {
    verification_methods: { zeta: {}, alpha: {} },
    providers: {
      "/z": { status: "active", methods: ["m1", "m2"] },
      "/a": { methods: ["m1"] },
      "/e": { status: "", methods: ["m1"] },
      "/off": { status: "retired", methods: ["m1"] },
      "/nom": { status: "active" },
    },
  };

  it("active providers: undefined/empty/active status, sorted", () => {
    expect(activeProviderPathsFromProvenanceConfig(cfg)).toEqual(["/a", "/e", "/nom", "/z"]);
    expect(activeProviderPathsFromProvenanceConfig({})).toEqual([]);
  });

  it("providerEntry returns the entry or undefined", () => {
    expect(providerEntryFromProvenanceConfig(cfg, "/z")).toBe(cfg.providers["/z"]);
    expect(providerEntryFromProvenanceConfig(cfg, "/nope")).toBeUndefined();
    expect(providerEntryFromProvenanceConfig({}, "/z")).toBeUndefined();
  });

  it("providers for method: active only, sorted", () => {
    expect(providerPathsForMethodFromProvenanceConfig(cfg, "m1")).toEqual(["/a", "/e", "/z"]);
    expect(providerPathsForMethodFromProvenanceConfig(cfg, "m2")).toEqual(["/z"]);
    expect(providerPathsForMethodFromProvenanceConfig(cfg, "none")).toEqual([]);
    expect(providerPathsForMethodFromProvenanceConfig({}, "m1")).toEqual([]);
  });

  it("methods for provider: copy of methods; empty when inactive/unknown/none", () => {
    const m = methodsForProviderPathFromProvenanceConfig(cfg, "/z");
    expect(m).toEqual(["m1", "m2"]);
    expect(m).not.toBe(cfg.providers["/z"].methods);
    expect(methodsForProviderPathFromProvenanceConfig(cfg, "/off")).toEqual([]);
    expect(methodsForProviderPathFromProvenanceConfig(cfg, "/nope")).toEqual([]);
    expect(methodsForProviderPathFromProvenanceConfig(cfg, "/nom")).toEqual([]);
    expect(methodsForProviderPathFromProvenanceConfig({}, "/z")).toEqual([]);
  });

  it("verification method keys are sorted", () => {
    expect(verificationMethodKeysFromProvenanceConfig(cfg)).toEqual(["alpha", "zeta"]);
    expect(verificationMethodKeysFromProvenanceConfig({})).toEqual([]);
  });
});
