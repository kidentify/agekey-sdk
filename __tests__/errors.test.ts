import { describe, it, expect } from "vitest";
import {
  AgeKeyError,
  StateMismatchError,
  NonceMismatchError,
  AccessDeniedError,
  InvalidTokenError,
  InvalidRequestError,
  UnauthorizedClientError,
  ServerError,
  NetworkError,
  mapOidcError,
} from "../src/errors";

describe("error classes", () => {
  it("AgeKeyError exposes code, message, docsUrl and cause", () => {
    const cause = new Error("root");
    const e = new AgeKeyError("server_error", "msg", { docsUrl: "https://d", cause });
    expect(e).toBeInstanceOf(Error);
    expect(e.name).toBe("AgeKeyError");
    expect(e.code).toBe("server_error");
    expect(e.message).toBe("msg");
    expect(e.docsUrl).toBe("https://d");
    expect(e.cause).toBe(cause);
  });

  it("AgeKeyError without options has no docsUrl or cause", () => {
    const e = new AgeKeyError("server_error", "m");
    expect(e.docsUrl).toBeUndefined();
    expect(e.cause).toBeUndefined();
  });

  const cases: Array<[string, () => AgeKeyError, string, string, string | undefined]> = [
    ["StateMismatchError", () => new StateMismatchError(), "state_mismatch",
      "State parameter mismatch. The callback state doesn't match the original request. This could indicate a CSRF attack or an expired session.",
      "https://docs.agekey.org/troubleshooting#state-mismatch"],
    ["NonceMismatchError", () => new NonceMismatchError(), "nonce_mismatch",
      "Nonce mismatch. The ID token nonce doesn't match the original request. This could indicate a replay attack.",
      "https://docs.agekey.org/troubleshooting#nonce-mismatch"],
    ["AccessDeniedError", () => new AccessDeniedError(), "access_denied",
      "User denied the age verification request or closed the dialog.",
      "https://docs.agekey.org/guides/handling-denials"],
    ["InvalidTokenError", () => new InvalidTokenError(), "invalid_token",
      "Invalid or malformed ID token received.",
      "https://docs.agekey.org/guides/jwt-validation"],
    ["UnauthorizedClientError", () => new UnauthorizedClientError(), "unauthorized_client",
      "Client is not authorized to perform this request. Check your credentials.",
      "https://docs.agekey.org/troubleshooting#unauthorized-client"],
    ["ServerError", () => new ServerError(), "server_error",
      "AgeKey server error. Please try again later.",
      "https://docs.agekey.org/troubleshooting#server-errors"],
    ["NetworkError", () => new NetworkError(), "network_error",
      "Network error during API request.", undefined],
  ];

  for (const [name, make, code, message, docs] of cases) {
  }

  it("custom messages override defaults", () => {
    expect(new StateMismatchError("a").message).toBe("a");
    expect(new NonceMismatchError("b").message).toBe("b");
    expect(new InvalidTokenError("c").message).toBe("c");
    expect(new UnauthorizedClientError("d").message).toBe("d");
    expect(new ServerError("e").message).toBe("e");
    expect(new NetworkError("f").message).toBe("f");
  });

  it("AccessDeniedError carries errorDescription", () => {
    const e = new AccessDeniedError("nope");
    expect(e.errorDescription).toBe("nope");
    expect(e.message).toBe("nope");
    expect(new AccessDeniedError().errorDescription).toBeUndefined();
  });

  it("InvalidRequestError uses the message and api-reference docs", () => {
    const e = new InvalidRequestError("bad");
    expect(e.name).toBe("InvalidRequestError");
    expect(e.code).toBe("invalid_request");
    expect(e.message).toBe("bad");
    expect(e.docsUrl).toBe("https://docs.agekey.org/api-reference");
  });

  it("NetworkError keeps its cause", () => {
    const cause = new Error("x");
    expect(new NetworkError("m", cause).cause).toBe(cause);
  });
});

describe("mapOidcError", () => {
  it("maps access_denied", () => {
    const e = mapOidcError("access_denied", "desc");
    expect(e).toBeInstanceOf(AccessDeniedError);
    expect((e as AccessDeniedError).errorDescription).toBe("desc");
    const d = mapOidcError("access_denied");
    expect(d).toBeInstanceOf(AccessDeniedError);
    expect(d.message).toBe("User denied the age verification request or closed the dialog.");
  });

  it("maps invalid_request", () => {
    const e = mapOidcError("invalid_request", "d");
    expect(e).toBeInstanceOf(InvalidRequestError);
    expect(e.message).toBe("d");
    expect(mapOidcError("invalid_request").message).toBe("OIDC error: invalid_request");
  });

  it("maps unauthorized_client", () => {
    const e = mapOidcError("unauthorized_client", "d");
    expect(e).toBeInstanceOf(UnauthorizedClientError);
    expect(e.message).toBe("d");
    expect(mapOidcError("unauthorized_client").message).toBe("OIDC error: unauthorized_client");
  });

  it("maps server_error", () => {
    const e = mapOidcError("server_error", "d");
    expect(e).toBeInstanceOf(ServerError);
    expect(e.code).toBe("server_error");
    expect(e.message).toBe("d");
    expect(mapOidcError("server_error").message).toBe("OIDC error: server_error");
  });

  it("maps temporarily_unavailable to ServerError with prefix", () => {
    const e = mapOidcError("temporarily_unavailable", "d");
    expect(e).toBeInstanceOf(ServerError);
    expect(e.message).toBe("Service temporarily unavailable. d");
    expect(mapOidcError("temporarily_unavailable").message).toBe(
      "Service temporarily unavailable. OIDC error: temporarily_unavailable"
    );
  });

  it("maps unknown errors to a generic invalid_request AgeKeyError", () => {
    const e = mapOidcError("weird", "d");
    expect(e.constructor).toBe(AgeKeyError);
    expect(e.code).toBe("invalid_request");
    expect(e.message).toBe("d");
    expect(mapOidcError("weird").message).toBe("OIDC error: weird");
  });
});
