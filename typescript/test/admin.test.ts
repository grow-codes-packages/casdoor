import { afterEach, describe, expect, it } from "vitest";
import {
  CasdoorClient,
  CasdoorReason,
  NotFoundError,
  ValidationError,
  casdoorReason,
} from "../src/index.js";
import { ADMIN_PASSWORD, type FakeCasdoor, startFakeCasdoor } from "./helpers/fake-casdoor.js";
import { type MockServer, startServer } from "./helpers/server.js";

const fakes: FakeCasdoor[] = [];
const servers: MockServer[] = [];
const clients: CasdoorClient[] = [];
afterEach(async () => {
  await Promise.all(clients.splice(0).map((c) => c.close()));
  await Promise.all(fakes.splice(0).map((f) => f.close()));
  await Promise.all(servers.splice(0).map((s) => s.close()));
});

async function setup(
  extra: Record<string, unknown> = {},
): Promise<{ f: FakeCasdoor; c: CasdoorClient }> {
  const f = await startFakeCasdoor();
  fakes.push(f);
  const c = new CasdoorClient({
    url: f.url,
    adminPassword: ADMIN_PASSWORD,
    organization: "shop",
    application: "app-shop",
    clientId: "shop-client",
    clientSecret: "shop-secret-0123456789",
    retry: { maxRetries: 0 },
    ...extra,
  });
  clients.push(c);
  return { f, c };
}

describe("admin operations", () => {
  it("sets up an organization, application, provider, roles and users idempotently", async () => {
    const { f, c } = await setup();
    expect(await c.ensureOrganization({ name: "shop", displayName: "Shop" })).toEqual({
      name: "shop",
      created: true,
    });
    expect((await c.ensureOrganization({ name: "shop", displayName: "Shop" })).created).toBe(false);
    await c.ensureOrganization({ name: "shop", enableTotp: false, passwordOptions: ["AtLeast12"] });
    expect(f.orgs.get("admin/shop")?.passwordOptions).toEqual(["AtLeast12"]);

    const app = await c.ensureApplication({
      redirectUris: ["https://shop.test/cb"],
      providers: ["provider-mail"],
    });
    expect(app).toMatchObject({
      name: "app-shop",
      clientId: "shop-client",
      clientSecret: "shop-secret-0123456789",
      created: true,
    });
    const again = await c.ensureApplication({
      redirectUris: ["https://shop.test/cb", "https://b.test/cb"],
      signUpEmailCode: true,
    });
    expect(again.created).toBe(false);
    expect(again.redirectUris).toEqual(["https://shop.test/cb", "https://b.test/cb"]);
    const stored = f.apps.get("admin/app-shop") ?? {};
    // full object kept: fields set at creation survive the update
    expect(stored.tokenFormat).toBe("JWT");
    expect(stored.enablePassword).toBe(true);
    expect((stored.providers as unknown[]).length).toBe(1);

    expect(
      await c.ensureEmailProvider({
        name: "provider-mail",
        host: "mailpit",
        port: 1025,
        from: "no-reply@shop.test",
        disableSsl: true,
      }),
    ).toEqual({
      name: "provider-mail",
      created: true,
    });
    const p = await c.ensureEmailProvider({
      name: "provider-mail",
      host: "mailpit2",
      port: 1025,
      from: "no-reply@shop.test",
      password: "smtp-pw",
    });
    expect(p.created).toBe(false);
    expect(f.providers.get("admin/provider-mail")?.host).toBe("mailpit2");
    expect(f.providers.get("admin/provider-mail")?.clientId2).toBe("no-reply@shop.test");
    await c.ensureEmailProvider({ name: "provider-2", host: "h", port: 25, from: "a@b.c" });
    expect(
      (f.apps.get("admin/app-shop")?.providers as { name: string }[]).map((x) => x.name),
    ).toEqual(["provider-mail", "provider-2"]);

    expect(await c.ensureRoles(["buyer", "seller"])).toEqual([
      { name: "buyer", created: true },
      { name: "seller", created: true },
    ]);
    expect((await c.ensureRoles(["buyer"]))[0]?.created).toBe(false);

    const u = await c.ensureUser({
      email: "buyer@shop.test",
      password: "Password-123",
      roles: ["buyer"],
    });
    expect(u).toMatchObject({ userId: "shop/buyer", emailVerified: true, created: true });
    expect(f.roles.get("shop/buyer")?.users).toEqual(["shop/buyer"]);
    const u2 = await c.ensureUser({
      email: "buyer@shop.test",
      password: "Password-456",
      displayName: "B",
      roles: ["buyer", "admin"],
    });
    expect(u2.created).toBe(false);
    expect(u2.displayName).toBe("B");
    expect(f.users.get("shop/buyer")?.password).toBe("Password-456");
    expect(f.roles.get("shop/buyer")?.users).toEqual(["shop/buyer"]);
    expect(f.roles.get("shop/admin")?.users).toEqual(["shop/buyer"]);
    // unchanged user: no update needed
    expect((await c.ensureUser({ email: "buyer@shop.test" })).created).toBe(false);

    await c.assignRoles("buyer@shop.test", ["seller"]);
    await c.assignRoles("shop/buyer", ["seller"]);
    expect(f.roles.get("shop/seller")?.users).toEqual(["shop/buyer"]);
    await expect(c.assignRoles("nobody", ["seller"])).rejects.toBeInstanceOf(NotFoundError);
  });

  it("works with client credentials (Basic) instead of the admin password", async () => {
    const { f, c } = await setup({
      adminPassword: undefined,
      organization: "acme",
      application: "app-acme",
      clientId: "cid",
      clientSecret: "csecret",
    });
    const app = await c.ensureApplication({ redirectUris: ["https://app.test/cb"] });
    expect(app.clientSecret).toBe("csecret");
    expect(f.calls).not.toContain("/api/login");
  });

  it("generates credentials when none are configured", async () => {
    const { c } = await setup({ clientId: undefined, clientSecret: undefined });
    const app = await c.ensureApplication({ name: "app-new", organization: "shop" });
    expect(app.clientId).toMatch(/^[0-9a-f]{20}$/);
    expect(app.clientSecret).toMatch(/^[0-9a-f]{40}$/);
  });

  it("refuses to write back masked objects", async () => {
    const s = await startServer((req) => {
      if (req.url.startsWith("/api/login"))
        return { headers: { "set-cookie": "casdoor_session_id=x" }, body: { status: "ok" } };
      if (req.url.startsWith("/api/get-application"))
        return {
          body: {
            status: "ok",
            data: {
              owner: "admin",
              name: "a",
              clientId: "c",
              clientSecret: "***",
              cert: "***",
              samlReplyUrl: "***",
            },
          },
        };
      return { body: { status: "ok" } };
    });
    servers.push(s);
    const c = new CasdoorClient({
      url: s.url,
      adminPassword: "pw-123456",
      organization: "o",
      application: "a",
      retry: { maxRetries: 0 },
    });
    clients.push(c);
    const err = await c.ensureApplication({ redirectUris: ["x"] }).catch((e: unknown) => e);
    expect(casdoorReason(err)).toBe(CasdoorReason.MaskedObject);
  });

  it("reports objects that were not created and invalid input", async () => {
    const s = await startServer((req) => {
      if (req.url.startsWith("/api/login"))
        return { headers: { "set-cookie": "casdoor_session_id=x" }, body: { status: "ok" } };
      return { body: { status: "ok", data: null } };
    });
    servers.push(s);
    const c = new CasdoorClient({
      url: s.url,
      adminPassword: "pw-123456",
      organization: "o",
      application: "a",
      retry: { maxRetries: 0 },
    });
    clients.push(c);
    await expect(c.ensureApplication()).rejects.toThrow(/was not created/);
    await expect(c.ensureUser({ email: "a@b.c", password: "Password-1" })).rejects.toThrow(
      /was not created/,
    );
    await expect(c.ensureUser({ email: "a@b.c" })).rejects.toThrow(/password is required/);
    await expect(c.ensureEmailProvider({ host: "h", port: 0, from: "f" })).rejects.toBeInstanceOf(
      ValidationError,
    );
    await expect(c.ensureRoles([""])).rejects.toBeInstanceOf(ValidationError);
    expect(await c.ensureOrganization({ name: "o" })).toEqual({ name: "o", created: true });
  });
});
