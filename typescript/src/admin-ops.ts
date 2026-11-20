// Service-owned: idempotent admin operations (platform identity setup, tests).
//
// Casdoor quirks encoded here:
// - ids are always `owner/name`; applications, organizations and providers are owned by `admin`,
//   roles and users by the organization;
// - updates replace the WHOLE object: read it (`get-*`), change fields, send it back
//   (`update-*?id=owner/name`); a partial object resets every missing field;
// - objects read without admin rights come back with `***` in secret fields; sending those back
//   would store `***`, so the update is refused (`masked_object`);
// - user names cannot be e-mail addresses.

import { randomBytes } from "node:crypto";
import { NotFoundError, ValidationError } from "./core/index.js";
import type { CasdoorApi } from "./casdoor-api.js";
import { maskedObjectError } from "./casdoor-errors.js";
import { userNameFor } from "./pkce.js";
import { required } from "./user-flows.js";
import type {
  ApplicationInfo,
  CasdoorUser,
  EnsureApplicationInput,
  EnsureOrganizationInput,
  EnsureUserInput,
  RoleInfo,
  SmtpSettings,
} from "./types.js";

type Obj = Record<string, unknown>;

const MASK = "***";

/** A string field or `""`. */
function text(value: unknown): string {
  return typeof value === "string" ? value : typeof value === "number" ? String(value) : "";
}

/** Optional signal spread. */
function sig(signal?: AbortSignal): { signal?: AbortSignal } {
  return signal === undefined ? {} : { signal };
}

/** Reads one object (`get-<kind>?id=owner/name`); `undefined` when missing. */
async function getObject(
  api: CasdoorApi,
  op: string,
  kind: string,
  id: string,
  signal?: AbortSignal,
): Promise<Obj | undefined> {
  const env = await api.call<Obj | null>({
    operation: op,
    path: `/api/get-${kind}`,
    query: { id },
    auth: "admin",
    ...sig(signal),
  });
  return env.data ?? undefined;
}

/** Sends `add-<kind>`. */
async function addObject(
  api: CasdoorApi,
  op: string,
  kind: string,
  body: Obj,
  signal?: AbortSignal,
): Promise<void> {
  await api.call({
    operation: op,
    method: "POST",
    path: `/api/add-${kind}`,
    json: body,
    auth: "admin",
    ...sig(signal),
  });
}

/** Sends the whole object to `update-<kind>?id=…`, refusing masked objects. */
async function updateObject(
  api: CasdoorApi,
  op: string,
  kind: string,
  id: string,
  body: Obj,
  exempt: readonly string[],
  signal?: AbortSignal,
): Promise<void> {
  // Any field still masked would be stored as "***": refuse (users always mask `password`,
  // which Casdoor ignores on update).
  if (Object.entries(body).some(([k, v]) => v === MASK && !exempt.includes(k)))
    throw maskedObjectError(op, kind);
  await api.call({
    operation: op,
    method: "POST",
    path: `/api/update-${kind}`,
    query: { id },
    json: body,
    auth: "admin",
    ...sig(signal),
  });
}

/** True when `patch` would change `current`. */
function differs(current: Obj, patch: Obj): boolean {
  return Object.entries(patch).some(([k, v]) => JSON.stringify(current[k]) !== JSON.stringify(v));
}

/** Creates the organization unless it exists, then aligns password and MFA settings. */
export async function ensureOrganization(
  api: CasdoorApi,
  input: EnsureOrganizationInput,
  signal?: AbortSignal,
): Promise<{ name: string; created: boolean }> {
  const op = "ensureOrganization";
  required(op, { name: input.name });
  const id = `admin/${input.name}`;
  const patch: Obj = {
    displayName: input.displayName ?? input.name,
    passwordOptions: input.passwordOptions ?? ["AtLeast8"],
    mfaItems: input.enableTotp === false ? [] : [{ name: "app", rule: "Optional" }],
  };
  let current = await getObject(api, op, "organization", id, signal);
  let created = false;
  if (current === undefined) {
    await addObject(
      api,
      op,
      "organization",
      {
        owner: "admin",
        name: input.name,
        passwordType: "bcrypt",
        countryCodes: ["US"],
        languages: ["en"],
        defaultAvatar: "",
        enableSoftDeletion: false,
        isProfilePublic: false,
        ...patch,
      },
      signal,
    );
    created = true;
    current = await getObject(api, op, "organization", id, signal);
  }
  if (current !== undefined && differs(current, patch)) {
    await updateObject(api, op, "organization", id, { ...current, ...patch }, [], signal);
  }
  return { name: input.name, created };
}

/** Creates or aligns the OAuth application (exact redirect URIs, pinned client credentials). */
export async function ensureApplication(
  api: CasdoorApi,
  input: EnsureApplicationInput = {},
  signal?: AbortSignal,
): Promise<ApplicationInfo> {
  const op = "ensureApplication";
  const name = api.application(op, input.name);
  const organization = api.organization(op, input.organization);
  const id = `admin/${name}`;
  const signupItems = [
    { name: "ID", visible: false, required: true, prompted: false, rule: "Random" },
    { name: "Username", visible: true, required: true, prompted: false, rule: "None" },
    { name: "Display name", visible: true, required: false, prompted: false, rule: "None" },
    { name: "Password", visible: true, required: true, prompted: false, rule: "None" },
    { name: "Confirm password", visible: true, required: true, prompted: false, rule: "None" },
    {
      name: "Email",
      visible: true,
      required: true,
      prompted: false,
      rule: input.signUpEmailCode === true ? "Normal" : "No verification",
    },
    { name: "Agreement", visible: false, required: false, prompted: false, rule: "None" },
  ];
  const patch: Obj = {
    organization,
    displayName: input.displayName ?? name,
    redirectUris: input.redirectUris ?? [],
    grantTypes: input.grantTypes ?? ["authorization_code", "refresh_token"],
    enablePassword: true,
    enableSignUp: input.enableSignUp ?? true,
    signinMethods: [{ name: "Password", displayName: "Password", rule: "All" }],
    signupItems,
    tokenFormat: "JWT",
    cert: input.cert ?? "cert-built-in",
    expireInHours: input.expireInHours ?? 1,
    refreshExpireInHours: input.refreshExpireInHours ?? 168,
    failedSigninLimit: input.failedSigninLimit ?? 5,
    failedSigninFrozenTime: input.failedSigninFrozenTime ?? 15,
  };
  const clientId = input.clientId ?? api.config.clientId;
  const clientSecret = input.clientSecret ?? api.config.clientSecret?.reveal();
  if (clientId !== undefined) patch.clientId = clientId;
  if (clientSecret !== undefined) patch.clientSecret = clientSecret;

  let current = await getObject(api, op, "application", id, signal);
  let created = false;
  if (current === undefined) {
    await addObject(
      api,
      op,
      "application",
      {
        owner: "admin",
        name,
        clientId: clientId ?? randomBytes(10).toString("hex"),
        clientSecret: clientSecret ?? randomBytes(20).toString("hex"),
        ...patch,
      },
      signal,
    );
    created = true;
    current = await getObject(api, op, "application", id, signal);
    if (current === undefined)
      throw new ValidationError(`${op}: application ${name} was not created`);
  }
  const existingProviders = Array.isArray(current.providers) ? (current.providers as Obj[]) : [];
  const providers = [...existingProviders];
  for (const provider of input.providers ?? []) {
    if (!providers.some((p) => p.name === provider)) providers.push(providerRef(provider));
  }
  if (providers.length !== existingProviders.length) patch.providers = providers;
  if (differs(current, patch)) {
    const next = { ...current, ...patch };
    await updateObject(api, op, "application", id, next, [], signal);
    current = next;
  }
  const secret = current.clientSecret;
  if (secret === MASK) throw maskedObjectError(op, "application");
  return {
    name,
    organization,
    clientId: text(current.clientId),
    clientSecret: text(secret),
    redirectUris: Array.isArray(current.redirectUris) ? current.redirectUris.map(String) : [],
    created,
  };
}

/** Application provider entry for an e-mail provider. */
function providerRef(name: string): Obj {
  return {
    owner: "",
    name,
    canSignUp: true,
    canSignIn: true,
    canUnlink: true,
    prompted: false,
    rule: "All",
  };
}

/**
 * Creates or aligns an e-mail (SMTP) provider and lists it on the configured application when
 * that application exists.
 */
export async function ensureEmailProvider(
  api: CasdoorApi,
  smtp: SmtpSettings,
  signal?: AbortSignal,
): Promise<{ name: string; created: boolean }> {
  const op = "ensureEmailProvider";
  required(op, { host: smtp.host, from: smtp.from });
  if (!Number.isInteger(smtp.port) || smtp.port <= 0)
    throw new ValidationError(`${op}: port must be a positive integer`);
  const name = smtp.name ?? "provider-email";
  const id = `admin/${name}`;
  const patch: Obj = {
    displayName: name,
    category: "Email",
    type: "Default",
    host: smtp.host,
    port: smtp.port,
    disableSsl: smtp.disableSsl ?? false,
    // Casdoor: clientId/clientSecret = SMTP login, clientId2/clientSecret2 = from address/name.
    clientId: smtp.username ?? smtp.from,
    clientId2: smtp.from,
    clientSecret2: smtp.fromName ?? "Casdoor",
    title: smtp.title ?? "Verification code",
    content: smtp.content ?? "Your verification code is %s",
  };
  if (smtp.password !== undefined) patch.clientSecret = smtp.password;
  const current = await getObject(api, op, "provider", id, signal);
  let created = false;
  if (current === undefined) {
    await addObject(
      api,
      op,
      "provider",
      { owner: "admin", name, clientSecret: "", ...patch },
      signal,
    );
    created = true;
  } else if (differs(current, patch)) {
    await updateObject(api, op, "provider", id, { ...current, ...patch }, [], signal);
  }
  if (api.config.application !== undefined) {
    const appId = `admin/${api.config.application}`;
    const app = await getObject(api, op, "application", appId, signal);
    if (app !== undefined) {
      const providers = Array.isArray(app.providers) ? (app.providers as Obj[]) : [];
      if (!providers.some((p) => p.name === name)) {
        await updateObject(
          api,
          op,
          "application",
          appId,
          { ...app, providers: [...providers, providerRef(name)] },
          [],
          signal,
        );
      }
    }
  }
  return { name, created };
}

/** Creates every missing role of the organization. */
export async function ensureRoles(
  api: CasdoorApi,
  names: readonly string[],
  organization?: string,
  signal?: AbortSignal,
): Promise<RoleInfo[]> {
  const op = "ensureRoles";
  const owner = api.organization(op, organization);
  const out: RoleInfo[] = [];
  for (const name of names) {
    required(op, { role: name });
    const existing = await getObject(api, op, "role", `${owner}/${name}`, signal);
    if (existing === undefined) {
      await addObject(
        api,
        op,
        "role",
        {
          owner,
          name,
          displayName: name,
          users: [],
          groups: [],
          roles: [],
          domains: [],
          isEnabled: true,
        },
        signal,
      );
    }
    out.push({ name, created: existing === undefined });
  }
  return out;
}

/** Resolves `org/name`, a user name or an e-mail to the user object. */
async function findUser(
  api: CasdoorApi,
  op: string,
  owner: string,
  user: string,
  signal?: AbortSignal,
): Promise<Obj | undefined> {
  if (user.includes("@")) {
    const env = await api.call<Obj | null>({
      operation: op,
      path: "/api/get-user",
      query: { owner, email: user },
      auth: "admin",
      ...sig(signal),
    });
    return env.data ?? undefined;
  }
  const id = user.includes("/") ? user : `${owner}/${user}`;
  return getObject(api, op, "user", id, signal);
}

/** Maps a Casdoor user object. */
function toUser(owner: string, user: Obj, created: boolean): CasdoorUser {
  const name = text(user.name);
  const out: CasdoorUser = {
    userId: `${owner}/${name}`,
    organization: owner,
    name,
    emailVerified: user.emailVerified === true,
    isForbidden: user.isForbidden === true,
    created,
  };
  if (typeof user.id === "string" && user.id !== "") out.id = user.id;
  if (typeof user.email === "string" && user.email !== "") out.email = user.email;
  if (typeof user.displayName === "string" && user.displayName !== "")
    out.displayName = user.displayName;
  return out;
}

/** Creates or aligns a user (verified e-mail, password, display name) and assigns roles. */
export async function ensureUser(
  api: CasdoorApi,
  input: EnsureUserInput,
  signal?: AbortSignal,
): Promise<CasdoorUser> {
  const op = "ensureUser";
  required(op, { email: input.email });
  if (input.password !== undefined) required(op, { password: input.password });
  const owner = api.organization(op, input.organization);
  const name = userNameFor(input.email, input.username);
  const verified = input.emailVerified ?? true;
  let user = await findUser(api, op, owner, input.email, signal);
  let created = false;
  if (user === undefined) {
    if (input.password === undefined)
      throw new ValidationError(`${op}: password is required to create a user`);
    await addObject(
      api,
      op,
      "user",
      {
        owner,
        name,
        email: input.email,
        password: input.password,
        displayName: input.displayName ?? name,
        type: "normal-user",
        emailVerified: verified,
        ...(api.config.application === undefined
          ? {}
          : { signupApplication: api.config.application }),
      },
      signal,
    );
    created = true;
    user = await findUser(api, op, owner, `${owner}/${name}`, signal);
    if (user === undefined) throw new ValidationError(`${op}: user ${name} was not created`);
  } else {
    const patch: Obj = { emailVerified: verified };
    if (input.displayName !== undefined) patch.displayName = input.displayName;
    if (input.password !== undefined) patch.password = input.password;
    if (input.password !== undefined || differs(user, patch)) {
      const next = { ...user, ...patch };
      await updateObject(
        api,
        op,
        "user",
        `${owner}/${text(user.name)}`,
        next,
        ["password"],
        signal,
      );
      user = next;
    }
  }
  if (input.roles !== undefined && input.roles.length > 0) {
    await assignRoles(api, `${owner}/${text(user.name)}`, input.roles, owner, signal);
  }
  return toUser(owner, user, created);
}

/** Adds the user to each role (creating missing roles); full-object `update-role`. */
export async function assignRoles(
  api: CasdoorApi,
  user: string,
  roles: readonly string[],
  organization?: string,
  signal?: AbortSignal,
): Promise<void> {
  const op = "assignRoles";
  required(op, { user });
  const owner = api.organization(op, organization);
  const found = await findUser(api, op, owner, user, signal);
  if (found === undefined) throw new NotFoundError(`${op}: user not found`);
  const userId = `${text(found.owner) || owner}/${text(found.name)}`;
  await ensureRoles(api, roles, owner, signal);
  for (const role of roles) {
    const id = `${owner}/${role}`;
    const current = await getObject(api, op, "role", id, signal);
    if (current === undefined) continue;
    const users = Array.isArray(current.users) ? current.users.map(String) : [];
    if (users.includes(userId)) continue;
    await updateObject(api, op, "role", id, { ...current, users: [...users, userId] }, [], signal);
  }
}
