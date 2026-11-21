/** Podstawione API dla testów interfejsu: odpowiedzi z e2e/fixtures, zapis wysłanych żądań. */
import { readFileSync } from "node:fs";
import path from "node:path";

import type { Page } from "@playwright/test";

const DIR = path.join(import.meta.dirname, "fixtures");

function fixture(name: string): unknown {
  return JSON.parse(readFileSync(path.join(DIR, `${name}.json`), "utf8"));
}

const ROUTES: [RegExp, string][] = [
  [/^\/api\/health/, "health"],
  [/^\/api\/stats/, "stats"],
  [/^\/api\/inbox/, "inbox"],
  [/^\/api\/findings\?.*asset_id/, "asset_findings"],
  [/^\/api\/findings/, "findings"],
  [/^\/api\/assets\/[^/]+\/details/, "asset_detail"],
  [/^\/api\/assets/, "assets"],
  [/^\/api\/iam\/permissions/, "iam_permissions"],
  [/^\/api\/iam\/roles/, "iam_roles"],
  [/^\/api\/iam\/users/, "iam_users"],
];

export interface Sent {
  method: string;
  path: string;
  body: unknown;
}

/** Uprawnienia ról z rules/roles.yaml (administrator ma wszystkie z pliku). */
function permissionsOf(role: string): string[] {
  const roles = fixture("iam_roles") as { name: string; permissions: string[] }[];
  const all = (fixture("iam_permissions") as { name: string }[]).map((p) => p.name);
  const found = roles.find((r) => r.name === role)?.permissions ?? [];
  return found.includes("*") ? all : found;
}

export function meFor(role: string) {
  return {
    username: role === "administrator" ? "admin" : role,
    display_name: role,
    email: `${role}@sentinel.example`,
    kind: "human",
    roles: [role],
    permissions: permissionsOf(role),
    mfa: true,
    client_id: "sentinel-admin",
  };
}

/** Loguje konto o danej roli (z TOTP) i podstawia API. Zwraca listę wysłanych zmian. */
export async function stubApi(
  page: Page,
  { role = "administrator" }: { role?: string } = {},
): Promise<Sent[]> {
  const sent: Sent[] = [];
  const me = meFor(role);
  await page.route("**/auth/**", (route) => route.abort());
  await page.route("**/api/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const where = url.pathname + url.search;
    const body = request.postDataJSON?.() ?? null;
    if (request.method() !== "GET") {
      sent.push({ method: request.method(), path: url.pathname, body });
    }
    if (url.pathname === "/api/me") return route.fulfill({ json: me });
    if (url.pathname === "/api/console/admin") return route.fulfill({ status: 204 });
    if (request.method() === "PUT" && url.pathname.startsWith("/api/iam/roles/")) {
      const name = decodeURIComponent(url.pathname.split("/").pop() ?? "");
      const input = body as { description: string; permissions: string[] };
      return route.fulfill({
        json: {
          name,
          label: name,
          kind: "human",
          builtin: false,
          grantable: true,
          created_by: me.username,
          updated_at: "2026-11-21T12:00:00",
          ...input,
        },
      });
    }
    if (request.method() === "DELETE" && url.pathname.startsWith("/api/iam/roles/")) {
      return route.fulfill({ status: 204 });
    }
    if (url.pathname.startsWith("/api/iam/users/") && request.method() !== "GET") {
      const users = fixture("iam_users") as { id: string }[];
      const user = users.find((u) => url.pathname.includes(u.id)) ?? users[0];
      return route.fulfill({ json: user });
    }
    const hit = ROUTES.find(([pattern]) => pattern.test(where));
    if (!hit) return route.fulfill({ json: [] });
    let data = fixture(hit[1]);
    if (hit[1] === "health") data = { ...(data as object), demo_mode: true };
    return route.fulfill({ json: data });
  });
  await page.addInitScript(() => {
    sessionStorage.setItem(
      `oidc.user:${location.origin}/auth/realms/sentinel:sentinel-admin`,
      JSON.stringify({
        access_token: "test",
        token_type: "Bearer",
        scope: "openid",
        profile: { sub: "t", preferred_username: "admin" },
        expires_at: Math.floor(Date.now() / 1000) + 3600,
      }),
    );
  });
  return sent;
}
