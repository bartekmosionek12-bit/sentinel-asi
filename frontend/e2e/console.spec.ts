/** Konsola zespołu IT: menu zależne od roli, role i użytkownicy, karta hosta (P1, #30). */
import { expect, test } from "@playwright/test";

import { stubApi } from "./stub";

const nav = (page: import("@playwright/test").Page) =>
  page.getByRole("navigation", { name: "Nawigacja główna" });

test("administrator widzi macierz ról i tworzy rolę własną bez iam:manage", async ({ page }) => {
  const sent = await stubApi(page);
  await page.goto("/admin/role");
  await expect(page.getByRole("heading", { name: "Role i użytkownicy" })).toBeVisible();
  for (const label of ["Administracja", "Dodawanie, usuwanie, modyfikacja", "Odczyt"]) {
    await expect(page.getByRole("columnheader", { name: label, exact: true })).toBeVisible();
  }
  await expect(page.getByRole("columnheader", { name: /audytor/ })).toBeVisible();

  await page.getByLabel("Nazwa (małe litery, cyfry, - i _)").fill("kierownik-zmiany");
  await page.getByLabel("Zacznij od roli").selectOption("viewer");
  await expect(page.locator("label", { hasText: "iam:manage" }).getByRole("checkbox")).toBeDisabled();
  await page.locator("label", { hasText: "findings:update" }).getByRole("checkbox").check();
  await page.getByRole("button", { name: "Zapisz rolę" }).click();
  await expect(page.getByRole("status")).toContainText("Zapisano rolę kierownik-zmiany");

  const put = sent.find((s) => s.method === "PUT");
  expect(put?.path).toBe("/api/iam/roles/kierownik-zmiany");
  const permissions = (put?.body as { permissions: string[] }).permissions;
  expect(permissions).toContain("findings:update");
  expect(permissions).toContain("inventory:read");
  expect(permissions).not.toContain("iam:manage");
});

test("administrator nadaje rolę z konsoli; Administracji nie da się nadać", async ({ page }) => {
  const sent = await stubApi(page);
  await page.goto("/admin/role");
  const select = page.getByLabel("Rola dla viewer");
  await expect(select.locator("option", { hasText: "Administracja" })).toHaveCount(0);
  await select.selectOption("editor");
  await page.getByRole("row", { name: /viewer/ }).getByRole("button", { name: "Nadaj" }).click();
  await expect.poll(() => sent.find((s) => s.method === "POST")?.body).toEqual({ role: "editor" });
  await expect(page.getByLabel("Rola dla sentinel-agent")).toHaveCount(0);
});

test("rola Odczyt: bez ról, audytu i formularzy zapisu", async ({ page }) => {
  await stubApi(page, { role: "viewer" });
  await page.goto("/admin/zasoby");
  await expect(page.getByRole("heading", { name: "Zasoby" })).toBeVisible();
  await expect(nav(page).getByRole("link", { name: "Role i użytkownicy" })).toHaveCount(0);
  await expect(nav(page).getByRole("link", { name: "Dziennik audytu" })).toHaveCount(0);
  await expect(nav(page).getByRole("link", { name: "Zgodność" })).toHaveCount(0);
  await expect(page.getByText("Dodaj zasób ręcznie")).toHaveCount(0);
  await expect(page.getByText("Import z pliku CSV")).toHaveCount(0);
});

test("karta hosta: usługi, zagrożenia i historia zmian", async ({ page }) => {
  await stubApi(page, { role: "modifier" });
  await page.goto("/admin/zasoby");
  await page.getByRole("link", { name: "web-01" }).click();
  await expect(page).toHaveURL(/\/admin\/zasoby\/2e017b46/);
  await expect(page.getByRole("heading", { name: "web-01" })).toBeVisible();
  await expect(page.getByRole("cell", { name: "Apache httpd", exact: true })).toBeVisible();
  await expect(page.getByText("CVE-2021-42013").first()).toBeVisible();
  await expect(page.getByText("Historia zmian")).toBeVisible();
  await expect(page.getByText("10.20.0.10")).toBeVisible();
});

test("rola Odczyt ma skrzynkę raportów w konsoli zespołu IT", async ({ page }) => {
  await stubApi(page, { role: "viewer" });
  await page.goto("/admin/skrzynka");
  await expect(page.getByRole("heading", { name: "Skrzynka" })).toBeVisible();
  await expect(page.getByText("Ocena stanu bezpieczeństwa (2026-11-21)")).toBeVisible();
});
