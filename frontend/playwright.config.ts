/**
 * Testy interfejsu konsoli zespołu IT (Playwright). API jest podstawione syntetycznymi danymi
 * z e2e/fixtures, więc testy sprawdzają interfejs: menu zależne od roli, stronę ról i kartę
 * hosta. Uprawnienia egzekwuje backend (pytest: test_iam, test_roles_matrix), a całą ścieżkę
 * na żywo job e2e-demo w CI (scripts/check_demo.py).
 */
import { defineConfig } from "@playwright/test";

const browser = process.env.PLAYWRIGHT_CHROMIUM
  ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM }
  : {};

export default defineConfig({
  testDir: "e2e",
  timeout: 30_000,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL: "http://localhost:5173",
    viewport: { width: 1440, height: 900 },
    trace: "off",
    launchOptions: browser,
  },
  webServer: {
    command: "npx vite --config admin/vite.config.ts --port 5173 --strictPort",
    url: "http://localhost:5173/admin/",
    reuseExistingServer: !process.env.CI,
  },
});
