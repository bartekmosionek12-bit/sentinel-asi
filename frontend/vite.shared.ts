import path from "node:path";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig, type UserConfig } from "vite";

/**
 * Konfiguracja konsoli zespołu IT (katalog bazowy /admin/ w nginx). Kod wspólny
 * importuje przez alias `@shared`.
 *
 * `npm run dev:admin` wymaga działającego stosu (`docker compose up`): Keycloak i API są
 * dostępne przez nginx na :8080, a serwer deweloperski przekazuje do niego /api i /auth.
 */
export function sentinelApp(app: "admin", port: number): UserConfig {
  const root = path.resolve(import.meta.dirname, app);
  const stack = process.env.SENTINEL_URL ?? "http://localhost:8080";
  const apiUrl = process.env.SENTINEL_API_URL ?? stack;
  const authUrl = process.env.SENTINEL_AUTH_URL ?? stack;
  return defineConfig({
    root,
    base: `/${app}/`,
    publicDir: path.resolve(import.meta.dirname, "shared/public"),
    plugins: [react(), tailwindcss()],
    resolve: {
      alias: {
        "@shared": path.resolve(import.meta.dirname, "shared/src"),
        "@": path.resolve(root, "src"),
      },
    },
    build: { outDir: path.resolve(root, "dist"), emptyOutDir: true },
    server: { port, proxy: { "/api": apiUrl, "/auth": authUrl } },
  });
}
