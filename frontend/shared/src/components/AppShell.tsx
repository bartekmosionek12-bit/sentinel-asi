/** Szkielet konsoli zespołu IT: menu boczne, nagłówek ze stanem systemu i zalogowanym użytkownikiem. */
import { useQuery } from "@tanstack/react-query";
import { ShieldCheck, type LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import { NavLink } from "react-router-dom";

import { Badge } from "@shared/components/ui/badge";
import { api } from "@shared/lib/api";
import { UserMenu } from "@shared/lib/auth";
import { useAuth } from "@shared/lib/auth-context";
import { cn } from "@shared/lib/utils";

export interface NavItem {
  path: string;
  label: string;
  icon: LucideIcon;
  /** Etap planu (P0–P12), w którym widok powstaje. Brak = działa już teraz. */
  stage?: number;
  summary?: string;
  /** Aktywny tylko dla dokładnie tej ścieżki (gdy pod nią są inne pozycje menu). */
  end?: boolean;
  /** Uprawnienie potrzebne, żeby pozycja była widoczna (API i tak sprawdza je osobno). */
  permission?: string;
}

export interface NavGroup {
  title: string;
  items: NavItem[];
}

function SystemStatus() {
  const { data, isError, isPending } = useQuery({
    queryKey: ["health"],
    queryFn: api.health,
    refetchInterval: 15_000,
  });
  if (isPending) return <Badge variant="neutral">Łączenie…</Badge>;
  if (isError || !data) return <Badge variant="danger">Brak połączenia z API</Badge>;
  return (
    <div className="flex flex-wrap items-center gap-2">
      {data.demo_mode && (
        <Badge
          variant="warn"
          title="Tryb demo: zasoby pochodzą z demo-lab, a wartości EPSS mogą być przykładowe."
        >
          Dane demonstracyjne
        </Badge>
      )}
      <Badge variant={data.status === "ok" ? "ok" : "warn"}>
        {data.status === "ok" ? "System działa" : "System działa częściowo"}
      </Badge>
    </div>
  );
}

function DemoDataNotice() {
  const { data } = useQuery({ queryKey: ["health"], queryFn: api.health, refetchInterval: 15_000 });
  if (!data?.demo_mode) return null;
  return (
    <p
      role="note"
      className="border-b border-amber-200 bg-amber-50 px-4 py-2 text-sm text-amber-900 md:px-8"
    >
      <strong className="font-semibold">Dane demonstracyjne.</strong> System działa w trybie demo
      (DEMO_MODE=true): zasoby pochodzą z demo-lab, a wartości EPSS z wbudowanego zestawu są
      przykładowe, nie rzeczywiste.
    </p>
  );
}

export function AppShell({
  navGroups,
  subtitle,
  footer,
  banner,
  headerExtra,
  children,
}: {
  navGroups: NavGroup[];
  subtitle: string;
  footer: string;
  /** Pilny komunikat nad treścią (np. raport zero-day w skrzynce). */
  banner?: ReactNode;
  /** Dodatkowe elementy w nagłówku . */
  headerExtra?: ReactNode;
  children: ReactNode;
}) {
  const { can } = useAuth();
  const visible = navGroups
    .map((group) => ({
      ...group,
      items: group.items.filter((item) => !item.permission || can(item.permission)),
    }))
    .filter((group) => group.items.length);
  return (
    <div className="flex min-h-screen">
      <aside className="hidden w-64 shrink-0 flex-col bg-sidebar text-sidebar-foreground md:flex">
        <div className="flex items-center gap-2 px-5 py-5 text-white">
          <ShieldCheck className="size-6 text-sky-400" aria-hidden />
          <span className="text-base font-semibold">Sentinel ASI</span>
        </div>
        <nav className="flex-1 space-y-6 px-3 pb-6" aria-label="Nawigacja główna">
          {visible.map((group) => (
            <div key={group.title}>
              <p className="px-2 pb-2 text-xs font-medium tracking-wide text-slate-500 uppercase">
                {group.title}
              </p>
              <ul className="space-y-1">
                {group.items.map(({ path, label, icon: Icon, end }) => (
                  <li key={path}>
                    <NavLink
                      to={path}
                      end={end ?? path === "/"}
                      className={({ isActive }) =>
                        cn(
                          "flex items-center gap-3 rounded-md px-2 py-2 text-sm transition-colors hover:bg-sidebar-active hover:text-white",
                          isActive && "bg-sidebar-active text-white",
                        )
                      }
                    >
                      <Icon className="size-4 shrink-0" aria-hidden />
                      {label}
                    </NavLink>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </nav>
        <p className="px-5 pb-4 text-xs text-slate-500">
          {footer}
        </p>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-between gap-4 border-b border-border bg-card px-4 py-3 md:px-8">
          <nav className="flex gap-1 overflow-x-auto md:hidden" aria-label="Nawigacja mobilna">
            {visible.flatMap((g) => g.items).map(({ path, label, icon: Icon, end }) => (
              <NavLink
                key={path}
                to={path}
                end={end ?? path === "/"}
                title={label}
                aria-label={label}
                className={({ isActive }) =>
                  cn("rounded-md p-2 text-muted-foreground", isActive && "bg-muted text-foreground")
                }
              >
                <Icon className="size-4" aria-hidden />
              </NavLink>
            ))}
          </nav>
          <span className="hidden text-sm text-muted-foreground md:block">{subtitle}</span>
          <div className="flex items-center gap-3">
            {headerExtra}
            <SystemStatus />
            <UserMenu />
          </div>
        </header>
        {banner}
        <DemoDataNotice />
        <main className="min-w-0 flex-1 px-4 py-6 md:px-8">{children}</main>
      </div>
    </div>
  );
}
