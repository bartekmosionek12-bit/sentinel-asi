import {
  Bot,
  Crosshair,
  FileText,
  FlaskConical,
  Inbox,
  LayoutDashboard,
  ListChecks,
  Network,
  Radar,
  Rss,
  ScrollText,
  Server,
  ShieldAlert,
  UserCog,
} from "lucide-react";

import type { NavGroup } from "@shared/components/AppShell";

export const NAV_GROUPS: NavGroup[] = [
  {
    title: "Przegląd",
    items: [
      { path: "/", label: "Pulpit", icon: LayoutDashboard },
      { path: "/skrzynka", label: "Skrzynka", icon: Inbox, permission: "reports:read" },
      {
        path: "/raporty",
        label: "Raporty",
        icon: FileText,
        permission: "reports:read",
        summary: "Raporty dwuwarstwowe: „W skrócie” dla kierownictwa i szczegóły techniczne dla zespołu IT.",
      },
      {
        path: "/mapa",
        label: "Mapa powierzchni ataku",
        icon: Network,
        stage: 10,
        summary:
          "Widok sieci i segmentów: zasoby pogrupowane według podsieci, kolorowane poziomem ryzyka.",
      },
    ],
  },
  {
    title: "Inwentarz i ryzyko",
    items: [
      { path: "/zasoby", label: "Zasoby", icon: Server },
      {
        path: "/zagrozenia",
        label: "Zagrożenia",
        icon: ShieldAlert,
        summary:
          "Lista zagrożeń przypisanych do konkretnych zasobów, ze statusem, właścicielem i rozbiciem oceny ryzyka.",
      },
      {
        path: "/feed",
        label: "Feed zagrożeń",
        icon: Rss,
        summary:
          "Nowe podatności z dzisiaj: te, które nas dotyczą, obok wszystkich opublikowanych.",
      },
      {
        path: "/weryfikacja",
        label: "Kolejka weryfikacji",
        icon: ListChecks,
        summary:
          "Dopasowania oprogramowania do bazy podatności o niskiej pewności, czekające na decyzję człowieka.",
      },
    ],
  },
  {
    title: "Kontrola",
    items: [
      { path: "/skany", label: "Skany", icon: Radar },
      { path: "/zakres", label: "Zakres skanowania", icon: Crosshair },
      { path: "/agent", label: "Agent AI", icon: Bot, end: true },
      { path: "/agent/test", label: "Test agenta", icon: FlaskConical },
      { path: "/audyt", label: "Dziennik audytu", icon: ScrollText, permission: "audit:read" },
      { path: "/role", label: "Role i użytkownicy", icon: UserCog, permission: "iam:read" },
    ],
  },
];
