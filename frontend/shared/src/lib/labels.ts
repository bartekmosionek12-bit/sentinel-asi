import type { Asset, AssetType, FindingStatus } from "@shared/lib/api";

export const STATUS_LABELS: Record<FindingStatus, string> = {
  open: "Otwarte",
  acknowledged: "Przyjęte do wiadomości",
  in_progress: "W trakcie naprawy",
  resolved: "Rozwiązane",
  accepted_risk: "Ryzyko zaakceptowane",
  false_positive: "Fałszywy alarm",
};

/** Typy urządzeń (Etap 6, ARCHITECTURE §7.1). */
export const DEVICE_TYPE_LABELS: Record<string, string> = {
  host: "Host",
  server: "Serwer",
  workstation: "Stacja robocza",
  laptop: "Laptop",
  network: "Urządzenie sieciowe",
  printer: "Drukarka",
  iot: "Urządzenie IoT",
  cloud: "Zasób w chmurze",
  ai_system: "System AI",
};

export const ASSET_TYPE_LABELS: Record<AssetType, string> = {
  host: "Host",
  domain: "Domena",
  ip: "Adres IP",
  service: "Usługa",
  application: "Aplikacja",
};

export const ASSET_STATUS_LABELS: Record<Asset["status"], string> = {
  active: "Aktywny",
  missing: "Nie odpowiada",
  retired: "Wycofany",
  shadow: "Shadow IT",
};

export const ASSET_STATUS_HINTS: Record<Asset["status"], string> = {
  active: "Zasób jest w inwentarzu i odpowiada",
  missing: "Zasób jest w inwentarzu, ale nie odpowiedział w ostatnim skanie",
  retired: "Zasób wycofany z użycia",
  shadow: "Host odpowiada w sieci, ale nikt nie dodał go do inwentarza",
};
