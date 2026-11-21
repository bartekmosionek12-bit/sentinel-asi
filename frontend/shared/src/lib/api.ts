/** Klient REST API. Typy odpowiadają schematom z backend/app/api/schemas.py. */

export type AssetType = "host" | "domain" | "ip" | "service" | "application";
/** Typy w odpowiedziach: także urządzenia z AD, MDM i CMDB (Etap 6). */
export type AnyAssetType =
  | AssetType
  | "workstation"
  | "laptop"
  | "server"
  | "network"
  | "printer"
  | "iot"
  | "cloud"
  | "ai_system";
export type Exposure = "internet" | "internal";

export interface Health {
  status: "ok" | "degraded";
  version: string;
  database: boolean;
  redis: boolean;
  demo_mode: boolean;
}

export interface Asset {
  id: string;
  type: AnyAssetType;
  name: string;
  exposure: Exposure;
  criticality: number;
  owner: string | null;
  tags: string[];
  status: "active" | "missing" | "retired" | "shadow";
  first_seen: string;
  last_seen: string;
}

export interface AssetInput {
  type: AssetType;
  name: string;
  exposure: Exposure;
  criticality: number;
  owner: string | null;
}

export interface AuditEntry {
  id: number;
  ts: string;
  actor: string;
  action: string;
  object_type: string | null;
  object_id: string | null;
  reason: string;
  inputs: Record<string, unknown>;
  hash: string;
  prev_hash: string;
}

export interface AuditChain {
  ok: boolean;
  entries: number;
  broken_at_id: number | null;
  detail: string | null;
}

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface Scope {
  allowed_domains: string[];
  allowed_cidrs: string[];
  denied_domains: string[];
  denied_cidrs: string[];
  default_rate_per_minute: number;
  demo_mode: boolean;
  demo_lab_cidr: string;
  demo_approval_expires_at: string | null;
}

export interface ScopeCheck {
  target: string;
  allowed: boolean;
  decision: string;
  reason: string;
  resolved_ip: string | null;
  approval_source: string | null;
}

export type RiskLevel = "krytyczny" | "wysoki" | "średni" | "niski";
export type FindingStatus =
  | "open"
  | "acknowledged"
  | "in_progress"
  | "resolved"
  | "accepted_risk"
  | "false_positive";

export interface AssetRef {
  id: string;
  name: string;
  type: AnyAssetType;
  exposure: Exposure;
  criticality: number;
  status: Asset["status"];
}

export interface VulnRef {
  cve_id: string;
  cvss_score: number | null;
  epss: number | null;
  in_kev: boolean;
  kev_due_date: string | null;
  has_public_exploit: boolean;
}

export interface Finding {
  id: string;
  type: string;
  status: FindingStatus;
  risk_score: number;
  risk_level: RiskLevel;
  summary: string;
  asset: AssetRef;
  vulnerability: VulnRef | null;
  product: string | null;
  version: string | null;
  port: number | null;
  fixed_version: string | null;
  assignee: string | null;
  first_seen: string;
  last_seen: string;
}

export interface RiskComponent {
  name: string;
  label: string;
  source: string;
  value: number;
  weight: number;
  contribution: number;
}

export interface FindingEvent {
  id: string;
  kind: string;
  before: Record<string, unknown>;
  after: Record<string, unknown>;
  actor: string;
  reason: string | null;
  created_at: string;
}

export interface FindingDetail extends Finding {
  description: string;
  references: string[];
  kev_required_action: string | null;
  risk_breakdown: {
    components: RiskComponent[];
    base_score: number;
    premiums: { rule: string; points: number; description: string }[];
    score: number;
    level: RiskLevel;
    summary: string;
    config_version: string;
  };
  evidence: Record<string, string | number | null>;
  events: FindingEvent[];
}

export interface FindingPatch {
  status?: FindingStatus;
  assignee?: string | null;
  reason?: string;
}

export interface Threat {
  cve_id: string;
  description: string;
  cvss_score: number | null;
  epss: number | null;
  in_kev: boolean;
  kev_date_added: string | null;
  has_public_exploit: boolean;
  published: string | null;
  first_ingested: string;
  is_new: boolean;
  affected_assets: {
    finding_id: string;
    asset_id: string;
    asset_name: string;
    risk_score: number;
    risk_level: RiskLevel;
  }[];
  max_risk: number | null;
}

export interface ThreatFeed {
  items: Threat[];
  total: number;
  total_ours: number;
  new_total: number;
  new_ours: number;
  new_since: string;
}

export interface FeedStatus {
  feed: string;
  mode: string | null;
  status: string;
  items_new: number;
  items_updated: number;
  error: string | null;
  finished_at: string | null;
}

export interface Software {
  id: string;
  product: string;
  version: string;
  port: number | null;
  protocol: string | null;
  raw_banner: string | null;
  cpe_vendor: string | null;
  cpe_product: string | null;
  match_status: string;
  match_method: string | null;
  match_confidence: number;
  source: string;
  last_seen: string;
}

export interface ReviewItem {
  id: string;
  cpe: string;
  score: number;
  method: string;
  reason: string;
  created_at: string;
  software: Software;
  asset: AssetRef;
}

export interface SignalItem {
  id: string;
  cve_id: string;
  source: string;
  vendor: string;
  product: string;
  score: number;
  method: string;
  reason: string;
  kev_due_date: string | null;
  created_at: string;
  software: Software;
  asset: AssetRef;
}

export interface ScanAction {
  id: string;
  scan_run_id: string;
  asset_id: string | null;
  target: string;
  tool: string;
  rule_name: string;
  intrusiveness: number;
  status: string;
  approval_source: string | null;
  scope_decision: string | null;
  params: Record<string, string>;
  reason: string;
  detail: string | null;
  created_at: string;
  finished_at: string | null;
}

export interface ScanRun {
  id: string;
  trigger: string;
  status: string;
  summary: Record<string, unknown>;
  started_at: string;
  finished_at: string | null;
  actions: ScanAction[];
}

export interface Task {
  task_id: string;
  detail: string;
}

export interface NotificationItem {
  id: string;
  finding_id: string | null;
  rule_name: string;
  channel: string;
  status: string;
  payload: {
    title?: string;
    lines?: string[];
    asset_name?: string;
    delivery?: string;
  };
  created_at: string;
}

export interface Stats {
  assets_total: number;
  assets_by_status: Record<string, number>;
  findings_active: number;
  findings_by_level: Partial<Record<RiskLevel, number>>;
  kev_active: number;
  review_queue: number;
  awaiting_approval: number;
  notifications_today: number;
  last_scan: ScanRun | null;
  feeds: FeedStatus[];
}

export interface ImportResult {
  created: number;
  updated: number;
  unchanged: number;
  errors: string[];
}

export type Audience = "technical" | "operational" | "executive";

export interface Explanation {
  finding_id: string;
  cve_id: string;
  audience: Audience;
  asset_context: string;
  text: string;
  source: "model" | "template";
  label: string;
  validation: "passed" | "rejected" | "none" | "unavailable";
  cached: boolean;
  model: string | null;
  prompt_version: string;
  created_at: string | null;
  problems: string[];
}

export interface ExplanationJob {
  job_id: string | null;
  detail: string;
  explanation: Explanation | null;
}

export interface LlmStatus {
  enabled: boolean;
  available: boolean;
  model: string;
  detail: string;
  external_enabled: boolean;
}

export type ExplanationEvent =
  | { type: "queued" | "start" | "retry" }
  | { type: "token"; text: string }
  | { type: "done"; source: string; validation: string; problems?: string[] }
  | { type: "error"; message: string };

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

/** Dostawca tokenu dostępu; ustawia go `AuthProvider` po zalogowaniu. */
type TokenSource = { token: () => string | null; onUnauthorized: () => void };
let tokenSource: TokenSource = { token: () => null, onUnauthorized: () => undefined };

export function setTokenSource(source: TokenSource): void {
  tokenSource = source;
}

function authHeaders(): Record<string, string> {
  const token = tokenSource.token();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...authHeaders(), ...init?.headers },
  });
  if (response.status === 401) tokenSource.onUnauthorized();
  if (!response.ok) {
    let message = `Błąd serwera (${response.status})`;
    try {
      const body: unknown = await response.json();
      if (body && typeof body === "object" && "detail" in body && typeof body.detail === "string") {
        message = body.detail;
      }
    } catch {
      // odpowiedź bez treści JSON: zostaje komunikat domyślny
    }
    throw new ApiError(response.status, message);
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

/** Pobranie pliku z autoryzacją (np. PDF raportu): fetch → blob → link tymczasowy. */
async function download(path: string, fallbackName: string): Promise<void> {
  const response = await fetch(`/api${path}`, { headers: { ...authHeaders() } });
  if (response.status === 401) tokenSource.onUnauthorized();
  if (!response.ok) throw new ApiError(response.status, `Błąd serwera (${response.status})`);
  const disposition = response.headers.get("Content-Disposition") ?? "";
  const name = /filename="([^"]+)"/.exec(disposition)?.[1] ?? fallbackName;
  const url = URL.createObjectURL(await response.blob());
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** Strumień SSE przez fetch: EventSource nie potrafi wysłać nagłówka Authorization. */
function streamEvents<E extends { type: string }>(
  path: string,
  onEvent: (event: E) => void,
  isTerminal: (event: E) => boolean,
): () => void {
  const controller = new AbortController();
  const lost = () =>
    onEvent({ type: "error", message: "Utracono połączenie ze strumieniem" } as unknown as E);
  void (async () => {
    try {
      const response = await fetch(`/api${path}`, {
        headers: { Accept: "text/event-stream", ...authHeaders() },
        signal: controller.signal,
      });
      if (!response.ok || !response.body) {
        if (response.status === 401) tokenSource.onUnauthorized();
        lost();
        return;
      }
      const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
      let buffer = "";
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += value;
        let boundary = buffer.indexOf("\n\n");
        while (boundary >= 0) {
          const chunk = buffer.slice(0, boundary);
          buffer = buffer.slice(boundary + 2);
          const data = chunk
            .split("\n")
            .filter((line) => line.startsWith("data:"))
            .map((line) => line.slice(5).trimStart())
            .join("\n");
          if (data) {
            const event = JSON.parse(data) as E;
            onEvent(event);
            if (isTerminal(event)) {
              controller.abort();
              return;
            }
          }
          boundary = buffer.indexOf("\n\n");
        }
      }
    } catch (error) {
      if (!controller.signal.aborted) {
        console.warn("SSE", error);
        lost();
      }
    }
  })();
  return () => controller.abort();
}

export type ReportLight = "red" | "yellow" | "green";

export interface ReportListItem {
  id: string;
  kind: "assessment" | "zero_day" | "digest" | "ai_test";
  title: string;
  light: ReportLight;
  light_reason: string;
  summary_source: "model" | "template";
  created_at: string;
  read: boolean;
}

export interface Inbox {
  unread: number;
  items: ReportListItem[];
}

export interface AiTestCaseRow {
  case_id: string;
  category: string;
  title: string;
  model_resisted: boolean;
  code_held: boolean;
}

export interface ReportTechnicalRow {
  asset: string;
  cve_id: string | null;
  product: string;
  fixed_version: string | null;
  risk_score: number;
  risk_level: RiskLevel;
  status: string;
  in_kev: boolean;
  cvss: number | null;
  epss: number | null;
  exposure: Exposure;
  criticality: number;
  deadline: string;
  finding_id: string;
}

export interface Report extends ReportListItem {
  scope: Record<string, unknown>;
  summary: { key: string; question: string; answer: string }[];
  summary_validation: "none" | "passed" | "rejected" | "unavailable";
  summary_model: string | null;
  summary_problems: string[];
  summary_updated_at: string | null;
  facts: Record<string, string[]>;
  /** Dla `kind === "ai_test"` wiersze mają postać `AiTestCaseRow`. */
  technical: ReportTechnicalRow[];
  created_by: string;
}

export interface GlossaryTerm {
  key: string;
  name: string;
  definition: string;
}

export interface Me {
  username: string;
  display_name: string;
  email: string;
  kind: "human" | "agent" | "system";
  roles: string[];
  permissions: string[];
  mfa: boolean;
  client_id: string;
}

// --- agent AI i test agenta (Etap 5, moduł 19) ---

export interface AgentCapability {
  id: string;
  version: number;
  tools: string[];
  targets: string[];
  max_level: number;
  windows: unknown[];
  max_calls_per_task: number;
  max_calls_per_target: number;
  active: boolean;
  note: string;
  created_by: string;
  created_at: string;
}

export interface AgentCapabilityInput {
  tools: string[];
  targets: string[];
  max_level: number;
  note: string;
}

export interface AgentConfig {
  id: string;
  model: string;
  prompt_version: string;
  capability_version: number;
  external_llm: boolean;
  state: "pending_test" | "active" | "forced" | "failed" | "superseded" | string;
  reason: string;
  forced_by: string | null;
  force_justification: string | null;
  created_by: string;
  created_at: string;
  activated_at: string | null;
}

export interface AgentTestRun {
  id: string;
  config_version_id: string | null;
  suite: "quick" | "full" | string;
  trigger: string;
  requested_by: string;
  status: string;
  model_passed: number;
  model_failed: number;
  code_passed: number;
  code_failed: number;
  passed: boolean | null;
  result_sha256: string | null;
  signature: string | null;
  created_at: string;
  finished_at: string | null;
  signature_valid: boolean | null;
}

export interface AgentVerdict {
  judge: string;
  layer: string;
  passed: boolean;
  detail: string;
  kind: string;
}

export interface AgentCaseResult {
  id: string;
  case_id: string;
  category: string;
  title: string;
  model_resisted: boolean;
  code_held: boolean;
  verdicts: AgentVerdict[];
  transcript: Record<string, unknown>;
  attempts: Record<string, unknown>[];
}

export interface AgentTestRunDetail extends AgentTestRun {
  public_key: string | null;
  cases: AgentCaseResult[];
}

export interface KillEffect {
  name: string;
  ok: boolean;
  detail: string;
}

export interface AgentStatus {
  killed: boolean;
  killed_by: string | null;
  killed_reason: string | null;
  killed_at: string | null;
  last_killed_at: string | null;
  effects: KillEffect[];
  scanner_stopped_at: string | null;
  scanner_stopped: number | null;
  certificate_gap: string;
  capability: AgentCapability | null;
  config: AgentConfig | null;
  pending: AgentConfig[];
  last_test: AgentTestRun | null;
}

export interface AgentStep {
  id: string;
  position: number;
  tool: string;
  target: string;
  level: number;
  params: Record<string, unknown>;
  reason: string;
  source: string;
  status: string;
  decision: string | null;
  decision_reason: string | null;
  result: Record<string, unknown>;
  started_at: string | null;
  finished_at: string | null;
}

export interface AgentTask {
  id: string;
  command: string;
  status: string;
  capability_version: number | null;
  config_version_id: string | null;
  plan_source: string | null;
  plan_model: string | null;
  plan_problems: string[];
  created_by: string;
  approved_by: string | null;
  approval_reason: string | null;
  approved_at: string | null;
  summary: Record<string, unknown>;
  created_at: string;
  finished_at: string | null;
  steps: AgentStep[];
}

export interface CredentialLease {
  id: string;
  task_id: string | null;
  step_id: string | null;
  kind: string;
  target: string;
  principal: string;
  serial: string;
  ttl_seconds: number;
  issued_by: string;
  issued_at: string;
  expires_at: string;
  revoked_at: string | null;
  revoked_by: string | null;
}


// --- świeżość danych i asystent Sentek ---

export interface Freshness {
  last_scan_at: string | null;
  last_feeds_at: string | null;
  age_hours: number | null;
  threshold_hours: number;
  stale: boolean;
  label: string;
}

/** Odpowiedź Sentka: tekst z danych, linki i ewentualna propozycja zadania dla agenta.
 *  Sentek niczego nie uruchamia: zadanie trafia do agenta, a plan zatwierdza człowiek. */
export interface AssistantAction {
  kind: "agent_task";
  command?: string;
  label?: string;
}

export interface AssistantAnswer {
  intent: string;
  source: "model" | "keywords";
  text: string[];
  links: { label: string; to: string }[];
  suggestions: string[];
  action: AssistantAction | null;
  pose: string;
  freshness: string | null;
  disclaimer: string;
}

// --- szczegóły zasobu (karta hosta) ---

export interface AssetHistory {
  id: string;
  change: string;
  diff: Record<string, unknown>;
  created_at: string;
}

export interface AssetDetail {
  asset: Asset;
  attributes: Record<string, unknown>;
  software: Software[];
  history: AssetHistory[];
  active_findings: number;
}

// --- role i użytkownicy (P1, docs/ROLES.md) ---

export interface IamPermission {
  name: string;
  description: string;
  mfa: boolean;
  /** Tylko w rolach z pliku (np. `iam:manage`); edytor ról go nie nadaje. */
  reserved: boolean;
}

export interface IamRole {
  name: string;
  label: string;
  description: string;
  kind: "human" | "agent" | "system";
  builtin: boolean;
  grantable: boolean;
  permissions: string[];
  created_by: string | null;
  updated_at: string | null;
}

export interface IamUser {
  id: string;
  username: string;
  display_name: string;
  kind: "human" | "agent" | "system";
  active: boolean;
  /** Role z tokenu Keycloak (nadawane w Keycloak, tu tylko do odczytu). */
  token_roles: string[];
  /** Role nadane w konsoli. */
  granted_roles: string[];
  last_seen_at: string | null;
}

export const api = {
  health: () => request<Health>("/health"),
  me: () => request<Me>("/me"),
  logout: () => request<void>("/auth/logout", { method: "POST" }),
  adminConsoleAccess: () => request<void>("/console/admin").then(() => true),
  assets: () => request<Page<Asset>>("/assets?limit=500"),
  createAsset: (input: AssetInput) =>
    request<Asset>("/assets", { method: "POST", body: JSON.stringify(input) }),
  auditLog: (limit: number, offset: number) =>
    request<Page<AuditEntry>>(`/audit-log?limit=${limit}&offset=${offset}`),
  auditChain: () => request<AuditChain>("/audit-log/verify"),
  importAssets: (csv: string) =>
    request<ImportResult>("/assets/import", {
      method: "POST",
      body: JSON.stringify({ csv }),
    }),
  stats: () => request<Stats>("/stats"),
  findings: (status: string) => request<Page<Finding>>(`/findings?status=${status}&limit=500`),
  assetDetails: (id: string) => request<AssetDetail>(`/assets/${id}/details`),
  assetFindings: (assetId: string) =>
    request<Page<Finding>>(`/findings?status=active&asset_id=${assetId}&limit=100`),
  finding: (id: string) => request<FindingDetail>(`/findings/${id}`),
  updateFinding: (id: string, patch: FindingPatch) =>
    request<FindingDetail>(`/findings/${id}`, {
      method: "PATCH",
      body: JSON.stringify(patch),
    }),
  llmStatus: () => request<LlmStatus>("/llm/status"),
  explanation: (findingId: string, audience: Audience) =>
    request<Explanation>(`/findings/${findingId}/explanation?audience=${audience}`),
  requestExplanation: (
    findingId: string,
    body: {
      audience: Audience;
      regenerate?: boolean;
      provider?: "local" | "external";
    },
  ) =>
    request<ExplanationJob>(`/findings/${findingId}/explanation`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  /** Strumień zdarzeń generowania (SSE). Zwraca funkcję zamykającą połączenie. */
  explanationEvents: (jobId: string, onEvent: (event: ExplanationEvent) => void) =>
    streamEvents<ExplanationEvent>(
      `/explanations/jobs/${jobId}/events`,
      onEvent,
      (event) => event.type === "done" || event.type === "error",
    ),
  threatFeed: (scope: "ours" | "all") => request<ThreatFeed>(`/threat-feed?scope=${scope}`),
  syncFeeds: () => request<Task>("/feeds/sync", { method: "POST" }),
  reviewQueue: () => request<ReviewItem[]>("/review-queue"),
  decideReview: (id: string, accept: boolean) =>
    request<{ match_status: string; findings_created: number }>(`/review-queue/${id}/decision`, {
      method: "POST",
      body: JSON.stringify({ accept }),
    }),
  signalQueue: () => request<SignalItem[]>("/signal-queue"),
  decideSignal: (id: string, accept: boolean) =>
    request<{ decision: string; findings_created: number }>(`/signal-queue/${id}/decision`, {
      method: "POST",
      body: JSON.stringify({ accept }),
    }),
  scans: () => request<ScanRun[]>("/scans?limit=5"),
  triggerScan: () => request<Task>("/scans", { method: "POST" }),
  scanActions: (status: string) => request<ScanAction[]>(`/scan-actions?status=${status}`),
  approveAction: (id: string, reason: string) =>
    request<Task>(`/scan-actions/${id}/approve`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    }),
  rejectAction: (id: string, reason: string) =>
    request<ScanAction>(`/scan-actions/${id}/reject`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    }),
  notifications: () => request<NotificationItem[]>("/notifications?limit=20"),
  reports: () => request<ReportListItem[]>("/reports"),
  report: (id: string) => request<Report>(`/reports/${id}`),
  inbox: () => request<Inbox>("/inbox"),
  downloadReportPdf: (id: string) => download(`/reports/${id}/pdf`, "raport.pdf"),
  markReportRead: (id: string) => request<void>(`/reports/${id}/read`, { method: "POST" }),
  freshness: () => request<Freshness>("/freshness"),
  assistant: (question: string) =>
    request<AssistantAnswer>("/assistant", {
      method: "POST",
      body: JSON.stringify({ question }),
    }),
  createReport: () => request<Report>("/reports", { method: "POST" }),
  requestReportSummary: (id: string) =>
    request<{ task_id: string }>(`/reports/${id}/summary`, { method: "POST" }),
  glossary: () => request<GlossaryTerm[]>("/glossary"),
  scope: () => request<Scope>("/scope"),
  checkScope: (target: string, intrusiveness: 1 | 2 | 3) =>
    request<ScopeCheck>("/scope/check", {
      method: "POST",
      body: JSON.stringify({ target, intrusiveness }),
    }),
  agentStatus: () => request<AgentStatus>("/agent/status"),
  agentCapabilities: () => request<AgentCapability[]>("/agent/capabilities"),
  createAgentCapability: (input: AgentCapabilityInput) =>
    request<AgentConfig>("/agent/capabilities", { method: "POST", body: JSON.stringify(input) }),
  killAgent: (reason: string) =>
    request<Record<string, unknown>>("/agent/kill", {
      method: "POST",
      body: JSON.stringify({ reason }),
    }),
  agentLeases: () => request<CredentialLease[]>("/agent/leases?limit=50"),
  agentTasks: () => request<AgentTask[]>("/agent/tasks?limit=20"),
  createAgentTask: (command: string) =>
    request<AgentTask>("/agent/tasks", { method: "POST", body: JSON.stringify({ command }) }),
  approveAgentTask: (id: string, reason: string, stepIds?: string[]) =>
    request<Task>(`/agent/tasks/${id}/approve`, {
      method: "POST",
      body: JSON.stringify({ reason, step_ids: stepIds }),
    }),
  rejectAgentTask: (id: string, reason: string) =>
    request<AgentTask>(`/agent/tasks/${id}/reject`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    }),
  agentConfigs: () => request<AgentConfig[]>("/agent/configs"),
  agentTests: () => request<AgentTestRun[]>("/agent/tests?limit=20"),
  agentTest: (id: string) => request<AgentTestRunDetail>(`/agent/tests/${id}`),
  runAgentTest: (suite: "quick" | "full") =>
    request<Task>("/agent/tests", { method: "POST", body: JSON.stringify({ suite }) }),
  forceAgentConfig: (id: string, justification: string) =>
    request<AgentConfig>(`/agent/configs/${id}/force`, {
      method: "POST",
      body: JSON.stringify({ justification }),
    }),
  iamPermissions: () => request<IamPermission[]>("/iam/permissions"),
  iamRoles: () => request<IamRole[]>("/iam/roles"),
  iamUsers: () => request<IamUser[]>("/iam/users"),
  saveRole: (name: string, input: { description: string; permissions: string[] }) =>
    request<IamRole>(`/iam/roles/${encodeURIComponent(name)}`, {
      method: "PUT",
      body: JSON.stringify(input),
    }),
  deleteRole: (name: string) =>
    request<void>(`/iam/roles/${encodeURIComponent(name)}`, { method: "DELETE" }),
  grantRole: (userId: string, role: string) =>
    request<IamUser>(`/iam/users/${userId}/roles`, {
      method: "POST",
      body: JSON.stringify({ role }),
    }),
  revokeRole: (userId: string, role: string) =>
    request<IamUser>(`/iam/users/${userId}/roles/${encodeURIComponent(role)}`, {
      method: "DELETE",
    }),
};
