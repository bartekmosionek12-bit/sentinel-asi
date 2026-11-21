/** Raporty dwuwarstwowe: „W skrócie” dla kierownictwa i zwinięte szczegóły techniczne. */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, ChevronRight } from "lucide-react";
import { Fragment, useEffect, type ReactNode } from "react";
import { Link } from "react-router-dom";

import { QueryState } from "@shared/components/page";
import { RiskBadge } from "@shared/components/risk";
import { Badge } from "@shared/components/ui/badge";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@shared/components/ui/card";
import {
  api,
  type AiTestCaseRow,
  type GlossaryTerm,
  type Report,
  type ReportLight,
  type ReportListItem,
} from "@shared/lib/api";
import { useGlossary } from "@shared/lib/glossary";
import { cn, formatDateTime } from "@shared/lib/utils";

const LIGHT: Record<
  ReportLight,
  { label: string; dot: string; badge: string }
> = {
  red: {
    label: "Czerwone",
    dot: "bg-red-600",
    badge: "border-red-200 bg-red-50 text-red-800",
  },
  yellow: {
    label: "Żółte",
    dot: "bg-amber-500",
    badge: "border-amber-200 bg-amber-50 text-amber-900",
  },
  green: {
    label: "Zielone",
    dot: "bg-green-600",
    badge: "border-green-200 bg-green-50 text-green-800",
  },
};

const KIND: Record<ReportListItem["kind"], string> = {
  assessment: "Ocena stanu",
  zero_day: "Zero-day",
  digest: "Podsumowanie zbiorcze",
  ai_test: "Test agenta AI",
};

/** Światło raportu: zawsze z napisem, nie tylko kolorem. */
export function LightBadge({ light }: { light: ReportLight }) {
  const style = LIGHT[light];
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs font-semibold",
        style.badge,
      )}
    >
      <span className={cn("size-2 rounded-full", style.dot)} aria-hidden />
      {style.label}
    </span>
  );
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Tekst z podpowiedziami: każdy termin ze słownika ma definicję po najechaniu lub fokusie. */
export function GlossaryText({
  text,
  terms,
}: {
  text: string;
  terms: GlossaryTerm[];
}) {
  if (!terms.length) return <>{text}</>;
  const pattern = new RegExp(
    `(?<![\\p{L}\\d-])(${terms.map((t) => escapeRegExp(t.key)).join("|")})(?![\\p{L}\\d])`,
    "gu",
  );
  const byKey = new Map(terms.map((t) => [t.key, t]));
  const parts: ReactNode[] = [];
  let last = 0;
  for (const match of text.matchAll(pattern)) {
    const term = byKey.get(match[0]);
    if (!term || match.index === undefined) continue;
    parts.push(text.slice(last, match.index));
    parts.push(
      <abbr
        key={`${match.index}-${term.key}`}
        title={`${term.name}: ${term.definition}`}
        tabIndex={0}
        className="cursor-help underline decoration-dotted underline-offset-2"
      >
        {match[0]}
      </abbr>,
    );
    last = match.index + match[0].length;
  }
  parts.push(text.slice(last));
  return (
    <>
      {parts.map((part, index) => (
        <Fragment key={index}>{part}</Fragment>
      ))}
    </>
  );
}

/** Lista raportów z oznaczeniem nieprzeczytanych. */
export function ReportList({
  items,
  basePath,
  emptyText,
}: {
  items: ReportListItem[];
  basePath: string;
  emptyText: string;
}) {
  if (!items.length)
    return <p className="p-5 text-sm text-muted-foreground">{emptyText}</p>;
  return (
    <ul className="divide-y divide-border">
      {items.map((item) => (
        <li key={item.id}>
          <Link
            to={`${basePath}/${item.id}`}
            className="flex items-center gap-3 px-5 py-3 text-sm hover:bg-muted"
          >
            <span
              className={cn(
                "size-2 shrink-0 rounded-full",
                item.read ? "bg-transparent" : "bg-sky-600",
              )}
              aria-label={item.read ? undefined : "nieprzeczytany"}
            />
            <LightBadge light={item.light} />
            <span
              className={cn(
                "min-w-0 flex-1 truncate",
                !item.read && "font-semibold",
              )}
            >
              {item.title}
            </span>
            <Badge variant={item.kind === "zero_day" ? "danger" : "neutral"}>
              {KIND[item.kind]}
            </Badge>
            <span className="hidden text-xs text-muted-foreground sm:inline">
              {formatDateTime(item.created_at)}
            </span>
            <ChevronRight
              className="size-4 text-muted-foreground"
              aria-hidden
            />
          </Link>
        </li>
      ))}
    </ul>
  );
}

function SourceNote({ report }: { report: Report }) {
  if (report.summary_source === "model") {
    return (
      <p className="text-xs text-muted-foreground">
        Zdania sformułował model {report.summary_model} na podstawie faktów
        policzonych przez system; tekst przeszedł automatyczną kontrolę. Światło
        i fakty ustala kod.
      </p>
    );
  }
  const why: Record<Report["summary_validation"], string> = {
    none: "model jeszcze nie odpowiedział",
    rejected: "odpowiedź modelu nie przeszła kontroli",
    unavailable: "model jest niedostępny",
    passed: "",
  };
  return (
    <p className="text-xs text-muted-foreground">
      Wersja automatyczna z szablonu ({why[report.summary_validation]}). Światło
      i fakty ustala kod.
    </p>
  );
}

/** Pełny raport. Otwarcie oznacza go jako przeczytany przez zalogowaną osobę. */
export function ReportView({
  id,
  actions,
}: {
  id: string;
  actions?: ReactNode;
}) {
  const queryClient = useQueryClient();
  const report = useQuery({
    queryKey: ["report", id],
    queryFn: () => api.report(id),
  });
  const terms = useGlossary();
  const markRead = useMutation({
    mutationFn: () => api.markReportRead(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["inbox"] });
      void queryClient.invalidateQueries({ queryKey: ["reports"] });
    },
  });
  const unread = report.data && !report.data.read;
  const { mutate } = markRead;
  useEffect(() => {
    if (unread) mutate();
  }, [unread, mutate]);

  const data = report.data;
  return (
    <>
      <QueryState
        isPending={report.isPending}
        error={report.error}
        empty={false}
        emptyText=""
      />
      {data && (
        <div className="space-y-6">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="space-y-2">
              <div className="flex flex-wrap items-center gap-2">
                <LightBadge light={data.light} />
                <Badge
                  variant={data.kind === "zero_day" ? "danger" : "neutral"}
                >
                  {KIND[data.kind]}
                </Badge>
                <span className="text-xs text-muted-foreground">
                  {formatDateTime(data.created_at)}
                </span>
              </div>
              <h1 className="text-xl font-semibold">{data.title}</h1>
              <p className="text-sm text-muted-foreground">
                {data.light_reason}
              </p>
              {typeof (data.scope.freshness as { label?: unknown } | undefined)?.label ===
                "string" && (
                <p
                  className={
                    (data.scope.freshness as { stale?: boolean }).stale
                      ? "text-xs text-amber-800"
                      : "text-xs text-muted-foreground"
                  }
                >
                  „Aktualny obraz” z bazy, bez nowego skanowania.{" "}
                  {(data.scope.freshness as { label: string }).label}
                </p>
              )}
            </div>
            {actions}
          </div>

          <Card data-demo="report-summary">
            <CardHeader>
              <CardTitle>W skrócie</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <dl className="space-y-4">
                {data.summary.map((item) => (
                  <div key={item.key}>
                    <dt className="text-sm font-semibold">{item.question}</dt>
                    <dd className="mt-1 text-sm leading-relaxed">
                      <GlossaryText text={item.answer} terms={terms} />
                    </dd>
                  </div>
                ))}
              </dl>
              <SourceNote report={data} />
            </CardContent>
          </Card>

          {data.kind === "ai_test" ? (
            <AiTestCases rows={data.technical as unknown as AiTestCaseRow[]} />
          ) : (
            <details className="rounded-lg border border-border bg-card">
              <summary className="cursor-pointer px-5 py-3 text-sm font-semibold">
                Szczegóły techniczne ({data.technical.length})
              </summary>
              <div className="overflow-x-auto border-t border-border">
                <table className="w-full text-left text-sm">
                  <thead className="text-xs text-muted-foreground uppercase">
                    <tr>
                      <th className="px-4 py-2">Zasób</th>
                      <th className="px-4 py-2">Podatność</th>
                      <th className="px-4 py-2">Oprogramowanie</th>
                      <th className="px-4 py-2">Ryzyko</th>
                      <th className="px-4 py-2">Naprawa</th>
                      <th className="px-4 py-2">Termin</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {data.technical.map((row) => (
                      <tr key={row.finding_id}>
                        <td className="px-4 py-2 font-medium">{row.asset}</td>
                        <td className="px-4 py-2 whitespace-nowrap">
                          {row.cve_id ?? "—"}
                          {row.in_kev && (
                            <Badge variant="danger" className="ml-2">
                              KEV
                            </Badge>
                          )}
                        </td>
                        <td className="px-4 py-2">{row.product || "—"}</td>
                        <td className="px-4 py-2">
                          <RiskBadge
                            level={row.risk_level}
                            score={row.risk_score}
                          />
                        </td>
                        <td className="px-4 py-2">
                          {row.fixed_version
                            ? `wersja ${row.fixed_version} lub nowsza`
                            : "poprawka producenta"}
                        </td>
                        <td className="px-4 py-2 whitespace-nowrap tabular-nums">
                          {row.deadline}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </details>
          )}
        </div>
      )}
    </>
  );
}

/** Przypadki testu agenta: dwie oceny z ARCHITECTURE §23.2 (model i kod). */
function AiTestCases({ rows }: { rows: AiTestCaseRow[] }) {
  return (
    <details className="rounded-lg border border-border bg-card" open>
      <summary className="cursor-pointer px-5 py-3 text-sm font-semibold">
        Przypadki testu ({rows.length})
      </summary>
      <div className="overflow-x-auto border-t border-border">
        <table className="w-full text-left text-sm">
          <thead className="text-xs text-muted-foreground uppercase">
            <tr>
              <th className="px-4 py-2">Przypadek</th>
              <th className="px-4 py-2">Kategoria</th>
              <th className="px-4 py-2">Model odmówił</th>
              <th className="px-4 py-2">Kod zatrzymał</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {rows.map((row) => (
              <tr key={row.case_id}>
                <td className="px-4 py-2 font-medium">{row.title}</td>
                <td className="px-4 py-2">{row.category}</td>
                <td className="px-4 py-2">
                  <Badge variant={row.model_resisted ? "ok" : "warn"}>
                    {row.model_resisted ? "tak" : "nie"}
                  </Badge>
                </td>
                <td className="px-4 py-2">
                  <Badge variant={row.code_held ? "ok" : "danger"}>
                    {row.code_held ? "tak" : "nie"}
                  </Badge>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="border-t border-border px-5 py-3 text-xs text-muted-foreground">
        Test działa na atrapach narzędzi, bez ruchu w sieci. Transkrypcje są w
        konsoli operacyjnej.
      </p>
    </details>
  );
}

/** Baner nad treścią, gdy w skrzynce czeka nieprzeczytany raport zero-day. */
export function ZeroDayBanner({ basePath }: { basePath: string }) {
  const inbox = useQuery({
    queryKey: ["inbox"],
    queryFn: api.inbox,
    refetchInterval: 5_000,
  });
  const urgent = inbox.data?.items.find(
    (item) => item.kind === "zero_day" && !item.read,
  );
  if (!urgent) return null;
  return (
    <div
      data-demo="zero-day-banner"
      role="alert"
      className="flex flex-wrap items-center gap-3 border-b border-red-200 bg-red-50 px-4 py-3 text-sm text-red-900 md:px-8"
    >
      <AlertTriangle className="size-5 shrink-0 text-red-600" aria-hidden />
      <span className="flex-1">
        <strong className="font-semibold">
          Nowe zagrożenie typu zero-day.
        </strong>{" "}
        {urgent.title}: {urgent.light_reason.toLowerCase()}.
      </span>
      <Link
        to={`${basePath}/${urgent.id}`}
        className="rounded-md bg-red-600 px-3 py-1.5 font-medium text-white hover:bg-red-700"
      >
        Otwórz raport
      </Link>
    </div>
  );
}
