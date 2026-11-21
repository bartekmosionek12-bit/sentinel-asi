/** Karta hosta: atrybuty, wykryte usługi, aktywne zagrożenia i historia zmian zasobu. */
import { useQuery } from "@tanstack/react-query";
import { ArrowLeft } from "lucide-react";
import { Link, useParams } from "react-router-dom";

import { QueryState } from "@shared/components/page";
import { KevBadge, RiskBadge } from "@shared/components/risk";
import { Badge } from "@shared/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@shared/components/ui/card";
import { Table, Td, Th } from "@shared/components/ui/table";
import { api, type AssetDetail as Detail, type AssetType } from "@shared/lib/api";
import { useAuth } from "@shared/lib/auth-context";
import {
  ASSET_STATUS_HINTS,
  ASSET_STATUS_LABELS,
  ASSET_TYPE_LABELS,
  DEVICE_TYPE_LABELS,
  STATUS_LABELS as FINDING_STATUS,
} from "@shared/lib/labels";
import { formatDateTime } from "@shared/lib/utils";

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="mt-0.5 text-sm break-all">{children}</dd>
    </div>
  );
}

function Summary({ data }: { data: Detail }) {
  const { asset } = data;
  const attributes = Object.entries(data.attributes).filter(
    ([, value]) => value !== null && value !== "",
  );
  return (
    <Card className="mb-6">
      <CardContent className="pt-5">
        <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Field label="Typ">
            {ASSET_TYPE_LABELS[asset.type as AssetType] ?? DEVICE_TYPE_LABELS[asset.type] ?? asset.type}
          </Field>
          <Field label="Status">
            <Badge variant={asset.status === "active" ? "ok" : "warn"} title={ASSET_STATUS_HINTS[asset.status]}>
              {ASSET_STATUS_LABELS[asset.status]}
            </Badge>
          </Field>
          <Field label="Ekspozycja">
            {asset.exposure === "internet" ? "Internet" : "Sieć wewnętrzna"}
          </Field>
          <Field label="Krytyczność">{asset.criticality} / 5</Field>
          <Field label="Właściciel">{asset.owner ?? "brak"}</Field>
          <Field label="Pierwszy raz widziany">{formatDateTime(asset.first_seen)}</Field>
          <Field label="Ostatnio widziany">{formatDateTime(asset.last_seen)}</Field>
          <Field label="Aktywne zagrożenia">{data.active_findings}</Field>
          {asset.tags.length > 0 && <Field label="Tagi">{asset.tags.join(", ")}</Field>}
          {attributes.map(([key, value]) => (
            <Field key={key} label={key}>
              {typeof value === "object" ? JSON.stringify(value) : String(value)}
            </Field>
          ))}
        </dl>
      </CardContent>
    </Card>
  );
}

function Services({ data }: { data: Detail }) {
  return (
    <Card className="mb-6">
      <CardHeader>
        <CardTitle>Wykryte usługi i oprogramowanie</CardTitle>
      </CardHeader>
      {data.software.length === 0 ? (
        <p className="px-5 pb-5 text-sm text-muted-foreground">Skan nie wykrył jeszcze usług.</p>
      ) : (
        <Table>
          <thead>
            <tr>
              <Th>Port</Th>
              <Th>Produkt</Th>
              <Th>Wersja</Th>
              <Th>Dopasowanie CPE</Th>
              <Th>Źródło</Th>
              <Th>Ostatnio widziane</Th>
            </tr>
          </thead>
          <tbody>
            {data.software.map((s) => (
              <tr key={s.id}>
                <Td className="tabular-nums">
                  {s.port ? `${s.port}/${s.protocol ?? "tcp"}` : "—"}
                </Td>
                <Td className="font-medium">{s.product}</Td>
                <Td>{s.version || "nieznana"}</Td>
                <Td>
                  {s.cpe_product ? `${s.cpe_vendor ?? "?"}:${s.cpe_product}` : "brak"}{" "}
                  <span className="text-xs text-muted-foreground">({s.match_status})</span>
                </Td>
                <Td>{s.source}</Td>
                <Td className="whitespace-nowrap">{formatDateTime(s.last_seen)}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </Card>
  );
}

function Findings({ assetId }: { assetId: string }) {
  const { can } = useAuth();
  const findings = useQuery({
    queryKey: ["asset-findings", assetId],
    queryFn: () => api.assetFindings(assetId),
    enabled: can("findings:read"),
  });
  if (!can("findings:read")) return null;
  return (
    <Card className="mb-6">
      <CardHeader>
        <CardTitle>Aktywne zagrożenia</CardTitle>
      </CardHeader>
      <QueryState
        isPending={findings.isPending}
        error={findings.error}
        empty={findings.data?.items.length === 0}
        emptyText="Brak aktywnych zagrożeń na tym zasobie."
      />
      {findings.data && findings.data.items.length > 0 && (
        <Table>
          <thead>
            <tr>
              <Th>Ryzyko</Th>
              <Th>Zagrożenie</Th>
              <Th>Usługa</Th>
              <Th>Status</Th>
            </tr>
          </thead>
          <tbody>
            {findings.data.items.map((f) => (
              <tr key={f.id}>
                <Td>
                  <RiskBadge level={f.risk_level} score={f.risk_score} />
                </Td>
                <Td>
                  <span className="font-medium">{f.vulnerability?.cve_id ?? f.type}</span>{" "}
                  {f.vulnerability?.in_kev && <KevBadge />}
                  <p className="text-xs text-muted-foreground">{f.summary}</p>
                </Td>
                <Td>
                  {[f.product, f.version].filter(Boolean).join(" ") || "—"}
                  {f.port ? ` (port ${f.port})` : ""}
                </Td>
                <Td>{FINDING_STATUS[f.status]}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </Card>
  );
}

function History({ data }: { data: Detail }) {
  if (data.history.length === 0) return null;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Historia zmian</CardTitle>
      </CardHeader>
      <ul className="divide-y divide-border px-5 pb-3 text-sm">
        {data.history.map((h) => (
          <li key={h.id} className="py-2">
            <span className="text-muted-foreground">{formatDateTime(h.created_at)}</span>{" "}
            <span className="font-medium">{h.change}</span>{" "}
            <code className="text-xs break-all">{JSON.stringify(h.diff)}</code>
          </li>
        ))}
      </ul>
    </Card>
  );
}

export function AssetDetail() {
  const { id = "" } = useParams();
  const detail = useQuery({ queryKey: ["asset", id], queryFn: () => api.assetDetails(id) });
  return (
    <>
      <Link
        to="/zasoby"
        className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="size-4" aria-hidden /> Wszystkie zasoby
      </Link>
      <h1 className="mb-4 text-xl font-semibold break-all">
        {detail.data?.asset.name ?? "Karta zasobu"}
      </h1>
      <QueryState
        isPending={detail.isPending}
        error={detail.error}
        empty={false}
        emptyText=""
      />
      {detail.data && (
        <>
          <Summary data={detail.data} />
          <Services data={detail.data} />
          <Findings assetId={id} />
          <History data={detail.data} />
        </>
      )}
    </>
  );
}
