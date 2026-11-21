import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";

import { PageHeader, QueryState } from "@shared/components/page";
import { Badge } from "@shared/components/ui/badge";
import { Button } from "@shared/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@shared/components/ui/card";
import { Input, Select } from "@shared/components/ui/input";
import { Table, Td, Th } from "@shared/components/ui/table";
import { api, type AssetInput, type AssetType, type Exposure } from "@shared/lib/api";
import { useAuth } from "@shared/lib/auth-context";
import {
  ASSET_STATUS_HINTS,
  ASSET_STATUS_LABELS,
  ASSET_TYPE_LABELS,
  DEVICE_TYPE_LABELS,
} from "@shared/lib/labels";
import { formatDateTime } from "@shared/lib/utils";

const EMPTY: AssetInput = {
  type: "host",
  name: "",
  exposure: "internal",
  criticality: 3,
  owner: null,
};

export function Assets() {
  const queryClient = useQueryClient();
  const { can } = useAuth();
  const { data, isPending, error } = useQuery({
    queryKey: ["assets"],
    queryFn: api.assets,
  });
  const [form, setForm] = useState<AssetInput>(EMPTY);
  const create = useMutation({
    mutationFn: api.createAsset,
    onSuccess: () => {
      setForm(EMPTY);
      void queryClient.invalidateQueries({ queryKey: ["assets"] });
      void queryClient.invalidateQueries({ queryKey: ["audit-chain"] });
    },
  });

  const importCsv = useMutation({
    mutationFn: api.importAssets,
    onSuccess: () => void queryClient.invalidateQueries(),
  });

  function submit(event: FormEvent) {
    event.preventDefault();
    create.mutate({
      ...form,
      name: form.name.trim(),
      owner: form.owner?.trim() || null,
    });
  }

  return (
    <>
      <PageHeader
        title="Zasoby"
        description="Centralny inwentarz. Każda podatność, aktualizacja, wynik skanu i reguła zgodności jest przypisana do zasobu z tej listy."
      />

      {can("inventory:write") && (
      <>
      <Card className="mb-6">
        <CardHeader>
          <CardTitle>Dodaj zasób ręcznie</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={submit} className="grid items-end gap-3 md:grid-cols-6">
            <label className="text-xs font-medium md:col-span-2">
              Nazwa
              <Input
                className="mt-1"
                required
                maxLength={255}
                placeholder="np. web-01.firma.example"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
              />
            </label>
            <label className="text-xs font-medium">
              Typ
              <Select
                className="mt-1"
                value={form.type}
                onChange={(e) => setForm({ ...form, type: e.target.value as AssetType })}
              >
                {Object.entries(ASSET_TYPE_LABELS).map(([value, label]) => (
                  <option key={value} value={value}>
                    {label}
                  </option>
                ))}
              </Select>
            </label>
            <label className="text-xs font-medium">
              Ekspozycja
              <Select
                className="mt-1"
                value={form.exposure}
                onChange={(e) => setForm({ ...form, exposure: e.target.value as Exposure })}
              >
                <option value="internal">Sieć wewnętrzna</option>
                <option value="internet">Internet</option>
              </Select>
            </label>
            <label className="text-xs font-medium">
              Krytyczność (1–5)
              <Input
                className="mt-1"
                type="number"
                min={1}
                max={5}
                value={form.criticality}
                onChange={(e) => setForm({ ...form, criticality: Number(e.target.value) })}
              />
            </label>
            <Button type="submit" disabled={create.isPending}>
              {create.isPending ? "Dodawanie…" : "Dodaj"}
            </Button>
            <label className="text-xs font-medium md:col-span-2">
              Właściciel (opcjonalnie)
              <Input
                className="mt-1"
                maxLength={255}
                placeholder="np. zespół WWW"
                value={form.owner ?? ""}
                onChange={(e) => setForm({ ...form, owner: e.target.value })}
              />
            </label>
          </form>
          {create.error && (
            <p className="mt-3 text-sm text-red-700" role="alert">
              {create.error.message}
            </p>
          )}
        </CardContent>
      </Card>

      <Card className="mb-6">
        <CardHeader>
          <CardTitle>Import z pliku CSV</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="mb-3 text-sm text-muted-foreground">
            Kolumny: name, type, address, exposure, criticality, owner, tags (tagi rozdzielone
            średnikiem). Ponowny import aktualizuje istniejące zasoby zamiast je dublować.
          </p>
          <input
            type="file"
            accept=".csv,text/csv"
            aria-label="Plik CSV z zasobami"
            className="text-sm"
            onChange={(event) => {
              const file = event.target.files?.[0];
              if (file) void file.text().then((text) => importCsv.mutate(text));
              event.target.value = "";
            }}
          />
          {importCsv.data && (
            <div className="mt-3 text-sm" role="status">
              <p>
                Dodano: {importCsv.data.created}, zaktualizowano: {importCsv.data.updated}, bez
                zmian: {importCsv.data.unchanged}.
              </p>
              {importCsv.data.errors.length > 0 && (
                <ul className="mt-1 list-disc pl-5 text-red-700">
                  {importCsv.data.errors.map((line) => (
                    <li key={line}>{line}</li>
                  ))}
                </ul>
              )}
            </div>
          )}
          {importCsv.error && (
            <p className="mt-3 text-sm text-red-700" role="alert">
              {importCsv.error.message}
            </p>
          )}
        </CardContent>
      </Card>
      </>
      )}

      <Card>
        <QueryState
          isPending={isPending}
          error={error}
          empty={data?.items.length === 0}
          emptyText="Inwentarz jest pusty. Dodaj zasób powyżej, zaimportuj CSV albo uruchom skan."
        />
        {data && data.items.length > 0 && (
          <Table>
            <thead>
              <tr>
                <Th>Nazwa</Th>
                <Th>Typ</Th>
                <Th>Ekspozycja</Th>
                <Th>Krytyczność</Th>
                <Th>Właściciel</Th>
                <Th>Status</Th>
                <Th>Ostatnio widziany</Th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((asset) => (
                <tr key={asset.id}>
                  <Td className="font-medium break-all">
                    <Link className="underline-offset-2 hover:underline" to={`/zasoby/${asset.id}`}>
                      {asset.name}
                    </Link>
                  </Td>
                  <Td>
                    {ASSET_TYPE_LABELS[asset.type as AssetType] ??
                      DEVICE_TYPE_LABELS[asset.type] ??
                      asset.type}
                  </Td>
                  <Td>
                    <Badge variant={asset.exposure === "internet" ? "warn" : "neutral"}>
                      {asset.exposure === "internet" ? "Internet" : "Wewnętrzna"}
                    </Badge>
                  </Td>
                  <Td className="tabular-nums">{asset.criticality} / 5</Td>
                  <Td>{asset.owner ?? <span className="text-muted-foreground">brak</span>}</Td>
                  <Td>
                    <Badge
                      variant={asset.status === "active" ? "ok" : "warn"}
                      title={ASSET_STATUS_HINTS[asset.status]}
                    >
                      {ASSET_STATUS_LABELS[asset.status]}
                    </Badge>
                  </Td>
                  <Td className="whitespace-nowrap">{formatDateTime(asset.last_seen)}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
    </>
  );
}
