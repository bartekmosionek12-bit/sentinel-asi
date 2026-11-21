/** Role i użytkownicy (P1, brief pkt 12–13): macierz uprawnień, edytor ról, nadawanie ról. */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Lock } from "lucide-react";
import { useState, type FormEvent } from "react";

import { PageHeader, QueryState } from "@shared/components/page";
import { Badge } from "@shared/components/ui/badge";
import { Button } from "@shared/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@shared/components/ui/card";
import { Input, Select } from "@shared/components/ui/input";
import { Table, Td, Th } from "@shared/components/ui/table";
import { api, type IamPermission, type IamRole, type IamUser } from "@shared/lib/api";
import { useAuth } from "@shared/lib/auth-context";
import { formatDateTime } from "@shared/lib/utils";

const NAME_PATTERN = "[a-z][a-z0-9_\\-]{2,39}";

function useIam() {
  const roles = useQuery({ queryKey: ["iam", "roles"], queryFn: api.iamRoles });
  const permissions = useQuery({ queryKey: ["iam", "permissions"], queryFn: api.iamPermissions });
  const users = useQuery({ queryKey: ["iam", "users"], queryFn: api.iamUsers });
  return { roles, permissions, users };
}

function has(role: IamRole, permission: string): boolean {
  return role.permissions.includes("*") || role.permissions.includes(permission);
}

/** Macierz rola × uprawnienie. Ten sam obraz co w docs/ROLES.md, ale z rolami własnymi. */
function Matrix({ roles, permissions }: { roles: IamRole[]; permissions: IamPermission[] }) {
  const human = roles.filter((r) => r.kind === "human");
  return (
    <Card className="mb-6">
      <CardHeader>
        <CardTitle>Macierz uprawnień</CardTitle>
        <CardDescription>
          Role wbudowane pochodzą z pliku rules/roles.yaml i zmieniają się tylko przez przegląd
          w PR. Uprawnienia oznaczone MFA działają wyłącznie po logowaniu z drugim składnikiem.
          Role techniczne (agent, system) nie mają uprawnień: agent dostaje tylko zdolności
          nadane przez administratora.
        </CardDescription>
      </CardHeader>
      <div className="overflow-x-auto">
        <Table>
          <thead>
            <tr>
              <Th>Uprawnienie</Th>
              {human.map((role) => (
                <Th key={role.name} className="text-center">
                  <span title={role.description}>{role.label}</span>
                  {!role.builtin && (
                    <span className="block text-xs font-normal text-muted-foreground">własna</span>
                  )}
                </Th>
              ))}
            </tr>
          </thead>
          <tbody>
            {permissions.map((p) => (
              <tr key={p.name}>
                <Td>
                  <code className="text-xs">{p.name}</code>{" "}
                  {p.mfa && <Badge variant="info">MFA</Badge>}{" "}
                  {p.reserved && (
                    <Lock
                      className="inline size-3 text-muted-foreground"
                      aria-label="tylko w rolach z pliku"
                    />
                  )}
                  <p className="text-xs text-muted-foreground">{p.description}</p>
                </Td>
                {human.map((role) => (
                  <Td key={role.name} className="text-center">
                    {has(role, p.name) ? (
                      <Check className="mx-auto size-4 text-green-700" aria-label="tak" />
                    ) : (
                      <span className="text-muted-foreground" aria-label="nie">
                        ·
                      </span>
                    )}
                  </Td>
                ))}
              </tr>
            ))}
          </tbody>
        </Table>
      </div>
    </Card>
  );
}

/** Rola własna: dowolny podzbiór uprawnień z pliku, bez zarezerwowanych (`iam:manage`). */
function RoleEditor({
  roles,
  permissions,
}: {
  roles: IamRole[];
  permissions: IamPermission[];
}) {
  const queryClient = useQueryClient();
  const custom = roles.filter((r) => !r.builtin);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [selected, setSelected] = useState<string[]>([]);
  const refresh = () => void queryClient.invalidateQueries({ queryKey: ["iam"] });
  const save = useMutation({
    mutationFn: () => api.saveRole(name.trim(), { description: description.trim(), permissions: selected }),
    onSuccess: refresh,
  });
  const remove = useMutation({ mutationFn: api.deleteRole, onSuccess: refresh });

  function edit(role: IamRole) {
    setName(role.name);
    setDescription(role.description);
    setSelected(role.permissions);
  }

  function copyFrom(roleName: string) {
    const role = roles.find((r) => r.name === roleName);
    if (!role) return;
    const all = role.permissions.includes("*") ? permissions.map((p) => p.name) : role.permissions;
    const reserved = new Set(permissions.filter((p) => p.reserved).map((p) => p.name));
    setSelected(all.filter((p) => !reserved.has(p)));
  }

  function submit(event: FormEvent) {
    event.preventDefault();
    save.mutate();
  }

  return (
    <Card className="mb-6">
      <CardHeader>
        <CardTitle>Edytor ról</CardTitle>
        <CardDescription>
          Rola własna składa się z uprawnień z pliku. Nie może zawierać zarządzania rolami
          (iam:manage), więc nikt nie nada sobie administracji. Każda zmiana trafia do dziennika
          audytu.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {custom.length > 0 && (
          <ul className="mb-4 flex flex-wrap gap-2">
            {custom.map((role) => (
              <li key={role.name} className="flex items-center gap-1 rounded-md border px-2 py-1 text-sm">
                <button type="button" className="underline-offset-2 hover:underline" onClick={() => edit(role)}>
                  {role.name}
                </button>
                <span className="text-xs text-muted-foreground">({role.permissions.length})</span>
                <Button
                  variant="ghost"
                  size="sm"
                  aria-label={`Usuń rolę ${role.name}`}
                  disabled={remove.isPending}
                  onClick={() => remove.mutate(role.name)}
                >
                  Usuń
                </Button>
              </li>
            ))}
          </ul>
        )}
        <form onSubmit={submit} className="space-y-3">
          <div className="grid gap-3 md:grid-cols-3">
            <label className="text-xs font-medium">
              Nazwa (małe litery, cyfry, - i _)
              <Input
                className="mt-1"
                required
                pattern={NAME_PATTERN}
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="np. audytor"
              />
            </label>
            <label className="text-xs font-medium">
              Opis
              <Input
                className="mt-1"
                maxLength={500}
                value={description}
                onChange={(e) => setDescription(e.target.value)}
              />
            </label>
            <label className="text-xs font-medium">
              Zacznij od roli
              <Select className="mt-1" value="" onChange={(e) => copyFrom(e.target.value)}>
                <option value="">wybierz…</option>
                {roles
                  .filter((r) => r.kind === "human")
                  .map((r) => (
                    <option key={r.name} value={r.name}>
                      {r.label}
                    </option>
                  ))}
              </Select>
            </label>
          </div>
          <fieldset className="grid gap-x-4 gap-y-1 sm:grid-cols-2 lg:grid-cols-3">
            <legend className="mb-1 text-xs font-medium">Uprawnienia</legend>
            {permissions.map((p) => (
              <label
                key={p.name}
                className="flex items-center gap-2 text-sm"
                title={p.reserved ? "Tylko w rolach z pliku" : p.description}
              >
                <input
                  type="checkbox"
                  className="size-4"
                  disabled={p.reserved}
                  checked={selected.includes(p.name)}
                  onChange={(e) =>
                    setSelected(
                      e.target.checked
                        ? [...selected, p.name]
                        : selected.filter((x) => x !== p.name),
                    )
                  }
                />
                <code className="text-xs">{p.name}</code>
                {p.mfa && <span className="text-xs text-muted-foreground">MFA</span>}
              </label>
            ))}
          </fieldset>
          <div className="flex flex-wrap items-center gap-3">
            <Button type="submit" disabled={save.isPending}>
              Zapisz rolę
            </Button>
            {save.isSuccess && (
              <span role="status" className="text-sm text-muted-foreground">
                Zapisano rolę {save.data.name}.
              </span>
            )}
            {(save.error ?? remove.error) && (
              <span role="alert" className="text-sm text-red-700">
                {(save.error ?? remove.error)?.message}
              </span>
            )}
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

function UserRow({ user, roles, manage }: { user: IamUser; roles: IamRole[]; manage: boolean }) {
  const queryClient = useQueryClient();
  const [role, setRole] = useState("");
  const refresh = () => void queryClient.invalidateQueries({ queryKey: ["iam", "users"] });
  const grant = useMutation({ mutationFn: () => api.grantRole(user.id, role), onSuccess: refresh });
  const revoke = useMutation({
    mutationFn: (name: string) => api.revokeRole(user.id, name),
    onSuccess: refresh,
  });
  const grantable = roles.filter(
    (r) => r.grantable && !user.granted_roles.includes(r.name) && !user.token_roles.includes(r.name),
  );
  const label = (name: string) => roles.find((r) => r.name === name)?.label ?? name;
  return (
    <tr>
      <Td>
        <span className="font-medium">{user.display_name || user.username}</span>
        <p className="text-xs text-muted-foreground">
          {user.username}
          {user.kind !== "human" && ` · ${user.kind}`}
          {!user.active && " · nieaktywne"}
        </p>
      </Td>
      <Td>
        <div className="flex flex-wrap gap-1">
          {user.token_roles.map((name) => (
            <Badge key={name} variant="neutral" title="Rola z Keycloak">
              {label(name)}
            </Badge>
          ))}
          {user.granted_roles.map((name) => (
            <Badge key={name} variant="info" title="Rola nadana w konsoli">
              {label(name)}
              {manage && (
                <button
                  type="button"
                  className="ml-1"
                  aria-label={`Odbierz rolę ${name} użytkownikowi ${user.username}`}
                  onClick={() => revoke.mutate(name)}
                >
                  ×
                </button>
              )}
            </Badge>
          ))}
        </div>
      </Td>
      <Td className="whitespace-nowrap">
        {user.last_seen_at ? formatDateTime(user.last_seen_at) : "—"}
      </Td>
      {manage && (
        <Td>
          {user.kind === "human" && grantable.length > 0 && (
            <div className="flex items-center gap-2">
              <Select
                aria-label={`Rola dla ${user.username}`}
                value={role}
                onChange={(e) => setRole(e.target.value)}
              >
                <option value="">rola…</option>
                {grantable.map((r) => (
                  <option key={r.name} value={r.name}>
                    {r.label}
                  </option>
                ))}
              </Select>
              <Button size="sm" disabled={!role || grant.isPending} onClick={() => grant.mutate()}>
                Nadaj
              </Button>
            </div>
          )}
          {(grant.error ?? revoke.error) && (
            <p role="alert" className="text-xs text-red-700">
              {(grant.error ?? revoke.error)?.message}
            </p>
          )}
        </Td>
      )}
    </tr>
  );
}

function Users({ users, roles, manage }: { users: IamUser[]; roles: IamRole[]; manage: boolean }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Użytkownicy</CardTitle>
        <CardDescription>
          Konto pojawia się po pierwszym logowaniu przez Keycloak. Rolę Administracja nadaje się
          tylko w Keycloak; tutaj można nadać pozostałe role wbudowane i role własne.
        </CardDescription>
      </CardHeader>
      <Table>
        <thead>
          <tr>
            <Th>Konto</Th>
            <Th>Role</Th>
            <Th>Ostatnio aktywne</Th>
            {manage && <Th>Nadaj rolę</Th>}
          </tr>
        </thead>
        <tbody>
          {users.map((user) => (
            <UserRow key={user.id} user={user} roles={roles} manage={manage} />
          ))}
        </tbody>
      </Table>
    </Card>
  );
}

export function Roles() {
  const { can } = useAuth();
  const { roles, permissions, users } = useIam();
  const manage = can("iam:manage");
  const pending = roles.isPending || permissions.isPending || users.isPending;
  const error = roles.error ?? permissions.error ?? users.error;
  return (
    <>
      <PageHeader
        title="Role i użytkownicy"
        description="Cztery role z briefu: Administracja; Dodawanie, usuwanie, modyfikacja; Modyfikacja i odczyt; Odczyt. Backend sprawdza uprawnienie na każdym endpoincie (deny-by-default), a ta strona tylko je pokazuje i zmienia."
      />
      <QueryState isPending={pending} error={error} empty={false} emptyText="" />
      {roles.data && permissions.data && (
        <>
          <Matrix roles={roles.data} permissions={permissions.data} />
          {manage && <RoleEditor roles={roles.data} permissions={permissions.data} />}
        </>
      )}
      {roles.data && users.data && <Users users={users.data} roles={roles.data} manage={manage} />}
    </>
  );
}
