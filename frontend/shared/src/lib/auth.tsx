/**
 * Logowanie przez Keycloak (OIDC, kod autoryzacji z PKCE).
 *
 * Token trzymamy w sessionStorage karty (znika po jej zamknięciu), odświeżamy refresh tokenem
 * i dołączamy do każdego wywołania API. Uprawnienia pobieramy z `/api/me`: interfejs ukrywa
 * na ich podstawie przyciski, ale o dostępie zawsze decyduje backend.
 */
import { useQuery } from "@tanstack/react-query";
import { LogOut, ShieldAlert } from "lucide-react";
import { UserManager, WebStorageStateStore, type User } from "oidc-client-ts";
import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

import { Button } from "@shared/components/ui/button";
import { api, setTokenSource } from "@shared/lib/api";
import { AuthContext, useAuth, type AuthState } from "@shared/lib/auth-context";

export type AppName = "admin";

const CLIENT_ID: Record<AppName, string> = {
  admin: "sentinel-admin",
};

function createManager(app: AppName): UserManager {
  const origin = window.location.origin;
  return new UserManager({
    authority: `${origin}/auth/realms/sentinel`,
    client_id: CLIENT_ID[app],
    redirect_uri: `${origin}/${app}/`,
    post_logout_redirect_uri: `${origin}/${app}/`,
    response_type: "code",
    scope: "openid",
    automaticSilentRenew: true,
    userStore: new WebStorageStateStore({ store: window.sessionStorage }),
  });
}

function FullScreen({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-6">
      <div className="max-w-md space-y-3 text-center">{children}</div>
    </div>
  );
}

/** Jedno logowanie na załadowanie strony. Kod autoryzacji można wymienić tylko raz, a React
 *  w trybie deweloperskim uruchamia efekty dwukrotnie. */
let pendingSignIn: Promise<User | null> | null = null;

function signIn(manager: UserManager, app: AppName): Promise<User | null> {
  pendingSignIn ??= (async () => {
    const params = new URLSearchParams(window.location.search);
    if (params.has("code") && params.has("state")) {
      const signedIn = await manager.signinRedirectCallback();
      // Usuwa kod z adresu, żeby odświeżenie strony go nie powtórzyło.
      window.history.replaceState({}, "", `/${app}/`);
      return signedIn;
    }
    if (params.has("error")) {
      throw new Error(params.get("error_description") ?? params.get("error") ?? "błąd");
    }
    const stored = await manager.getUser();
    if (stored && !stored.expired) return stored;
    await manager.signinRedirect();
    return null;
  })();
  return pendingSignIn;
}

/** Wymusza zalogowanie przed pokazaniem aplikacji. */
export function AuthProvider({ app, children }: { app: AppName; children: ReactNode }) {
  const manager = useMemo(() => createManager(app), [app]);
  const [user, setUser] = useState<User | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    signIn(manager, app)
      .then((signedIn) => {
        if (!cancelled && signedIn) setUser(signedIn);
      })
      .catch((reason: unknown) => {
        if (!cancelled) setError(reason instanceof Error ? reason.message : String(reason));
      });
    const onLoaded = (loaded: User) => setUser(loaded);
    const onSignedOut = () => setUser(null);
    manager.events.addUserLoaded(onLoaded);
    manager.events.addUserSignedOut(onSignedOut);
    return () => {
      cancelled = true;
      manager.events.removeUserLoaded(onLoaded);
      manager.events.removeUserSignedOut(onSignedOut);
    };
  }, [app, manager]);

  useEffect(() => {
    setTokenSource({
      token: () => user?.access_token ?? null,
      onUnauthorized: () => {
        // Sesja wygasła albo została zakończona: zaloguj ponownie.
        void manager.removeUser().then(() => manager.signinRedirect());
      },
    });
  }, [manager, user]);

  const me = useQuery({
    queryKey: ["me", user?.profile.sub],
    queryFn: api.me,
    enabled: user !== null,
    staleTime: 60_000,
  });

  const logout = useCallback(async () => {
    try {
      await api.logout();
    } finally {
      await manager.signoutRedirect({ id_token_hint: user?.id_token });
    }
  }, [manager, user]);

  const state = useMemo<AuthState | null>(() => {
    if (!user) return null;
    const permissions = new Set(me.data?.permissions ?? []);
    return { user, me: me.data, can: (p) => permissions.has(p), logout };
  }, [user, me.data, logout]);

  if (error) {
    return (
      <FullScreen>
        <h1 className="text-lg font-semibold">Nie udało się zalogować</h1>
        <p className="text-sm text-muted-foreground">{error}</p>
        <Button onClick={() => void manager.signinRedirect()}>Spróbuj ponownie</Button>
      </FullScreen>
    );
  }
  if (!state || me.isPending) {
    return (
      <FullScreen>
        <p className="text-sm text-muted-foreground">Logowanie…</p>
      </FullScreen>
    );
  }
  return <AuthContext.Provider value={state}>{children}</AuthContext.Provider>;
}

/** Strona „brak dostępu”, gdy zalogowany nie ma uprawnienia do całej aplikacji. */
export function AccessDenied({ title, children }: { title: string; children: ReactNode }) {
  const { logout } = useAuth();
  return (
    <FullScreen>
      <ShieldAlert className="mx-auto size-10 text-red-600" aria-hidden />
      <h1 className="text-lg font-semibold">{title}</h1>
      <div className="text-sm text-muted-foreground">{children}</div>
      <Button variant="outline" onClick={() => void logout()}>
        Wyloguj
      </Button>
    </FullScreen>
  );
}

/** Kto jest zalogowany, z przyciskiem wylogowania (nagłówek aplikacji). */
export function UserMenu() {
  const { me, user, logout } = useAuth();
  const name = me?.display_name || user.profile.preferred_username || "użytkownik";
  return (
    <div className="flex items-center gap-2 text-sm">
      <span className="hidden text-muted-foreground sm:inline" title={me?.roles.join(", ")}>
        {name}
        {me?.mfa ? " · MFA" : ""}
      </span>
      <Button size="sm" variant="outline" onClick={() => void logout()} aria-label="Wyloguj">
        <LogOut className="size-4" aria-hidden />
        <span className="hidden sm:inline">Wyloguj</span>
      </Button>
    </div>
  );
}

/** Informacja przy decyzji: kto ją podpisze w dzienniku audytu (z tokenu, nie z formularza). */
export function SignedBy() {
  const { me, user } = useAuth();
  const name = me?.display_name || user.profile.preferred_username || "zalogowany użytkownik";
  return (
    <p className="text-xs text-muted-foreground">
      Decyzja trafi do dziennika audytu jako: <strong className="text-foreground">{name}</strong>
    </p>
  );
}
