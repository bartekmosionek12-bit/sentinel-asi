import { useQuery } from "@tanstack/react-query";

import { api, type GlossaryTerm } from "@shared/lib/api";

/** Słownik terminów z rules/glossary.yaml (podpowiedzi w tekstach nietechnicznych). */
export function useGlossary(): GlossaryTerm[] {
  const glossary = useQuery({ queryKey: ["glossary"], queryFn: api.glossary, staleTime: 600_000 });
  return glossary.data ?? [];
}
