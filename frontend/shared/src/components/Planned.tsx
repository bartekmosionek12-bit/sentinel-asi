import { PageHeader } from "@shared/components/page";
import { Card, CardContent } from "@shared/components/ui/card";
import type { NavItem } from "@shared/components/AppShell";

export function Planned({ item }: { item: NavItem }) {
  return (
    <>
      <PageHeader title={item.label} description={item.summary ?? ""} />
      <Card>
        <CardContent className="p-8 text-center text-sm text-muted-foreground">
          Ten widok powstanie w etapie P{item.stage} (docs/ROADMAP.md). Inwentarz, skany, zakres i
          dziennik audytu działają już teraz.
        </CardContent>
      </Card>
    </>
  );
}
