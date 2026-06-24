import { Gauge, CreditCard, Mail } from "lucide-react";
import type { LucideIcon } from "lucide-react";

interface Area {
  label: string;
  icon: LucideIcon;
  body: string;
}

const areas: Area[] = [
  {
    label: "How usage is metered",
    icon: Gauge,
    body: "Two things draw down your balance: AI (Aegis and other AI features) and worker compute (the scans that run on Deptex's infrastructure). Every charge is recorded in a ledger you can review.",
  },
  {
    label: "Topping up & auto-recharge",
    icon: CreditCard,
    body: "Add credit with a card through Stripe. Optionally turn on auto-recharge: when your balance drops below a threshold you set, Deptex tops it up automatically — up to a monthly cap so spend stays predictable.",
  },
  {
    label: "Balance alerts",
    icon: Mail,
    body: "Email alerts for low balance, zero balance, credit added, and auto-recharge events go to the members who can manage billing, so funds never run out by surprise.",
  },
];

export default function BillingUsageContent() {
  return (
    <div className="space-y-12">
      <section>
        <p className="text-foreground/90 leading-relaxed">
          Deptex is prepaid and usage-based. You top up a balance and usage draws it down as you go —
          no seats and no subscriptions, so you only pay for what you actually use.
        </p>
      </section>

      <section>
        <div className="rounded-lg border border-border bg-background-card divide-y divide-border">
          {areas.map((area) => {
            const Icon = area.icon;
            return (
              <div key={area.label} className="flex gap-4 p-5">
                <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-border bg-background-subtle">
                  <Icon className="h-5 w-5 text-foreground" />
                </span>
                <div>
                  <h3 className="font-medium text-foreground">{area.label}</h3>
                  <p className="mt-1 text-sm leading-relaxed text-foreground/80">{area.body}</p>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      <section>
        <p className="text-sm leading-relaxed text-foreground/70">
          Managing top-ups, payment methods, and auto-recharge requires the{" "}
          <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono text-foreground">
            manage_billing
          </code>{" "}
          permission.
        </p>
      </section>
    </div>
  );
}
