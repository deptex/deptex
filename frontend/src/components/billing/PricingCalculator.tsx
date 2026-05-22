import React, { useMemo, useState } from 'react';
import { Slider } from '../ui/slider';

// Placeholder per-event rates. The 2x markup is baked in here so users see
// the price they'd actually pay. Once we have telemetry from real ledger
// usage, swap this for self-calibrated rates (opportunity-scout-f4 v1.1).
const RATES = {
  scanCents:  10,  // $0.10 — average repo scan
  chatCents:  40,  // $0.40 — average Aegis chat turn at Sonnet
  fixCents:  100,  // $1.00 — average fix-worker run
};

interface Slider1Props {
  label: string;
  value: number;
  min: number;
  max: number;
  step: number;
  unit: string;
  onChange: (v: number) => void;
}

function CalcSlider({ label, value, min, max, step, unit, onChange }: Slider1Props) {
  return (
    <div className="space-y-2">
      <div className="flex items-baseline justify-between">
        <span className="text-sm font-medium text-foreground">{label}</span>
        <span className="font-mono text-sm text-foreground-secondary">
          {value.toLocaleString()} {unit}
        </span>
      </div>
      <Slider
        value={value}
        min={min}
        max={max}
        step={step}
        onValueChange={(v) => onChange(v)}
      />
    </div>
  );
}

export function PricingCalculator() {
  const [scans, setScans] = useState(50);
  const [chats, setChats] = useState(100);
  const [fixes, setFixes] = useState(10);

  const total = useMemo(() => {
    const cents = scans * RATES.scanCents + chats * RATES.chatCents + fixes * RATES.fixCents;
    return cents;
  }, [scans, chats, fixes]);

  const breakdown = useMemo(
    () => [
      { label: 'Repo scans', count: scans, cost: scans * RATES.scanCents },
      { label: 'Aegis chats', count: chats, cost: chats * RATES.chatCents },
      { label: 'Auto-fixes', count: fixes, cost: fixes * RATES.fixCents },
    ],
    [scans, chats, fixes],
  );

  const totalDollars = (total / 100).toFixed(2);

  return (
    <div className="grid gap-8 rounded-xl border border-border bg-background-card p-6 sm:grid-cols-2">
      <div className="space-y-6">
        <CalcSlider label="Repo scans / month" value={scans} min={0} max={1000} step={5} unit="scans" onChange={setScans} />
        <CalcSlider label="Aegis chats / month" value={chats} min={0} max={2000} step={10} unit="chats" onChange={setChats} />
        <CalcSlider label="Auto-fixes / month" value={fixes} min={0} max={500} step={5} unit="fixes" onChange={setFixes} />
      </div>
      <div className="space-y-4">
        <div className="rounded-lg border border-border bg-background p-6 text-center">
          <p className="text-xs uppercase tracking-wider text-foreground-secondary">Estimated monthly</p>
          <p className="mt-2 text-4xl font-semibold tracking-tight text-foreground">${totalDollars}</p>
        </div>
        <ul className="space-y-2 text-sm">
          {breakdown.map((row) => (
            <li key={row.label} className="flex items-center justify-between text-foreground-secondary">
              <span>{row.label}</span>
              <span className="font-mono">${(row.cost / 100).toFixed(2)}</span>
            </li>
          ))}
        </ul>
        <p className="text-xs text-foreground-secondary">
          Estimates use placeholder per-event rates. Real bills are itemized by exact tokens + worker time.
        </p>
      </div>
    </div>
  );
}
