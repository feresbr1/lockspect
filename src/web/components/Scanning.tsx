import type { ScanProgress } from '../../core/types';

const STAGES: { id: ScanProgress['stage']; label: string }[] = [
  { id: 'parse', label: 'Reading lockfile' },
  { id: 'advisories', label: 'Checking OSV for malware and vulnerabilities' },
  { id: 'metadata', label: 'Fetching publish dates, licences and provenance' },
];

export function Scanning({ progress, count }: { progress: ScanProgress; count: number }) {
  const current = STAGES.findIndex((s) => s.id === progress.stage);
  const stageShare = 1 / STAGES.length;
  const within = progress.total ? Math.min(1, progress.done / progress.total) : 0;
  const pct = Math.round((Math.max(0, current) + within) * stageShare * 100);

  return (
    <main id="main" class="wrap">
      <section class="scanning" aria-busy="true">
        <h2>Inspecting {count ? `${count.toLocaleString()} packages` : 'lockfile'}…</h2>
        <div
          class="bar"
          role="progressbar"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={pct}
          aria-label="Scan progress"
        >
          <span style={{ width: `${pct}%` }} />
        </div>
        <ol class="stages" aria-live="polite">
          {STAGES.map((stage, i) => (
            <li
              key={stage.id}
              data-state={i < current ? 'done' : i === current ? 'active' : 'todo'}
            >
              {i < current ? '✓' : i === current ? '›' : '·'} {stage.label}
              {i === current && progress.total > 0 && progress.stage !== 'parse'
                ? ` (${progress.done.toLocaleString()} / ${progress.total.toLocaleString()})`
                : ''}
            </li>
          ))}
        </ol>
      </section>
    </main>
  );
}
