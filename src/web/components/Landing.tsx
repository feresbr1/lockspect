import { useEffect, useRef, useState } from 'preact/hooks';
import { SUPPORTED_LOCKFILES } from '../../core/parsers';
import { FINDING_INFO, FINDING_ORDER } from '../../core/report';
import { SAMPLES, type Sample } from '../samples';
import { FINDING_TONE } from '../tones';
import { UploadIcon } from './Icons';
import { CopyButton } from './CopyButton';

export const COOLDOWN_CHOICES = [1, 3, 7, 14, 30];
const MAX_BYTES = 50 * 1024 * 1024;

interface LandingProps {
  cooldownDays: number;
  onCooldownChange: (days: number) => void;
  onScan: (text: string, fileName?: string) => void;
  error?: string;
}

export function Landing({ cooldownDays, onCooldownChange, onScan, error }: LandingProps) {
  const [over, setOver] = useState(false);
  const [pasteOpen, setPasteOpen] = useState(false);
  const [pasted, setPasted] = useState('');
  const [readError, setReadError] = useState<string>();
  const inputRef = useRef<HTMLInputElement>(null);
  const pasteRef = useRef<HTMLTextAreaElement>(null);

  const readFile = async (file: File | undefined) => {
    setReadError(undefined);
    if (!file) return;
    if (file.size > MAX_BYTES) {
      setReadError(`${file.name} is ${(file.size / 1e6).toFixed(0)} MB. The limit is 50 MB.`);
      return;
    }
    try {
      onScan(await file.text(), file.name);
    } catch {
      setReadError(`Could not read ${file.name}.`);
    }
  };

  // Paste a lockfile anywhere on the page (outside text inputs) to scan it.
  useEffect(() => {
    const onPaste = (event: ClipboardEvent) => {
      const target = event.target as HTMLElement | null;
      if (target && /^(INPUT|TEXTAREA)$/.test(target.tagName)) return;
      const file = event.clipboardData?.files[0];
      if (file) {
        event.preventDefault();
        void readFile(file);
        return;
      }
      const text = event.clipboardData?.getData('text') ?? '';
      if (text.trim().length > 20) {
        event.preventDefault();
        onScan(text);
      }
    };
    window.addEventListener('paste', onPaste);
    return () => window.removeEventListener('paste', onPaste);
  });

  useEffect(() => {
    if (pasteOpen) pasteRef.current?.focus();
  }, [pasteOpen]);

  const loadSample = async (sample: Sample) => {
    setReadError(undefined);
    try {
      onScan(await sample.load(), sample.fileName);
    } catch {
      setReadError('Could not load the sample. Check your connection and try again.');
    }
  };

  const shownError = readError ?? error;

  return (
    <main id="main">
      <section class="hero wrap">
        <p class="eyebrow">npm · pnpm · Yarn · Bun lockfile inspector</p>
        <h1>
          Is your lockfile <em>hiding something?</em>
        </h1>
        <p class="lede">
          Drop a lockfile and lockspect checks every exact version you install for malware, known
          vulnerabilities, releases too fresh to trust, versions pulled from npm, install scripts
          and licence risk. It takes seconds, needs no account, and your file stays in your browser.
        </p>

        <div
          class={`drop${over ? ' is-over' : ''}`}
          data-testid="dropzone"
          // The whole zone is a convenience click target; keyboard users get the buttons below.
          onClick={() => inputRef.current?.click()}
          onDragOver={(e) => {
            e.preventDefault();
            setOver(true);
          }}
          onDragLeave={() => setOver(false)}
          onDrop={(e) => {
            e.preventDefault();
            setOver(false);
            void readFile(e.dataTransfer?.files[0]);
          }}
        >
          <UploadIcon />
          <div>
            <p class="drop-title">Drop your lockfile here</p>
            <p class="drop-sub">or click to choose a file · or press Ctrl/⌘ + V to paste it</p>
          </div>
          <div class="filetypes" aria-label="Supported files">
            {SUPPORTED_LOCKFILES.map((name) => (
              <span class="filetype" key={name}>
                {name}
              </span>
            ))}
          </div>
          <div class="drop-actions" onClick={(e) => e.stopPropagation()}>
            <button type="button" class="btn btn-primary" onClick={() => inputRef.current?.click()}>
              Choose lockfile
            </button>
            <button
              type="button"
              class="btn"
              aria-expanded={pasteOpen}
              onClick={() => setPasteOpen(!pasteOpen)}
            >
              Paste text
            </button>
          </div>
          <input
            ref={inputRef}
            type="file"
            class="sr-only"
            tabIndex={-1}
            aria-hidden="true"
            accept=".json,.yaml,.yml,.lock,application/json,text/plain"
            onChange={(e) => {
              const input = e.currentTarget;
              void readFile(input.files?.[0]);
              input.value = '';
            }}
          />
        </div>

        {pasteOpen && (
          <form
            class="paste-form"
            style={{ marginTop: '14px', display: 'grid', gap: '10px' }}
            onSubmit={(e) => {
              e.preventDefault();
              if (pasted.trim()) onScan(pasted);
            }}
          >
            <label class="sr-only" for="paste">
              Lockfile contents
            </label>
            <textarea
              id="paste"
              ref={pasteRef}
              class="paste-area"
              placeholder="Paste the contents of package-lock.json, pnpm-lock.yaml, yarn.lock or bun.lock"
              value={pasted}
              onInput={(e) => setPasted(e.currentTarget.value)}
              spellcheck={false}
            />
            <div>
              <button type="submit" class="btn btn-primary" disabled={!pasted.trim()}>
                Scan pasted lockfile
              </button>
            </div>
          </form>
        )}

        {shownError && (
          <div class="error-box" role="alert">
            <strong>Can't scan that.</strong> {shownError}
          </div>
        )}

        <div class="controls">
          <div class="segmented" role="group" aria-labelledby="cooldown-label">
            <span class="segmented-label" id="cooldown-label">
              Flag releases younger than
            </span>
            <span class="segmented-group">
              {COOLDOWN_CHOICES.map((days) => (
                <button
                  type="button"
                  key={days}
                  aria-pressed={cooldownDays === days}
                  onClick={() => onCooldownChange(days)}
                >
                  {days}d
                </button>
              ))}
            </span>
          </div>
          <div class="samples">
            <span>No lockfile handy? Try</span>
            {SAMPLES.map((sample, i) => (
              <span key={sample.id}>
                <button
                  type="button"
                  class="linkish"
                  title={sample.description}
                  onClick={() => void loadSample(sample)}
                >
                  {sample.label}
                </button>
                {i < SAMPLES.length - 1 ? ' or' : ''}
              </span>
            ))}
          </div>
        </div>
      </section>

      <section class="wrap" aria-labelledby="checks-title">
        <h2 id="checks-title" class="sr-only">
          What lockspect checks
        </h2>
        <div class="checks">
          {FINDING_ORDER.map((kind) => (
            <div class="check" key={kind}>
              <span class="dot" style={{ background: FINDING_TONE[kind].fg }} />
              <h3>{FINDING_INFO[kind].title}</h3>
              <p>{FINDING_INFO[kind].blurb}</p>
            </div>
          ))}
          <div class="check">
            <span class="dot" style={{ background: 'var(--green)' }} />
            <h3>Provenance</h3>
            <p>Which versions were built in public CI with a signed npm provenance attestation.</p>
          </div>
        </div>

        <div class="privacy">
          <div>
            <h2>Private by design</h2>
            <p>
              Your lockfile is parsed in this tab and is never uploaded. Only package names and
              versions are sent to the public <a href="https://osv.dev">OSV.dev</a> and{' '}
              <a href="https://deps.dev">deps.dev</a> APIs, plus the npm registry for versions those
              have not indexed. No accounts, cookies or analytics.
            </p>
          </div>
          <div>
            <h2>Same checks in CI</h2>
            <p>Fail a build on malware or critical advisories with the CLI or GitHub Action.</p>
            <div class="cmd">
              <code>npx github:feresbr1/lockspect --fail-on malware,vuln:critical</code>
              <CopyButton
                class="copy"
                text="npx github:feresbr1/lockspect --fail-on malware,vuln:critical"
              />
            </div>
          </div>
        </div>
      </section>
    </main>
  );
}
