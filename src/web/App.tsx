import { useEffect, useRef, useState } from 'preact/hooks';
import { analyzeLockfile, DEFAULT_COOLDOWN_DAYS } from '../core/analyze';
import { LockfileError, parseLockfile } from '../core/parsers';
import type { ScanProgress, ScanReport } from '../core/types';
import { VERSION } from '../core/version';
import { GitHubIcon, Logo, ThemeIcon } from './components/Icons';
import { COOLDOWN_CHOICES, Landing } from './components/Landing';
import { Report } from './components/Report';
import { Scanning } from './components/Scanning';
import { storage } from './storage';

const REPO = 'https://github.com/feresbr1/lockspect';

type State =
  | { view: 'landing'; error?: string }
  | { view: 'scanning'; progress: ScanProgress; count: number }
  | { view: 'report'; report: ScanReport };

export function App() {
  const [state, setState] = useState<State>({ view: 'landing' });
  const [cooldownDays, setCooldownDays] = useState(() => {
    const saved = Number(storage.get('cooldownDays'));
    return COOLDOWN_CHOICES.includes(saved) ? saved : DEFAULT_COOLDOWN_DAYS;
  });
  const [theme, setTheme] = useState<'light' | 'dark' | undefined>(
    () => (storage.get('theme') as 'light' | 'dark' | null) ?? undefined,
  );
  const scanId = useRef(0);

  useEffect(() => {
    if (theme) document.documentElement.dataset.theme = theme;
    else delete document.documentElement.dataset.theme;
  }, [theme]);

  // Browser back from a report returns to the drop zone.
  useEffect(() => {
    const onPop = () => {
      scanId.current++;
      setState({ view: 'landing' });
    };
    window.addEventListener('popstate', onPop);
    return () => window.removeEventListener('popstate', onPop);
  }, []);

  const toggleTheme = () => {
    const systemDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    const currentDark = theme ? theme === 'dark' : systemDark;
    const next = currentDark ? 'light' : 'dark';
    setTheme(next);
    storage.set('theme', next);
  };

  const changeCooldown = (days: number) => {
    setCooldownDays(days);
    storage.set('cooldownDays', String(days));
  };

  const scan = async (text: string, fileName?: string) => {
    const id = ++scanId.current;
    let parsed;
    try {
      parsed = parseLockfile(text, fileName);
    } catch (error) {
      const message =
        error instanceof LockfileError
          ? error.message
          : `Could not read this lockfile (${(error as Error).message}).`;
      setState({ view: 'landing', error: message });
      return;
    }
    if (parsed.packages.length === 0) {
      setState({
        view: 'landing',
        error:
          'This lockfile has no packages from the npm registry to check (only workspace, git or local dependencies).',
      });
      return;
    }

    const count = parsed.packages.length;
    setState({
      view: 'scanning',
      count,
      progress: { stage: 'parse', done: 1, total: 1, message: 'Parsed' },
    });
    window.scrollTo({ top: 0 });
    try {
      const report = await analyzeLockfile(parsed, {
        cooldownDays,
        fileName,
        onProgress: (progress) => {
          if (scanId.current === id) setState({ view: 'scanning', count, progress });
        },
      });
      if (scanId.current !== id) return;
      history.pushState({ report: true }, '', '#report');
      setState({ view: 'report', report });
      window.scrollTo({ top: 0 });
    } catch (error) {
      if (scanId.current !== id) return;
      setState({ view: 'landing', error: `Scan failed: ${(error as Error).message}` });
    }
  };

  const reset = () => {
    scanId.current++;
    if (location.hash === '#report') history.back();
    else setState({ view: 'landing' });
  };

  return (
    <>
      <a class="sr-only" href="#main">
        Skip to content
      </a>
      <header class="site-header">
        <div class="wrap">
          <button type="button" class="brand" onClick={reset} aria-label="lockspect home">
            <Logo />
            lockspect
          </button>
          <nav class="nav" aria-label="Site">
            <a class="hide-sm" href={`${REPO}#command-line`}>
              CLI &amp; CI
            </a>
            <button type="button" onClick={toggleTheme} aria-label="Toggle dark mode">
              <ThemeIcon />
            </button>
            <a href={REPO} aria-label="lockspect on GitHub">
              <GitHubIcon />
              <span class="hide-sm">GitHub</span>
            </a>
          </nav>
        </div>
      </header>

      {state.view === 'landing' && (
        <Landing
          cooldownDays={cooldownDays}
          onCooldownChange={changeCooldown}
          onScan={(text, name) => void scan(text, name)}
          error={state.error}
        />
      )}
      {state.view === 'scanning' && <Scanning progress={state.progress} count={state.count} />}
      {state.view === 'report' && <Report report={state.report} onReset={reset} />}

      <footer class="site-footer">
        <div class="wrap">
          <span>
            lockspect v{VERSION} · MIT licensed · <a href={`${REPO}/issues`}>report an issue</a>
          </span>
          <span>
            Advisory data from <a href="https://osv.dev">OSV.dev</a>, package metadata from{' '}
            <a href="https://deps.dev">deps.dev</a> and the npm registry.
          </span>
        </div>
      </footer>
    </>
  );
}
