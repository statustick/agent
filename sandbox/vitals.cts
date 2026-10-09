// Stands in for @playwright/test in the check's folder: the same API, with the last page's Web Vitals attached to each test.
// CommonJS, because the check folder's @playwright/test is a CommonJS shim that requires this file (see run.mts).
import type * as Playwright from '@playwright/test';

interface Vitals {
  lcpMs: number | null;
  cls: number;
  tbtMs: number;
}

declare global {
  interface Window {
    __statustickVitals?: () => Vitals;
  }
}

const base: typeof Playwright = require('/runner/node_modules/@playwright/test');

// Added to Chromium's own User-Agent, so a site can tell a StatusTick browser check; the same text the other checks send
// (USER_AGENT in @statustick/checks, which the sandbox cannot import).
const USER_AGENT_SUFFIX = 'StatusTick/2.0 (+https://statustick.com/docs/checks)';
let chromiumUserAgent: Promise<string> | null = null;

function defaultUserAgent(browser: Playwright.Browser): Promise<string> {
  chromiumUserAgent ??= (async () => {
    const page = await browser.newPage();
    try {
      return await page.evaluate(() => navigator.userAgent);
    } finally {
      await page.close();
    }
  })();
  return chromiumUserAgent;
}

// Set by run.mts only for the runner's /snapshot and /failure-snapshot runs; regular runs never attach page text.
const SNAPSHOT = process.env.ST_SNAPSHOT;
const SNAPSHOT_CHARS = 30 * 1024;

async function attachSnapshot(page: Playwright.Page, testInfo: Playwright.TestInfo): Promise<void> {
  const body = page.locator('body');
  const ariaSnapshot = await body.ariaSnapshot({ timeout: 5000 }).catch(() => '');
  const text = await body.innerText({ timeout: 5000 }).catch(() => '');
  const snapshot = {
    url: page.url(),
    title: await page.title().catch(() => ''),
    ariaSnapshot: ariaSnapshot.slice(0, SNAPSHOT_CHARS),
    text: text.slice(0, SNAPSHOT_CHARS),
    truncated: ariaSnapshot.length > SNAPSHOT_CHARS || text.length > SNAPSHOT_CHARS
  };
  await testInfo.attach('page-snapshot', { body: JSON.stringify(snapshot), contentType: 'application/json' });
}

function collectVitals() {
  if (window !== window.top || window.__statustickVitals) return;
  const state: { lcp: number | null; cls: number; longTasks: { start: number; duration: number }[] } = { lcp: null, cls: 0, longTasks: [] };
  Object.defineProperty(window, '__statustickVitals', {
    value: () => {
      const fcp = performance.getEntriesByName('first-contentful-paint')[0];
      const from = fcp ? fcp.startTime : 0;
      const tbt = state.longTasks
        .filter((task) => task.start >= from)
        .reduce((sum, task) => sum + Math.max(0, task.duration - 50), 0);
      return {
        lcpMs: state.lcp === null ? null : Math.round(state.lcp),
        cls: Math.round(state.cls * 10000) / 10000,
        tbtMs: Math.round(tbt)
      };
    }
  });
  const observe = (type: string, onEntry: (entry: PerformanceEntry & { hadRecentInput?: boolean; value?: number }) => void) => {
    try {
      new PerformanceObserver((list) => list.getEntries().forEach(onEntry)).observe({ type, buffered: true });
    } catch {
      // An entry type the browser does not support only leaves that value empty.
    }
  };
  observe('largest-contentful-paint', (entry) => { state.lcp = entry.startTime; });
  observe('layout-shift', (entry) => { if (!entry.hadRecentInput) state.cls += entry.value!; });
  observe('longtask', (entry) => { state.longTasks.push({ start: entry.startTime, duration: entry.duration }); });
}

const test = base.test.extend({
  // A check that sets its own `userAgent` keeps it.
  userAgent: async ({ userAgent, browser }, use) => {
    await use(userAgent ?? `${await defaultUserAgent(browser)} ${USER_AGENT_SUFFIX}`);
  },
  page: async ({ page }, use, testInfo) => {
    await page.addInitScript(collectVitals);
    await use(page);
    const failed = testInfo.status !== testInfo.expectedStatus;
    if (SNAPSHOT === 'end' || (SNAPSHOT === 'failure' && failed)) await attachSnapshot(page, testInfo).catch(() => {});
    const vitals = await page
      .evaluate(() => (typeof window.__statustickVitals === 'function' ? window.__statustickVitals() : null))
      .catch(() => null);
    if (vitals) await testInfo.attach('web-vitals', { body: JSON.stringify(vitals), contentType: 'application/json' });
  }
});

module.exports = { ...base, test, default: test };
