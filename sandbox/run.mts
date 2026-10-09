// Runs one browser check: reads the job as JSON on stdin and writes the outcome as JSON on stdout.
import fs from 'node:fs';
import path from 'node:path';
import { spawn, type StdioOptions } from 'node:child_process';

interface Job {
  script: string;
  fileName?: string;
  variables?: Record<string, unknown>;
  proxy?: string;
  snapshot?: 'end' | 'failure';
  guard?: boolean;
  maxArtifactBytes: number;
}

interface Attachment {
  name: string;
  path?: string;
}

interface Result {
  status?: string;
  attachments?: Attachment[];
}

interface Suite {
  specs?: { tests?: { results?: Result[] }[] }[];
  suites?: Suite[];
}

interface Report {
  suites?: Suite[];
}

interface ArtifactFiles {
  files: Record<string, string>;
  artifactBytes: number;
  artifactsTooLarge: boolean;
}

// Private agents run several checks at once, each in its own folder.
const WORK = process.env.ST_WORK_DIR || '/runner/work';
const OUT = path.join(WORK, 'out');
const REPORT = path.join(WORK, 'report.json');
const RUNNER = '/runner';
const BROWSERS = '/ms-playwright';
const CLI = '/runner/node_modules/@playwright/test/cli.js';
const CONFIG = '/runner/playwright.config.ts';
const FILE_NAME = /^check\.spec\.(ts|js)$/;
const VITALS = '/runner/vitals.cts';
const GUARD = '/runner/guard.cts';
const TMP = path.join(WORK, 'tmp');
const PASSING = new Set(['passed', 'skipped']);
// Files Playwright reads outside the folders it may read: its host checks, and the config files it looks for in every
// folder above the check and the config.
const HOST_FILES = ['/etc/os-release', '/.dockerenv', '/run/.containerenv', '/proc/self/cgroup', '/proc/version', '/proc/sys/fs/binfmt_misc/WSLInterop', '/run/WSL', '/etc/wsl.conf'];
const CONFIG_FILES = ['package.json', 'tsconfig.json', 'jsconfig.json'];
// guard.cts writes to this descriptor of the Playwright runner when it refuses a connection.
const REFUSED_FD = 4;
// Tells the process sandbox about a refusal: the check can delete the marker file, not change this exit code.
const REFUSED_EXIT = 3;

function readJob(): Promise<Job> {
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => { data += chunk; });
    process.stdin.on('end', () => {
      try {
        resolve(JSON.parse(data));
      } catch (error) {
        reject(error);
      }
    });
    process.stdin.on('error', reject);
  });
}

function oomKills(): number {
  try {
    const match = fs.readFileSync('/proc/vmstat', 'utf8').match(/^oom_kill (\d+)$/m);
    return match ? Number(match[1]) : 0;
  } catch {
    return 0;
  }
}

// Only the check's own variables reach the script; nothing from this process's environment except PATH.
function scriptEnv(job: Job): Record<string, string | undefined> {
  const env: Record<string, string | undefined> = { PATH: process.env.PATH, HOME: '/tmp', TMPDIR: '/tmp', PLAYWRIGHT_BROWSERS_PATH: BROWSERS, ST_WORK_DIR: WORK };
  for (const [name, value] of Object.entries(job.variables || {})) env[name] = String(value);
  if (job.proxy) env.ST_PROXY = job.proxy;
  if (job.snapshot === 'end' || job.snapshot === 'failure') env.ST_SNAPSHOT = job.snapshot;
  if (job.guard && job.proxy) {
    // Node's fetch and http(s) go through the run's proxy; guard.cts refuses every other connection.
    Object.assign(env, { TMPDIR: TMP, NODE_USE_ENV_PROXY: '1', HTTP_PROXY: job.proxy, HTTPS_PROXY: job.proxy, PLAYWRIGHT_SKIP_VALIDATE_HOST_REQUIREMENTS: '1' });
  }
  return env;
}

function configFilesAbove(folder: string): string[] {
  const files: string[] = [];
  for (let dir = path.dirname(folder); ; dir = path.dirname(dir)) {
    files.push(...CONFIG_FILES.map((name) => path.join(dir, name)));
    if (dir === path.dirname(dir)) return files;
  }
}

// Agent runs share the host's network and its /proc/<pid>/environ holds STATUSTICK_TOKEN, so reads and writes are
// limited and guard.cts is preloaded.
function nodeFlags(job: Job): string[] {
  if (!job.guard) return [];
  const reads = new Set([RUNNER, BROWSERS, WORK, ...HOST_FILES, ...configFilesAbove(WORK), ...configFilesAbove(RUNNER)]);
  return ['--permission', ...[...reads].map((read) => `--allow-fs-read=${read}`), `--allow-fs-write=${WORK}`, '--allow-child-process', '--require', GUARD];
}

function runPlaywright(job: Job, env: Record<string, string | undefined>): Promise<{ exitCode: number | null; refused: boolean }> {
  return new Promise((resolve) => {
    const stdio: StdioOptions = job.guard ? ['ignore', 'ignore', 'ignore', 'ignore', 'pipe'] : ['ignore', 'ignore', 'ignore'];
    const child = spawn(process.execPath, [...nodeFlags(job), CLI, 'test', '--config', CONFIG], { cwd: WORK, env, stdio });
    let refused = false;
    child.stdio[REFUSED_FD]?.on('data', () => { refused = true; });
    child.on('error', () => resolve({ exitCode: -1, refused }));
    child.on('close', (code) => resolve({ exitCode: code, refused }));
  });
}

function readReport(): Report | null {
  try {
    return JSON.parse(fs.readFileSync(REPORT, 'utf8'));
  } catch {
    return null;
  }
}

function results(suite: Suite, out: Result[]): Result[] {
  for (const spec of suite.specs || []) {
    for (const test of spec.tests || []) {
      const all = test.results || [];
      if (all.length) out.push(all[all.length - 1]!);
    }
  }
  for (const child of suite.suites || []) results(child, out);
  return out;
}

// Same choice as the launcher's result: the first failing test, else the last test.
function artifactFiles(report: Report, maxBytes: number): ArtifactFiles {
  const all = (report.suites || []).flatMap((suite) => results(suite, []));
  const source = all.find((result) => !PASSING.has(result.status!)) || all[all.length - 1];
  const picked: { key: string; real: string; size: number }[] = [];
  for (const name of ['screenshot', 'trace']) {
    const attachment = ((source && source.attachments) || []).find((entry) => entry.name === name && entry.path);
    if (!attachment) continue;
    try {
      const real = fs.realpathSync(attachment.path!);
      if (real.startsWith(OUT + path.sep)) picked.push({ key: attachment.path!, real, size: fs.statSync(real).size });
    } catch {
      // A missing attachment file only means no artifact.
    }
  }
  const artifactBytes = picked.reduce((sum, file) => sum + file.size, 0);
  if (artifactBytes > maxBytes) return { files: {}, artifactBytes, artifactsTooLarge: true };
  const files: Record<string, string> = {};
  for (const file of picked) files[file.key] = fs.readFileSync(file.real).toString('base64');
  return { files, artifactBytes, artifactsTooLarge: false };
}

// The script's `@playwright/test` resolves here first, so every page reports its Web Vitals.
function installVitals(): void {
  const dir = path.join(WORK, 'node_modules', '@playwright', 'test');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: '@playwright/test', main: 'index.js' }));
  fs.writeFileSync(path.join(dir, 'index.js'), `module.exports = require(${JSON.stringify(VITALS)});\n`);
}

async function main(): Promise<void> {
  const job = await readJob();
  if (!FILE_NAME.test(job.fileName || '')) throw new Error('bad file name');
  fs.mkdirSync(WORK, { recursive: true, mode: 0o700 });
  fs.mkdirSync(OUT, { recursive: true });
  if (job.guard) fs.mkdirSync(TMP, { recursive: true });
  installVitals();
  fs.writeFileSync(path.join(WORK, job.fileName!), job.script);

  const oomBefore = oomKills();
  const { exitCode, refused } = await runPlaywright(job, scriptEnv(job));
  const report = readReport();
  const artifacts = report ? artifactFiles(report, job.maxArtifactBytes) : { files: {}, artifactBytes: 0, artifactsTooLarge: false };
  process.stdout.write(JSON.stringify({ exitCode, report, ...artifacts, memoryExceeded: oomKills() > oomBefore }));
  if (refused) process.exitCode = REFUSED_EXIT;
}

main().catch((error: Error) => {
  process.stderr.write(`${error.message}\n`);
  process.exit(1);
});
