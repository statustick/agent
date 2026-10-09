// Preloaded (CommonJS, so before Playwright) into the agent's Playwright runner and workers: network only to the run's
// proxy, no listening, and child processes only Playwright's worker and Chromium on that proxy.
import type { ChildProcess } from 'node:child_process';
import type { Socket } from 'node:net';
import type { Writable } from 'node:stream';
import type * as NodeFs from 'node:fs';
import type * as NodePath from 'node:path';
import type * as NodeOs from 'node:os';
import type * as NodeNet from 'node:net';
import type * as NodeDns from 'node:dns';
import type * as NodeDgram from 'node:dgram';
import type * as NodeChildProcess from 'node:child_process';
import type * as NodeAsyncHooks from 'node:async_hooks';
import type * as NodeV8 from 'node:v8';
import type * as NodeModule from 'node:module';

type Fn = (...args: unknown[]) => unknown;

interface SpawnOptions {
  file: string;
  args: string[];
  envPairs?: string[];
  stdio?: unknown;
}

interface Command {
  method?: unknown;
  params?: Record<string, unknown>;
}

const fs: typeof NodeFs = require('node:fs');
const path: typeof NodePath = require('node:path');
const os: typeof NodeOs = require('node:os');
const net: typeof NodeNet = require('node:net');
const dns: typeof NodeDns = require('node:dns');
const dgram: typeof NodeDgram = require('node:dgram');
const childProcess: typeof NodeChildProcess = require('node:child_process');
const asyncHooks: typeof NodeAsyncHooks = require('node:async_hooks');
const v8: typeof NodeV8 = require('node:v8');
const { syncBuiltinESMExports }: typeof NodeModule = require('node:module');

const writeFileSync = fs.writeFileSync;
const writeSync = fs.writeSync;
const fstatSync = fs.fstatSync;
const realpathSync = fs.realpathSync;
const kill = (process as unknown as { _kill: (pid: number, signal: number) => number })._kill;
const SIGKILL = os.constants.signals.SIGKILL;

const POLICY = 'target not allowed by agent policy';
const MARKER = path.join(process.env.ST_WORK_DIR || '/runner/work', 'egress-refused');
// The script can delete the marker, so refusals also go to this descriptor; guarded children get it at the same number.
const REFUSED_FD = 4;
const refusedPipe = descriptorId(REFUSED_FD);
const RUN_FOLDER = realDir(process.env.ST_WORK_DIR || '/runner/work');
const PROXY = process.env.ST_PROXY || '';
const proxyURL = URL.canParse(PROXY) ? new URL(PROXY) : null;
const BROWSER_NAMES = new Set(['chrome', 'chrome-headless-shell', 'headless_shell']);
const BROWSERS = realDir(process.env.PLAYWRIGHT_BROWSERS_PATH);
const PROXY_SWITCH = /^--?(proxy-server|proxy-bypass-list|proxy-pac-url|no-proxy-server|proxy-auto-detect|force-webrtc-ip-handling-policy)(=|$)/i;
// Switches that start other programs, remap host names, open a debugging port or load an extension can bypass the proxy.
const REFUSED_SWITCH = /^--?([\w-]*cmd-prefix|[\w-]*launcher|browser-subprocess-path|host-resolver-rules|host-rules|remote-debugging-port|remote-debugging-address|load-extension|disable-extensions-except|enable-unsafe-extension-debugging)(=|$)/i;
const DNS_CALL = /^(lookup|lookupService|resolve\w*|reverse)$/;
// Chromium is outside Node's permission model and could read /proc/<pid>/environ (STATUSTICK_TOKEN), so DevTools
// commands may open only these schemes and no file outside the run's folder.
const URL_SCHEMES = new Set(['http:', 'https:', 'about:', 'data:', 'blob:']);
const URL_COMMANDS = new Set(['Page.navigate', 'Target.createTarget', 'Network.loadNetworkResource', 'Fetch.continueRequest', 'Network.continueInterceptedRequest']);

function realDir(dir: string | undefined): string | null {
  try {
    return dir ? realpathSync(dir) : null;
  } catch {
    return null;
  }
}

function descriptorId(fd: number): string | null {
  try {
    const stats = fstatSync(fd);
    return `${stats.dev}:${stats.ino}`;
  } catch {
    return null;
  }
}

function refusedPipeIntact(): boolean {
  return refusedPipe !== null && descriptorId(REFUSED_FD) === refusedPipe;
}

// A script that closed or replaced the descriptor loses this process instead, which fails the run too.
function reportRefusal(): void {
  if (refusedPipe === null) return;
  try {
    if (refusedPipeIntact()) {
      writeSync(REFUSED_FD, '!');
      return;
    }
  } catch {
    // Ends the process below.
  }
  Reflect.apply(kill, process, [process.pid, SIGKILL]);
}

function policyError(): Error {
  try {
    writeFileSync(MARKER, '');
  } catch {
    // The descriptor still reports the refusal.
  }
  reportRefusal();
  return Object.assign(new Error(POLICY), { code: 'TARGET_NOT_ALLOWED' });
}

function deniedError(what: string): Error {
  return Object.assign(new Error(`Browser checks on the agent cannot ${what}.`), { code: 'ERR_ACCESS_DENIED' });
}

function replace(target: object, name: string, make: (original: Fn) => Fn): void {
  const holder = target as Record<string, unknown>;
  const original = holder[name];
  if (typeof original === 'function') holder[name] = make(original as Fn);
}

// The only connection a script or Playwright may open is TCP to the run's proxy; IPC paths count as other targets.
function toProxy(args: unknown[]): boolean {
  if (!proxyURL) return false;
  const first: unknown = Array.isArray(args[0]) ? args[0][0] : args[0];
  let host: unknown = 'localhost';
  let port: unknown = first;
  if (first !== null && typeof first === 'object') {
    const options = first as Record<string, unknown>;
    if (options.path !== undefined) return false;
    host = options.host ?? 'localhost';
    port = options.port;
  } else if (typeof args[1] === 'string') {
    host = args[1];
  }
  return host === proxyURL.hostname && Number(port) === Number(proxyURL.port);
}

replace(net.Socket.prototype, 'connect', (connect) => function (this: Socket, ...args: unknown[]) {
  if (toProxy(args)) return Reflect.apply(connect, this, args);
  const error = policyError();
  process.nextTick(() => this.destroy(error));
  return this;
});

function refuseDNS(target: object, promises: boolean): void {
  for (const name of Object.getOwnPropertyNames(target)) {
    if (!DNS_CALL.test(name)) continue;
    replace(target, name, () => (...args: unknown[]) => {
      const error = policyError();
      if (promises) return Promise.reject(error);
      const callback = args.findLast((arg) => typeof arg === 'function') as Fn | undefined;
      if (!callback) throw error;
      process.nextTick(callback, error);
      return undefined;
    });
  }
}

refuseDNS(dns, false);
refuseDNS(dns.Resolver.prototype, false);
refuseDNS(dns.promises, true);
refuseDNS(dns.promises.Resolver.prototype, true);

for (const name of ['createSocket', 'Socket']) {
  replace(dgram, name, () => function () {
    throw policyError();
  });
}

// Every Node server (net, http, https, http2, tls) listens through this; Chromium talks to Playwright on a pipe.
replace(net.Server.prototype, 'listen', () => function () {
  throw deniedError('listen for connections');
});

function guardedNode(options: SpawnOptions): boolean {
  if (options.file !== process.execPath) return false;
  const flags = process.execArgv;
  const next = options.args[flags.length + 1];
  return flags.every((flag, index) => options.args[index + 1] === flag) && next !== undefined && !next.startsWith('-');
}

function isBrowser(file: string): boolean {
  if (!BROWSERS) return false;
  try {
    const real = realpathSync(file);
    return real.startsWith(BROWSERS + path.sep) && BROWSER_NAMES.has(path.basename(real));
  } catch {
    return false;
  }
}

// Chromium takes the last of repeated switches and stops reading switches at `--`, so the run's proxy goes first and
// every other proxy switch is dropped.
function browserArgs(args: string[]): string[] {
  const [argv0 = '', ...rest] = args;
  const refused = rest.find((arg) => REFUSED_SWITCH.test(arg));
  if (refused) throw deniedError(`start the browser with ${refused.split('=')[0]}`);
  return [
    argv0,
    `--proxy-server=${PROXY}`,
    '--proxy-bypass-list=<-loopback>',
    '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
    ...rest.filter((arg) => !PROXY_SWITCH.test(arg))
  ];
}

function checkURL(url: unknown): void {
  if (url === undefined || url === '') return;
  const scheme = typeof url === 'string' && URL.canParse(url) ? new URL(url).protocol : null;
  if (!scheme) throw deniedError('open this URL');
  if (!URL_SCHEMES.has(scheme)) throw deniedError(`open ${scheme} URLs`);
}

function checkFiles(files: unknown): void {
  for (const file of ([] as unknown[]).concat(files ?? [])) {
    let real = '';
    try {
      real = typeof file === 'string' ? realpathSync(file) : '';
    } catch {
      // Refused below.
    }
    if (!RUN_FOLDER || !real.startsWith(RUN_FOLDER + path.sep)) throw deniedError('give the browser files outside the run folder');
  }
}

function checkCommand(command: Command): void {
  const params = command.params ?? {};
  if (URL_COMMANDS.has(String(command.method))) checkURL(params.url);
  if (command.method === 'DOM.setFileInputFiles') checkFiles(params.files);
  if (command.method === 'Input.dispatchDragEvent') checkFiles((params.data as { files?: unknown } | undefined)?.files);
  if (command.method === 'Target.sendMessageToTarget' && typeof params.message === 'string') checkCommand(parseCommand(params.message));
}

function parseCommand(text: string): Command {
  try {
    const command: unknown = JSON.parse(text);
    if (command !== null && typeof command === 'object') return command as Command;
  } catch {
    // Refused below.
  }
  throw deniedError('send the browser this command');
}

// Sent re-serialized, so Chromium reads the command that was checked (no duplicate keys).
function browserCommand(text: string): string {
  const command = parseCommand(text);
  checkCommand(command);
  if (command.method !== 'Target.createBrowserContext') return JSON.stringify(command);
  return JSON.stringify({ ...command, params: { ...command.params, proxyServer: PROXY, proxyBypassList: '<-loopback>' } });
}

// Commands go to Chromium as JSON ending in NUL. A context can have its own proxy (CDP Target.createBrowserContext);
// every new context gets the run's proxy instead. A refused command throws to its sender and never reaches Chromium.
function filterCommands(pipe: Writable): void {
  const write = pipe.write as Fn;
  let pending = '';
  (pipe as unknown as { write: Fn }).write = function (this: Writable, chunk: unknown, ...rest: unknown[]) {
    pending += String(chunk);
    let out = '';
    let refused: unknown = null;
    for (let end = pending.indexOf('\0'); end !== -1 && !refused; end = pending.indexOf('\0')) {
      const text = pending.slice(0, end);
      pending = pending.slice(end + 1);
      try {
        out += `${browserCommand(text)}\0`;
      } catch (error) {
        refused = error;
      }
    }
    const written = out ? Reflect.apply(write, this, [out, ...rest]) : true;
    if (refused) throw refused;
    return written;
  };
}

// The script may pass another descriptor at that number; a forked Node child always gets the real one.
function withRefusedPipe(stdio: unknown): unknown[] {
  const list: unknown[] = Array.isArray(stdio) ? [...stdio] : new Array<unknown>(3).fill(stdio ?? 'pipe');
  while (list.length < REFUSED_FD) list.push('ignore');
  list[REFUSED_FD] = REFUSED_FD;
  return list;
}

replace(childProcess.ChildProcess.prototype, 'spawn', (spawn) => function (this: ChildProcess, ...args: unknown[]) {
  const options = args[0] as SpawnOptions;
  if (guardedNode(options)) {
    options.envPairs = options.envPairs?.filter((pair) => !pair.startsWith('NODE_OPTIONS='));
    if (refusedPipe !== null) {
      if (!refusedPipeIntact()) throw deniedError('start other programs');
      options.stdio = withRefusedPipe(options.stdio);
    }
    return Reflect.apply(spawn, this, args);
  }
  if (!PROXY || !isBrowser(options.file)) throw deniedError('start other programs');
  options.args = browserArgs(options.args);
  const result = Reflect.apply(spawn, this, args);
  const pipe = this.stdio[3];
  if (pipe && 'write' in pipe) filterCommands(pipe);
  return result;
});

for (const name of ['spawnSync', 'execSync', 'execFileSync']) {
  replace(childProcess, name, () => () => {
    throw deniedError('start other programs');
  });
}

// These hand out the request objects of pending connections, from which a new connection could be made by hand.
replace(asyncHooks, 'createHook', () => () => ({ enable() { return this; }, disable() { return this; } }));
replace(asyncHooks, 'executionAsyncResource', () => () => ({}));
replace(process, '_getActiveRequests', () => () => []);
replace(process, '_getActiveHandles', () => () => []);
replace(v8, 'setFlagsFromString', () => () => {
  throw deniedError('change V8 flags');
});

syncBuiltinESMExports();
