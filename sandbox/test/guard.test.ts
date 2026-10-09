import { test, before, after } from 'node:test';
import assert from 'node:assert';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import type { AddressInfo } from 'node:net';
import type { Duplex } from 'node:stream';

const GUARD = path.resolve(import.meta.dirname, '../guard.cts');
const POLICY = 'target not allowed by agent policy';
const LISTEN = 'Browser checks on the agent cannot listen for connections.';
const FILE_URLS = 'Browser checks on the agent cannot open file: URLs.';
const OUTSIDE_FILES = 'Browser checks on the agent cannot give the browser files outside the run folder.';

let internalHits = 0;
const internal = http.createServer((_req, res) => {
  internalHits++;
  res.end('internal');
});
const proxied: string[] = [];
const proxy = http.createServer((req, res) => {
  proxied.push(`${req.method} ${req.url?.startsWith('/') ? `http://${req.headers.host}${req.url}` : req.url}`);
  res.end('via proxy');
});
// Node 24's fetch tunnels plain http through CONNECT; the tunnel is served by the same proxy.
proxy.on('connect', (_req, socket: Duplex, head: Buffer) => {
  socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
  if (head.length > 0) socket.unshift(head);
  proxy.emit('connection', socket);
});
const port = (server: http.Server) => (server.address() as AddressInfo).port;
const proxyURL = () => `http://127.0.0.1:${port(proxy)}`;

before(async () => {
  await new Promise<void>((resolve) => internal.listen(0, '127.0.0.1', resolve));
  await new Promise<void>((resolve) => proxy.listen(0, '127.0.0.1', resolve));
});
after(() => {
  internal.close();
  proxy.close();
});

interface Guarded {
  output: string;
  /** The marker file is there. */
  refused: boolean;
  /** A refusal came on the descriptor run.mts reads. */
  reported: boolean;
  signal: NodeJS.Signals | null;
  work: string;
}

/**
 * Runs [code] as run.mts starts Playwright on the agent: permission model reading only the run folder, the guard and
 * [reads], guard.cts preloaded, a fresh work folder and the refusal descriptor.
 */
async function guarded(code: string, env: Record<string, string> = {}, reads: string[] = []): Promise<Guarded> {
  const work = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'st-run-')));
  const allowed = [work, path.dirname(GUARD), ...reads].map((read) => `--allow-fs-read=${read}`);
  const flags = ['--permission', ...allowed, `--allow-fs-write=${work}`, '--allow-child-process', '--require', GUARD];
  // A file, not -e: fork() passes process.execArgv on, and -e would be part of it.
  const script = path.join(work, 'check.cjs');
  fs.writeFileSync(script, code);
  const { output, reported, signal } = await new Promise<{ output: string; reported: boolean; signal: NodeJS.Signals | null }>((resolve, reject) => {
    const child = spawn(process.execPath, [...flags, script], {
      env: { PATH: process.env.PATH, ST_WORK_DIR: work, ST_PROXY: proxyURL(), PLAYWRIGHT_BROWSERS_PATH: path.join(work, 'browsers'), ...env },
      stdio: ['ignore', 'pipe', 'pipe', 'ignore', 'pipe'],
      timeout: 20_000
    });
    let stdout = '';
    let stderr = '';
    let reported = false;
    child.stdout?.on('data', (chunk) => { stdout += chunk; });
    child.stderr?.on('data', (chunk) => { stderr += chunk; });
    child.stdio[4]?.on('data', () => { reported = true; });
    child.on('error', reject);
    child.on('close', (code, signal) => {
      if (code === 0 || signal === 'SIGKILL') resolve({ output: stdout.trim(), reported, signal });
      else reject(new Error(`exited with ${code ?? signal}\n${stderr}`));
    });
  });
  return { output, refused: fs.existsSync(path.join(work, 'egress-refused')), reported, signal, work };
}

/** A stand-in for Chromium in [browsers]: writes its switches to `args` and what it gets on its DevTools pipe to `cdp`. */
function fakeChrome(browsers: string): string {
  const chrome = path.join(browsers, 'chromium_headless_shell-1', 'chrome-headless-shell-linux64', 'chrome-headless-shell');
  fs.mkdirSync(path.dirname(chrome), { recursive: true });
  fs.writeFileSync(chrome, '#!/bin/sh\nprintf \'%s\\n\' "$@" > "$ST_WORK_DIR/args"\ncat <&3 > "$ST_WORK_DIR/cdp"\n', { mode: 0o755 });
  return chrome;
}

test('a direct fetch fails with the agent policy error and marks the run as refused', async () => {
  const { output, refused, reported } = await guarded(`
fetch('http://127.0.0.1:${port(internal)}/').then(() => console.log('reached'), (error) => console.log(error.cause?.message ?? error.message));
`);
  assert.strictEqual(output, POLICY);
  assert.strictEqual(refused, true);
  assert.strictEqual(reported, true);
  assert.strictEqual(internalHits, 0);
});

test('a refusal is reported on the descriptor even when the script deletes the marker file', async () => {
  const { output, refused, reported } = await guarded(`
const fs = require('node:fs');
const path = require('node:path');
require('node:net').connect(${port(internal)}, '127.0.0.1').on('error', (error) => {
  fs.rmSync(path.join(process.env.ST_WORK_DIR, 'egress-refused'));
  console.log(error.message);
});
`);
  assert.strictEqual(output, POLICY);
  assert.strictEqual(refused, false);
  assert.strictEqual(reported, true);
});

test('a script that closes or replaces the descriptor is ended at its next refusal', async () => {
  const { output, reported, signal } = await guarded(`
const fs = require('node:fs');
fs.closeSync(4);
fs.openSync(require('node:path').join(process.env.ST_WORK_DIR, 'not-the-pipe'), 'w');
require('node:net').connect(${port(internal)}, '127.0.0.1').on('error', () => console.log('caught'));
`);
  assert.strictEqual(signal, 'SIGKILL');
  assert.strictEqual(output, '');
  assert.strictEqual(reported, false);
  assert.strictEqual(internalHits, 0);
});

test('a forked Node process reports on the same descriptor, whatever the script passes at its number', async () => {
  const { output, refused, reported } = await guarded(`
const fs = require('node:fs');
const path = require('node:path');
const child = path.join(process.env.ST_WORK_DIR, 'child.js');
fs.writeFileSync(child, "require('node:net').connect(80, '169.254.169.254').on('error', (error) => { require('node:fs').rmSync(require('node:path').join(process.env.ST_WORK_DIR, 'egress-refused')); process.send(error.message, () => process.exit()); });");
const forked = require('node:child_process').fork(child, { stdio: ['ignore', 'ignore', 'ignore', 'ipc', 'pipe'] });
forked.stdio[4]?.on('data', () => console.log('the script got the report'));
forked.on('message', (message) => console.log(message));
`);
  assert.strictEqual(output, POLICY);
  assert.strictEqual(refused, false);
  assert.strictEqual(reported, true);
});

test("the script reads only its run folder and the files Playwright needs, not the agent's environment or files", async () => {
  const agent = fs.mkdtempSync(path.join(os.tmpdir(), 'st-agent-'));
  const token = path.join(agent, 'token.env');
  fs.writeFileSync(token, 'STATUSTICK_TOKEN=sta_live_secret\n');
  try {
    const { output } = await guarded(`
const fs = require('node:fs');
const path = require('node:path');
const attempt = (run) => {
  try {
    run();
    return 'read';
  } catch (error) {
    return error.code;
  }
};
const own = path.join(process.env.ST_WORK_DIR, 'own.txt');
fs.writeFileSync(own, 'x');
console.log(JSON.stringify([
  attempt(() => fs.readFileSync(own)),
  attempt(() => fs.readFileSync(${JSON.stringify(token)})),
  attempt(() => process.loadEnvFile(${JSON.stringify(token)})),
  attempt(() => fs.readFileSync('/proc/' + process.ppid + '/environ')),
  attempt(() => fs.readFileSync('/proc/1/environ')),
  attempt(() => fs.readdirSync('/'))
]));
`);
    const denied = 'ERR_ACCESS_DENIED';
    assert.deepStrictEqual(JSON.parse(output), ['read', denied, denied, denied, denied, denied]);
  } finally {
    fs.rmSync(agent, { recursive: true, force: true });
  }
});

test('the script cannot listen: net, http, https and local socket servers are refused, and UDP sockets', async () => {
  const { output } = await guarded(`
const path = require('node:path');
const attempt = (run) => {
  try {
    run();
    return 'listening';
  } catch (error) {
    return error.message;
  }
};
console.log(JSON.stringify([
  attempt(() => require('node:net').createServer().listen(0)),
  attempt(() => require('node:http').createServer().listen(0, '127.0.0.1')),
  attempt(() => require('node:https').createServer().listen(8443)),
  attempt(() => require('node:net').createServer().listen(path.join(process.env.ST_WORK_DIR, 'server.sock'))),
  attempt(() => require('node:dgram').createSocket('udp4').bind(0))
]));
`);
  assert.deepStrictEqual(JSON.parse(output), [LISTEN, LISTEN, LISTEN, LISTEN, POLICY]);
});

test("the script's fetch and http requests go through the run's proxy", async () => {
  proxied.length = 0;
  const { output, refused } = await guarded(`
const http = require('node:http');
(async () => {
  const fetched = await (await fetch('http://app.internal/fetch')).text();
  const got = await new Promise((resolve, reject) => http.get('http://app.internal/http', (res) => {
    let body = '';
    res.on('data', (chunk) => { body += chunk; });
    res.on('end', () => resolve(body));
  }).on('error', reject));
  console.log(JSON.stringify([fetched, got]));
})();
`, { NODE_USE_ENV_PROXY: '1', HTTP_PROXY: proxyURL(), HTTPS_PROXY: proxyURL() });
  assert.deepStrictEqual(JSON.parse(output), ['via proxy', 'via proxy']);
  assert.deepStrictEqual(proxied.sort(), ['GET http://app.internal/fetch', 'GET http://app.internal/http']);
  assert.strictEqual(refused, false);
});

test('a raw socket reaches only the proxy port: other ports, TLS to metadata and local sockets are refused', async () => {
  const { output, refused } = await guarded(`
const net = require('node:net');
const tls = require('node:tls');
const { once } = require('node:events');
const attempt = async (socket) => {
  try {
    await once(socket, 'connect');
    socket.destroy();
    return 'connected';
  } catch (error) {
    return error.message;
  }
};
(async () => {
  console.log(JSON.stringify([
    await attempt(net.connect(${port(proxy)}, '127.0.0.1')),
    await attempt(net.connect(${port(internal)}, '127.0.0.1')),
    await attempt(net.connect({ host: '169.254.169.254', port: 80 })),
    await attempt(tls.connect(443, '169.254.169.254')),
    await attempt(net.connect('/var/run/docker.sock'))
  ]));
})();
`);
  assert.deepStrictEqual(JSON.parse(output), ['connected', POLICY, POLICY, POLICY, POLICY]);
  assert.strictEqual(refused, true);
  assert.strictEqual(internalHits, 0);
});

test('DNS lookups and queries are refused, by callback, promise, resolver and ES module import', async () => {
  const { output, refused } = await guarded(`
const dns = require('node:dns');
const message = (error) => error.message;
(async () => {
  const results = [];
  results.push(await new Promise((resolve) => dns.lookup('example.com', (error) => resolve(error.message))));
  results.push(await new Promise((resolve) => new dns.Resolver().resolve4('example.com', (error) => resolve(error.message))));
  results.push(await dns.promises.resolve4('example.com').catch(message));
  results.push(await require('node:dns/promises').lookup('example.com').catch(message));
  const { lookup } = await import('node:dns');
  results.push(await new Promise((resolve) => lookup('example.com', (error) => resolve(error.message))));
  console.log(JSON.stringify(results));
})();
`);
  assert.deepStrictEqual(JSON.parse(output), [POLICY, POLICY, POLICY, POLICY, POLICY]);
  assert.strictEqual(refused, true);
});

test('UDP and other programs are refused; a forked Node process keeps the guard', async () => {
  const { output } = await guarded(`
const fs = require('node:fs');
const path = require('node:path');
const childProcess = require('node:child_process');
const results = [];
const attempt = (run) => {
  try {
    run();
    results.push('ran');
  } catch (error) {
    results.push(error.message);
  }
};
attempt(() => require('node:dgram').createSocket('udp4').send('x', 53, '8.8.8.8'));
attempt(() => childProcess.execSync('curl http://169.254.169.254/'));
attempt(() => childProcess.spawn('sh', ['-c', 'true']));
attempt(() => childProcess.spawn(process.execPath, ['-e', '1']));
attempt(() => childProcess.spawn(process.execPath, [...process.execArgv, '--allow-addons', '-e', '1']));
const child = path.join(process.env.ST_WORK_DIR, 'child.js');
fs.writeFileSync(child, "require('node:net').connect(80, '169.254.169.254').on('error', (error) => process.send(error.message, () => process.exit()));");
childProcess.fork(child).on('message', (message) => {
  results.push(message);
  console.log(JSON.stringify(results));
});
`);
  const programs = 'Browser checks on the agent cannot start other programs.';
  assert.deepStrictEqual(JSON.parse(output), [POLICY, programs, programs, programs, programs, POLICY]);
});

test('Chromium starts only on the run proxy, with no switch that starts other programs, and each new context gets the proxy', async () => {
  const work = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'st-browsers-')));
  const chrome = fakeChrome(work);
  try {
    const { output, work: run } = await guarded(`
const childProcess = require('node:child_process');
const chrome = ${JSON.stringify(chrome)};
const child = childProcess.spawn(chrome, ['--headless', '--proxy-server=direct://', '--no-proxy-server', '--', 'about:blank'], { stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'pipe'] });
child.stdio[3].write(JSON.stringify({ id: 1, method: 'Target.createBrowserContext', params: { proxyServer: 'http://203.0.113.9:8080', proxyBypassList: '*' } }));
child.stdio[3].write('\\0');
child.stdio[3].end();
child.on('close', () => {
  try {
    childProcess.spawn(chrome, ['--headless', '--renderer-cmd-prefix=sh']);
    console.log('started');
  } catch (error) {
    console.log(error.message);
  }
});
`, { PLAYWRIGHT_BROWSERS_PATH: work }, [work]);
    assert.strictEqual(output, 'Browser checks on the agent cannot start the browser with --renderer-cmd-prefix.');
    assert.deepStrictEqual(fs.readFileSync(path.join(run, 'args'), 'utf8').trim().split('\n'), [
      `--proxy-server=${proxyURL()}`,
      '--proxy-bypass-list=<-loopback>',
      '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
      '--headless',
      '--',
      'about:blank'
    ]);
    const [message] = fs.readFileSync(path.join(run, 'cdp'), 'utf8').split('\0');
    assert.deepStrictEqual(JSON.parse(message!).params, { proxyServer: proxyURL(), proxyBypassList: '<-loopback>' });
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
});

test("a pending connection's request object stays out of reach", async () => {
  const { output } = await guarded(`
const asyncHooks = require('node:async_hooks');
const seen = [];
asyncHooks.createHook({ init: (_id, type) => seen.push(type) }).enable();
const socket = require('node:net').connect(${port(proxy)}, '127.0.0.1', () => {
  console.log(JSON.stringify([seen.length, process._getActiveRequests().length, Object.keys(asyncHooks.executionAsyncResource()).length]));
  socket.destroy();
});
`);
  assert.deepStrictEqual(JSON.parse(output), [0, 0, 0]);
});

test('the browser opens no local file: other URL schemes and files outside the run folder are refused on its DevTools pipe', async () => {
  const browsers = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'st-browsers-')));
  const chrome = fakeChrome(browsers);
  try {
    const { output, work } = await guarded(`
const fs = require('node:fs');
const path = require('node:path');
const upload = path.join(process.env.ST_WORK_DIR, 'upload.txt');
fs.writeFileSync(upload, 'x');
const child = require('node:child_process').spawn(${JSON.stringify(chrome)}, ['--headless'], { stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'pipe'] });
const pipe = child.stdio[3];
let id = 0;
const send = (text) => {
  try {
    pipe.write(text);
    pipe.write('\\0');
    return 'sent';
  } catch (error) {
    return error.message;
  }
};
const command = (method, params) => send(JSON.stringify({ id: ++id, method, params }));
const results = [
  command('Page.navigate', { url: 'https://example.com/' }),
  command('Page.navigate', { url: 'file:///proc/1/environ' }),
  command('Target.createTarget', { url: 'FILE:///etc/passwd' }),
  command('Page.navigate', { url: 'view-source:file:///etc/passwd' }),
  command('Target.sendMessageToTarget', { targetId: 't1', message: JSON.stringify({ id: 1, method: 'Page.navigate', params: { url: 'file:///etc/passwd' } }) }),
  command('DOM.setFileInputFiles', { nodeId: 1, files: [upload] }),
  command('DOM.setFileInputFiles', { nodeId: 1, files: [upload, '/etc/passwd'] }),
  command('Input.dispatchDragEvent', { type: 'drop', x: 1, y: 1, data: { items: [], dragOperationsMask: 1, files: [path.join(process.env.ST_WORK_DIR, '..', 'token')] } }),
  send('{"id":99,"method":"Page.navigate","params":{"url":"file:///etc/passwd","url":"https://example.com/two"}}')
];
pipe.end();
child.on('close', () => console.log(JSON.stringify(results)));
`, { PLAYWRIGHT_BROWSERS_PATH: browsers }, [browsers]);
    assert.deepStrictEqual(JSON.parse(output), [
      'sent',
      FILE_URLS,
      FILE_URLS,
      'Browser checks on the agent cannot open view-source: URLs.',
      FILE_URLS,
      'sent',
      OUTSIDE_FILES,
      OUTSIDE_FILES,
      'sent'
    ]);
    const received = fs.readFileSync(path.join(work, 'cdp'), 'utf8').split('\0').filter(Boolean).map((text) => JSON.parse(text));
    assert.deepStrictEqual(received.map((message) => `${message.method} ${message.params.url ?? message.params.files.length}`), [
      'Page.navigate https://example.com/',
      'DOM.setFileInputFiles 1',
      'Page.navigate https://example.com/two'
    ]);
  } finally {
    fs.rmSync(browsers, { recursive: true, force: true });
  }
});
