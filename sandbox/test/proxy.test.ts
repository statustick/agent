import { test, before, after } from 'node:test';
import assert from 'node:assert';
import http from 'node:http';
import net, { type AddressInfo } from 'node:net';
import { createProxy, EgressDenied, hostAllowed, portAllowed, parseAllowedHosts, isBlockedAddress } from '../proxy.mts';

let internalHits = 0;
const internal = http.createServer((req, res) => {
  internalHits++;
  res.end('internal');
});
const lookups: Record<string, string> = { 'app.example.com': '127.0.0.1', 'metadata.example.com': '169.254.169.254', 'fly.example.com': 'fdaa:0:1::3' };
const lookup = async (host: string) => [{ address: lookups[host] || '93.184.215.14', family: 4 }];
const proxy = createProxy({ allowed: parseAllowedHosts('example.com,*.example.com,127.0.0.1'), lookup });

before(async () => {
  await new Promise<void>((resolve) => internal.listen(0, '127.0.0.1', resolve));
  await new Promise<void>((resolve) => proxy.listen(0, '127.0.0.1', resolve));
});
after(() => {
  internal.close();
  proxy.close();
});

function connect(target: string, server: http.Server = proxy): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = net.connect((server.address() as AddressInfo).port, '127.0.0.1', () => socket.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`));
    socket.once('data', (data) => {
      socket.destroy();
      resolve(data.toString().split('\r\n')[0]!);
    });
    socket.on('error', reject);
  });
}

function get(url: string): Promise<{ status: number | undefined; body: string }> {
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port: (proxy.address() as AddressInfo).port, path: url, agent: false, headers: { host: new URL(url).host } }, (res) => {
      let body = '';
      res.on('data', (chunk: Buffer) => { body += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, body }));
    }).on('error', reject);
  });
}

test('should match allowed hosts exactly, by subdomain wildcard or by *', () => {
  const allowed = parseAllowedHosts('shop.example.com, *.cdn.net');
  assert.ok(hostAllowed('shop.example.com', allowed));
  assert.ok(hostAllowed('SHOP.example.com.', allowed));
  assert.ok(hostAllowed('img.cdn.net', allowed));
  assert.ok(!hostAllowed('cdn.net', allowed));
  assert.ok(!hostAllowed('evil-cdn.net', allowed));
  assert.ok(!hostAllowed('example.com', allowed));
  assert.ok(hostAllowed('anything.org', ['*']));
  assert.ok(!hostAllowed('example.com', []));
});

test('should refuse mail and other low ports', () => {
  assert.ok(portAllowed(443) && portAllowed(80) && portAllowed(8443));
  for (const port of [25, 465, 587, 22, 0, 70000]) assert.ok(!portAllowed(port), String(port));
});

test('should treat private, loopback, link-local, metadata and Fly private addresses as blocked', () => {
  for (const address of ['10.1.2.3', '127.0.0.1', '169.254.169.254', '172.16.0.1', '192.168.1.1', '100.64.0.1', '::1', 'fdaa:0:1::3', 'fe80::1', '::ffff:10.0.0.1', 'not-an-ip']) {
    assert.ok(isBlockedAddress(address), address);
  }
  assert.ok(!isBlockedAddress('93.184.215.14'));
  assert.ok(!isBlockedAddress('2606:4700::1111'));
});

test('should refuse a CONNECT to a host that is not allowed', async () => {
  assert.match(await connect('other.org:443'), /^HTTP\/1\.1 403/);
});

test('should refuse a CONNECT to an allowed host that resolves to an internal address', async () => {
  assert.match(await connect('app.example.com:443'), /^HTTP\/1\.1 403/);
  assert.match(await connect('metadata.example.com:443'), /^HTTP\/1\.1 403/);
  assert.match(await connect('fly.example.com:443'), /^HTTP\/1\.1 403/);
});

test('should refuse a loopback address even when it is listed', async () => {
  assert.match(await connect(`127.0.0.1:${(internal.address() as AddressInfo).port}`), /^HTTP\/1\.1 403/);
  const response = await get(`http://127.0.0.1:${(internal.address() as AddressInfo).port}/`);
  assert.strictEqual(response.status, 403);
  assert.strictEqual(internalHits, 0);
});

test('should refuse an SMTP port on an allowed host', async () => {
  assert.match(await connect('example.com:25'), /^HTTP\/1\.1 403/);
});

test('should refuse a plain HTTP request to a host that is not allowed', async () => {
  const response = await get('http://other.org/');
  assert.strictEqual(response.status, 403);
  assert.match(response.body, /other\.org is not an allowed host/);
});

test('should use a given resolve instead of the allowed hosts and public-address rule, as the agent does', async () => {
  const policy = createProxy({
    resolve: async (host) => {
      if (host !== '127.0.0.1') throw new EgressDenied(`${host} is refused by the policy`);
      return host;
    }
  });
  await new Promise<void>((resolve) => policy.listen(0, '127.0.0.1', resolve));
  try {
    assert.match(await connect(`127.0.0.1:${(internal.address() as AddressInfo).port}`, policy), /^HTTP\/1\.1 200/);
    assert.match(await connect('example.com:443', policy), /^HTTP\/1\.1 403/);
    assert.match(await connect('127.0.0.1:25', policy), /^HTTP\/1\.1 403/);
  } finally {
    policy.closeAllConnections();
    policy.close();
  }
});
