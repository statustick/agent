// Egress proxy for one run: only the check's allowed hosts, only public addresses (the SSRF rules of the drone).
import http from 'node:http';
import net from 'node:net';
import dns from 'node:dns';

type Lookup = (host: string, options: { all: true }) => Promise<{ address: string }[]>;
/** The address to connect to for a host; throws EgressDenied when the run may not reach it. */
export type Resolve = (host: string) => Promise<string>;

const blocked = new net.BlockList();
([
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['224.0.0.0', 4],
  ['240.0.0.0', 4]
] as const).forEach(([address, prefix]) => blocked.addSubnet(address, prefix, 'ipv4'));
([
  ['::', 128], ['::1', 128], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8]
] as const).forEach(([address, prefix]) => blocked.addSubnet(address, prefix, 'ipv6'));

const IDLE_TIMEOUT_MS = 60_000;

export class EgressDenied extends Error {}

export function isBlockedAddress(address: string): boolean {
  const mapped = address.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (mapped) return blocked.check(mapped[1]!, 'ipv4');
  const family = net.isIP(address);
  if (family === 0) return true;
  return blocked.check(address, family === 4 ? 'ipv4' : 'ipv6');
}

/** ST_ALLOWED_HOSTS: comma-separated hosts; `*.example.com` covers subdomains, `*` any public host. */
export function parseAllowedHosts(value: string | undefined): string[] {
  return (value || '').split(',').map((host) => host.trim().toLowerCase()).filter(Boolean);
}

export function hostAllowed(host: string, allowed: string[]): boolean {
  const name = host.toLowerCase().replace(/\.$/, '');
  return allowed.some((pattern) =>
    pattern === '*' || pattern === name || (pattern.startsWith('*.') && name.endsWith(pattern.slice(1))));
}

// No SMTP and other well-known service ports below 1024, so a run cannot send mail or probe services.
export function portAllowed(port: number): boolean {
  return port === 80 || port === 443 || (port >= 1024 && port <= 65535);
}

async function resolvePublic(host: string, lookup: Lookup): Promise<string> {
  const bare = host.replace(/^\[|\]$/g, '');
  const addresses = net.isIP(bare) ? [{ address: bare }] : await lookup(bare, { all: true });
  if (addresses.length === 0 || addresses.some(({ address }) => isBlockedAddress(address))) {
    throw new EgressDenied(`${bare} resolves to a private or internal address`);
  }
  return addresses[0]!.address;
}

function allowedPublicHost(allowed: string[], lookup: Lookup): Resolve {
  return async (host) => {
    if (!hostAllowed(host, allowed)) throw new EgressDenied(`${host} is not an allowed host for this check`);
    return resolvePublic(host, lookup);
  };
}

async function target(host: string, port: number, resolve: Resolve): Promise<string> {
  if (!portAllowed(port)) throw new EgressDenied(`port ${port} is not allowed`);
  return resolve(host.replace(/^\[|\]$/g, ''));
}

/** `resolve` replaces the allowed hosts and public-address rule; the agent passes its own target policy. */
export function createProxy({ allowed = [], lookup = dns.promises.lookup, resolve = allowedPublicHost(allowed, lookup), log = () => {} }: { allowed?: string[]; lookup?: Lookup; resolve?: Resolve; log?: (line: string) => void }): http.Server {
  const server = http.createServer(async (req, res) => {
    let url;
    try {
      url = new URL(req.url!);
      if (url.protocol !== 'http:') throw new EgressDenied('only http:// URLs can go through without CONNECT');
      const port = Number(url.port || 80);
      const address = await target(url.hostname, port, resolve);
      const headers: http.OutgoingHttpHeaders = { ...req.headers, host: url.host };
      delete headers['proxy-connection'];
      delete headers['proxy-authorization'];
      const upstream = http.request({ host: address, port, method: req.method, path: `${url.pathname}${url.search}`, headers }, (response) => {
        res.writeHead(response.statusCode!, response.headers);
        response.pipe(res);
      });
      upstream.setTimeout(IDLE_TIMEOUT_MS, () => upstream.destroy());
      upstream.on('error', () => res.headersSent ? res.destroy() : res.writeHead(502).end());
      req.pipe(upstream);
    } catch (error) {
      const denied = error instanceof EgressDenied;
      log(`egress ${denied ? 'denied' : 'failed'}: ${(error as Error).message}`);
      res.writeHead(denied ? 403 : 502, { 'content-type': 'text/plain' }).end(`Blocked by StatusTick: ${denied ? error.message : 'upstream failed'}\n`);
    }
  });

  server.on('connect', async (req: http.IncomingMessage, client: net.Socket, head: Buffer) => {
    client.on('error', () => {});
    try {
      const authority = String(req.url).match(/^(\[[^\]]+\]|[^:/\s]+):(\d{1,5})$/);
      if (!authority) throw new EgressDenied('CONNECT needs host:port');
      const port = Number(authority[2]);
      const address = await target(authority[1]!, port, resolve);
      const upstream = net.connect(port, address, () => {
        client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (head && head.length) upstream.write(head);
        upstream.pipe(client);
        client.pipe(upstream);
      });
      upstream.setTimeout(IDLE_TIMEOUT_MS, () => upstream.destroy());
      upstream.on('error', () => client.destroy());
      client.on('close', () => upstream.destroy());
    } catch (error) {
      const denied = error instanceof EgressDenied;
      log(`egress ${denied ? 'denied' : 'failed'}: ${(error as Error).message}`);
      client.end(`HTTP/1.1 ${denied ? '403 Forbidden' : '502 Bad Gateway'}\r\n\r\n`);
    }
  });

  return server;
}

if (import.meta.main) {
  const allowed = parseAllowedHosts(process.env.ST_ALLOWED_HOSTS);
  createProxy({ allowed, log: (line) => process.stderr.write(`${line}\n`) })
    .listen(3128, process.env.ST_PROXY_LISTEN || '0.0.0.0');
}
