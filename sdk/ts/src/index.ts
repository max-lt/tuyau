import net from "node:net";
import os from "node:os";
import { webcrypto } from "node:crypto";
import { QUICClient, QUICStream, native, events } from "@matrixai/quic";
import {
  ALPN,
  encodeHello,
  readFrame,
  type DataStreamHeader,
  type HelloResponse,
} from "./protocol.js";

export interface TuyauOptions {
  /** host:port of the tuyau-server QUIC tunnel listener. */
  server: string;
  /** Pinned SHA-256 fingerprint of the server's tunnel cert (64 hex chars). */
  fingerprint: string;
  /** 64-hex-char pre-shared token, or the raw 32 bytes. */
  token: string | Uint8Array;
  /** `{ "alpha.example.com": "127.0.0.1:8080" }` — at least one entry. */
  ingress: Record<string, string>;
  /** Informational name shown in server logs. Defaults to the OS hostname. */
  clientName?: string;
  /** Receives human-readable progress lines. */
  onLog?: (msg: string) => void;
}

function hexToBytes(hex: string, label: string): Uint8Array {
  const clean = hex.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(clean)) {
    throw new Error(`tuyau: ${label} must be 64 hex chars, got ${clean.length}`);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function splitAddr(addr: string): { host: string; port: number } {
  // Supports host:port and [::1]:port.
  const m = addr.match(/^\[(.+)\]:(\d+)$/) ?? addr.match(/^(.+):(\d+)$/);
  if (!m) throw new Error(`tuyau: invalid address '${addr}', expected host:port`);
  return { host: m[1], port: Number(m[2]) };
}

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** A live tunnel. The configured ingress is already being served. */
export class TunnelClient {
  private constructor(
    private readonly client: QUICClient,
    /** Resolves when the tunnel connection ends (any reason). */
    readonly closed: Promise<void>,
  ) {}

  static async connect(opts: TuyauOptions): Promise<TunnelClient> {
    const log = opts.onLog ?? (() => {});
    const { host, port } = splitAddr(opts.server);
    const token = typeof opts.token === "string" ? hexToBytes(opts.token, "token") : opts.token;
    const expectedFp = hexToBytes(opts.fingerprint, "fingerprint");
    const ingress = opts.ingress;

    if (Object.keys(ingress).length === 0) {
      throw new Error("tuyau: `ingress` needs at least one host=local_addr entry");
    }

    // Pin the self-signed tunnel cert by SHA-256 — no PKI, like the Rust client.
    const verifyCallback = async (
      certs: Array<Uint8Array>,
    ): Promise<native.CryptoError | undefined> => {
      if (certs.length === 0) return native.CryptoError.BadCertificate;
      const digest = new Uint8Array(await webcrypto.subtle.digest("SHA-256", certs[0]));
      if (timingSafeEqual(digest, expectedFp)) return undefined; // accept
      log("tuyau: server cert fingerprint mismatch — refusing");
      return native.CryptoError.BadCertificate; // reject
    };

    log(`connecting to ${opts.server}`);
    const client = await QUICClient.createQUICClient({
      host,
      port,
      serverName: host,
      crypto: {
        ops: {
          async randomBytes(data: ArrayBuffer) {
            const view = new Uint8Array(data);
            for (let i = 0; i < view.length; i += 65536) {
              webcrypto.getRandomValues(view.subarray(i, Math.min(i + 65536, view.length)));
            }
          },
        },
      },
      config: {
        verifyPeer: true,
        verifyCallback,
        applicationProtos: [ALPN],
        maxIdleTimeout: 60_000, // server uses 60s
        keepAliveIntervalTime: 15_000, // server uses 15s
      },
    });

    // Wire up the data plane before the handshake so no server-opened stream is
    // missed once we're Welcome'd.
    client.connection.addEventListener(
      events.EventQUICConnectionStream.name,
      (evt: Event) => {
        const stream = (evt as InstanceType<typeof events.EventQUICConnectionStream>).detail;
        handleDataStream(stream, ingress, log).catch((e) =>
          log(`data stream error: ${e?.message ?? e}`),
        );
      },
    );

    // Handshake on the first client-opened bidi stream.
    const clientName = opts.clientName ?? os.hostname();
    const hello = client.connection.newStream("bidi");
    const writer = hello.writable.getWriter();
    await writer.write(encodeHello({ token, client_name: clientName }));

    const reader = hello.readable.getReader();
    const { value } = await readFrame(reader);
    const resp = value as HelloResponse;

    if (resp !== "Welcome") {
      const reason =
        typeof resp === "object" && resp?.Reject ? resp.Reject.reason : JSON.stringify(resp);
      await client.destroy({ force: true }).catch(() => {});
      throw new Error(`tuyau: server rejected connection: ${reason}`);
    }

    log("connected, serving ingress");
    return new TunnelClient(client, client.closedP);
  }

  async close(): Promise<void> {
    await this.client.destroy({ force: true });
  }
}

/** Read the framed header, then splice the QUIC stream to a local TCP socket. */
async function handleDataStream(
  stream: QUICStream,
  ingress: Record<string, string>,
  log: (m: string) => void,
): Promise<void> {
  const reader = stream.readable.getReader();
  const { value, leftover } = await readFrame(reader);
  const header = value as DataStreamHeader;

  const local = ingress[header.hostname];
  if (!local) {
    log(`no ingress for '${header.hostname}', dropping stream`);
    await reader.cancel().catch(() => {});
    return;
  }

  const { host, port } = splitAddr(local);
  const tcp = net.connect({ host, port });
  const writer = stream.writable.getWriter();

  // QUIC → TCP (forward any bytes that rode in after the header first).
  if (leftover.length > 0) tcp.write(leftover);
  (async () => {
    try {
      for (;;) {
        const { value: chunk, done } = await reader.read();
        if (done) break;
        tcp.write(chunk);
      }
    } catch {
      /* stream torn down */
    }
    tcp.end();
  })();

  // TCP → QUIC
  tcp.on("data", (d) => {
    writer.write(d).catch(() => {});
  });
  tcp.on("end", () => {
    writer.close().catch(() => {});
  });
  tcp.on("error", () => {
    writer.abort?.().catch(() => {});
    reader.cancel().catch(() => {});
  });
}

/** Shorthand for {@link TunnelClient.connect}. */
export function connect(opts: TuyauOptions): Promise<TunnelClient> {
  return TunnelClient.connect(opts);
}
