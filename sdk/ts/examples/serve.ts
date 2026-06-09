// Single Node process: serves the HTTPS app AND opens the tuyau tunnel via the
// SDK — no second process, no Rust binary.
// Run: node examples/serve.ts   (after `bun run build`)
//
// Matching server side (server.toml on the tuyau-server). `passthrough` is what
// lets this app present its own LE cert end-to-end — the server never decrypts:
//
//   listen_addr        = "0.0.0.0:4433"   # QUIC tunnel (TUYAU_SERVER points here)
//   public_listen_addr = "0.0.0.0:443"    # public TLS
//
//   [[clients]]
//   name  = "service-a"
//   token = "<TUYAU_TOKEN, openssl rand -hex 32>"
//
//   [[hostnames]]
//   host      = "your.example.com"        # == TUYAU_HOSTNAME
//   client    = "service-a"
//   tls_mode  = "passthrough"             # app terminates TLS; omit/="terminated" to let the server do it
//
// The server prints its tunnel-cert SHA-256 at startup -> that's TUYAU_FINGERPRINT.
import https from "node:https";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { connect } from "../dist/index.js";

// Load sdk/ts/.env (next to this package), if present.
try {
  process.loadEnvFile(fileURLToPath(new URL("../.env", import.meta.url)));
} catch {
  /* no .env — rely on the ambient environment */
}

function reqEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`tuyau: missing env var ${name} (copy .env.example to .env)`);
  return v;
}

// 1. The local app (terminates TLS itself, since the tunnel is passthrough).
const server = https.createServer(
  {
    cert: readFileSync("/tmp/fullchain1.pem"),
    key: readFileSync("/tmp/privkey1.pem"),
  },
  (req, res) => {
    res.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
    res.end(`Hello from tuyau PASSTHROUGH + SDK 🔒\npath: ${req.url}\n`);
  },
);
await new Promise<void>((r) => server.listen(5173, "127.0.0.1", r));
console.log("[app] https on 127.0.0.1:5173");

// 2. The tunnel, in the same process.
const tunnel = await connect({
  server: reqEnv("TUYAU_SERVER"),
  fingerprint: reqEnv("TUYAU_FINGERPRINT"),
  token: reqEnv("TUYAU_TOKEN"),
  ingress: { [reqEnv("TUYAU_HOSTNAME")]: "127.0.0.1:5173" },
  onLog: (m) => console.log(`[tuyau] ${m}`),
});

console.log("[serve] app + tunnel up in one process — Ctrl-C to stop");
process.on("SIGINT", () => {
  tunnel.close().finally(() => server.close(() => process.exit(0)));
});

await tunnel.closed;
console.log("[serve] tunnel closed");
