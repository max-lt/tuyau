// Tuyau wire protocol: length-delimited CBOR frames, matching the Rust
// `tuyau-protocol` crate exactly.
//
//   frame = [u32 big-endian payload length][CBOR payload]
//   ALPN  = "tuyau/1"
//   MAX_FRAME_SIZE = 64 KiB
//
// Hello (client → server, first client-opened bidi stream):
//   CBOR map { token: bstr(32), client_name: tstr }
// HelloResponse (server → client, same stream):
//   "Welcome"  |  { Reject: { reason: tstr } }
// DataStreamHeader (server → client, first frame of each server-opened stream):
//   CBOR map { hostname: tstr, peer_addr: tstr, mode: "terminated" | "passthrough" }

import { Encoder } from "cbor-x";

export const ALPN = "tuyau/1";
export const MAX_FRAME_SIZE = 64 * 1024;
const LEN_PREFIX = 4;

// useRecords:false → plain CBOR maps (no cbor-x record tags); Node Buffers
// encode as byte strings (major type 2), matching serde's `serialize_bytes`.
const cbor = new Encoder({ useRecords: false, tagUint8Array: false });

export interface Hello {
  token: Uint8Array; // exactly 32 bytes
  client_name: string;
}

export type HelloResponse = "Welcome" | { Reject: { reason: string } };

export interface DataStreamHeader {
  hostname: string;
  peer_addr: string;
  mode: "terminated" | "passthrough";
}

/** Encode a value as a single length-delimited CBOR frame. */
export function encodeFrame(value: unknown): Uint8Array {
  const payload = cbor.encode(value);

  if (payload.length > MAX_FRAME_SIZE) {
    throw new Error(
      `tuyau: frame too large (${payload.length} > ${MAX_FRAME_SIZE})`,
    );
  }

  const out = new Uint8Array(LEN_PREFIX + payload.length);
  new DataView(out.buffer).setUint32(0, payload.length, false); // big-endian
  out.set(payload, LEN_PREFIX);
  return out;
}

export function encodeHello(h: Hello): Uint8Array {
  // Pass token as a Node Buffer so cbor-x emits a bare CBOR byte string.
  return encodeFrame({
    token: Buffer.from(h.token),
    client_name: h.client_name,
  });
}

/**
 * Pull one length-delimited frame off a Web `ReadableStream` reader, decode its
 * CBOR payload, and hand back any bytes that arrived after the frame so the
 * caller can forward them (the data stream is framed-header-then-raw-bytes).
 */
export async function readFrame(
  reader: ReadableStreamDefaultReader<Uint8Array>,
): Promise<{ value: unknown; leftover: Uint8Array }> {
  let buf = new Uint8Array(0);

  const pull = async (): Promise<void> => {
    const { value, done } = await reader.read();
    if (done) throw new Error("tuyau: stream ended before a full frame");
    const next = new Uint8Array(buf.length + value.length);
    next.set(buf);
    next.set(value, buf.length);
    buf = next;
  };

  while (buf.length < LEN_PREFIX) await pull();

  const len = new DataView(buf.buffer, buf.byteOffset, LEN_PREFIX).getUint32(
    0,
    false,
  );
  if (len > MAX_FRAME_SIZE) throw new Error(`tuyau: oversized frame (${len})`);

  while (buf.length < LEN_PREFIX + len) await pull();

  const payload = buf.subarray(LEN_PREFIX, LEN_PREFIX + len);
  const value = cbor.decode(payload);
  const leftover = buf.subarray(LEN_PREFIX + len);
  return { value, leftover };
}
