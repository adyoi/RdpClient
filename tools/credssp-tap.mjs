// TLS-terminating man-in-the-middle for RDP CredSSP.
//
// RDP negotiates in cleartext and only then starts TLS, so the proxy forwards
// the X.224 exchange verbatim, upgrades both sides to TLS once the
// RDP_NEG_RSP has passed through, and from that point logs plaintext in both
// directions. That is how the real SPNEGO tokens are obtained: they are inside
// TLS, which no external tap can see.
import net from "node:net";
import tls from "node:tls";
import { appendFileSync, writeFileSync, readFileSync } from "node:fs";

const LISTEN_PORT = Number(process.argv[2] ?? 3390);
const TARGET_PORT = Number(process.argv[3] ?? 3389);
const LOG = process.argv[4] ?? "credssp-tap.log";
const PFX = process.argv[5] ?? "tap-cert.pfx";
const CERT_PEM = process.argv[5] ?? "tap-cert.pem";
const KEY_PEM = process.argv[6] ?? "tap-key.pem";

const key = readFileSync(KEY_PEM);
const cert = readFileSync(CERT_PEM);
writeFileSync(LOG, "");
console.log(`using cert ${CERT_PEM} and key ${KEY_PEM}`);

function hex(d) {
  return Buffer.from(d).toString("hex").replace(/(..)/g, "$1 ").trim();
}

function logC2S(data) {
  appendFileSync(LOG, `\n=== C->S (${data.length} bytes) ===\n${hex(data)}\n`);
}

function logS2C(data) {
  appendFileSync(LOG, `\n=== S->C (${data.length} bytes) ===\n${hex(data)}\n`);
}

const server = net.createServer((client) => {
  const upstream = net.connect({ host: "127.0.0.1", port: TARGET_PORT });
  let upgraded = false;

  upstream.on("connect", () => console.log(`upstream connected to ${TARGET_PORT}`));

  // Cleartext phase: relay until the server's RDP_NEG_RSP has been forwarded.
  client.on("data", (chunk) => {
    if (upgraded) return;
    logC2S(chunk);
    upstream.write(chunk);
  });

  upstream.on("data", (chunk) => {
    if (upgraded) return;
    logS2C(chunk);
    client.write(chunk);

    // X.224 Connection Confirm (0xd0) carrying RDP_NEG_RSP (0x02) means the
    // client will start TLS next.
    if (chunk.includes(0xd0) && chunk.includes(0x02)) {
      upgraded = true;
      console.log("negotiation done; upgrading both sides to TLS");
      startTls(client, upstream);
    }
  });

  client.on("error", () => upstream.destroy());
  upstream.on("error", () => client.destroy());
});

function startTls(client, upstream) {
  client.removeAllListeners("data");
  upstream.removeAllListeners("data");

  const clientTls = new tls.TLSSocket(client, {
    isServer: true,
    key,
    cert,
    minVersion: "TLSv1.2",
  });

  const serverTls = tls.connect(
    {
      host: "127.0.0.1",
      port: TARGET_PORT,
      rejectUnauthorized: false,
      minVersion: "TLSv1.2",
      servername: process.env.TAP_SNI,
    },
    () => console.log(`outbound TLS established (${serverTls.getProtocol()})`),
  );

  clientTls.on("secure", () => console.log(`client TLS established (${clientTls.getProtocol()})`));
  serverTls.on("secure", () => console.log("outbound TLS secure"));

  clientTls.on("data", (d) => {
    logC2S(d);
    serverTls.write(d);
  });
  serverTls.on("data", (d) => {
    logS2C(d);
    clientTls.write(d);
  });

  clientTls.on("error", (e) => console.log(`client TLS error: ${e.message}`));
  serverTls.on("error", (e) => console.log(`server TLS error: ${e.message}`));
  clientTls.on("close", () => console.log("client TLS closed"));
  serverTls.on("close", () => console.log("server TLS closed"));
}

// Listen on every interface: mstsc resolves the machine name to its LAN
// address, so binding only to loopback would be unreachable for the client.
server.listen(LISTEN_PORT, () => {
  console.log(`CredSSP tap on :${LISTEN_PORT} -> 127.0.0.1:${TARGET_PORT}, log ${LOG}`);
});