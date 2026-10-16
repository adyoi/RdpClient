// Logging TCP proxy: captures the exact bytes a real RDP client sends.
// Usage: node rdp-tap.mjs <listenPort> <targetPort> <logFile>
import net from "node:net";
import { appendFileSync, writeFileSync } from "node:fs";

const listenPort = Number(process.argv[2] ?? 3390);
const targetPort = Number(process.argv[3] ?? 3389);
const logFile = process.argv[4] ?? "rdp-tap.log";

writeFileSync(logFile, "");
const log = (tag, data) => {
  const hex = Buffer.from(data).toString("hex").replace(/(..)/g, "$1 ").trim();
  appendFileSync(logFile, `${tag} [${data.length}]\n${hex}\n\n`);
};

const server = net.createServer((client) => {
  const upstream = net.connect({ host: "127.0.0.1", port: targetPort });
  client.on("data", (d) => { log("C->S", d); upstream.write(d); });
  upstream.on("data", (d) => { log("S->C", d); client.write(d); });
  client.on("error", () => upstream.destroy());
  upstream.on("error", () => client.destroy());
  client.on("close", () => upstream.end());
  upstream.on("close", () => client.end());
});

server.listen(listenPort, "127.0.0.1", () => {
  console.log(`tap listening on 127.0.0.1:${listenPort} -> 127.0.0.1:${targetPort}, logging to ${logFile}`);
});