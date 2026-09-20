// Vercel Build Output API: static dashboard plus an API proxy to Railway.
import { cp, mkdir, rm, writeFile } from "node:fs/promises";

const backend = new URL(process.env.BACKEND_URL || "missing:");
if (backend.protocol !== "https:" || !backend.hostname || backend.username ||
    backend.password || backend.pathname !== "/" || backend.search || backend.hash) {
  throw new Error("Set BACKEND_URL to your Railway HTTPS origin, e.g. https://example.up.railway.app");
}
const output = new URL("../.vercel/output/", import.meta.url);
await rm(output, { recursive: true, force: true });
await mkdir(output, { recursive: true });
await cp(new URL("../dashboard/", import.meta.url), new URL("static/", output), { recursive: true });
await cp(new URL("../results/investigation/EVIDENCE_REPORT.html", import.meta.url), new URL("static/final_htn26_report.html", output));
await writeFile(new URL("config.json", output), JSON.stringify({
  version: 3,
  routes: [
    { src: "/api/(.*)", dest: `${backend.origin}/api/$1` },
    { src: "/final_htn26_report/?", dest: "/final_htn26_report.html" },
    { handle: "filesystem" },
    { src: "/(?:analyze|models|investigations(?:/[a-zA-Z0-9_:.-]+)?)/?", dest: "/index.html" }
  ]
}, null, 2));
console.log("Built dashboard and Railway API proxy.");
