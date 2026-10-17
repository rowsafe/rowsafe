#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// `npx rowsafe ...` / `npm i -g rowsafe`: runs the rowsafe CLI.
//
// On first use it downloads the CLI for this computer from the GitHub release
// of the same version as this package, checks it against the release's
// SHA256SUMS (the copy in this package, written at publish time, or the
// release's own when the package has none), keeps it in a cache, and runs it.
// Nothing runs at install time. Messages go to stderr only, so stdout stays
// the CLI's (--json, `rowsafe mcp` over stdio).
//
// Environment:
//   ROWSAFE_VERSION        run this version instead of the package's
//   ROWSAFE_CACHE_DIR      cache folder (default: the OS's user cache folder)
//   ROWSAFE_DOWNLOAD_BASE  where releases are (tests serve a fake one)
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");

const REPO = "rowsafe/rowsafe";
const PKG = require("../package.json");

function die(msg) {
  process.stderr.write(`rowsafe: ${msg}\n`);
  process.exit(1);
}

// asset is the release file for this computer, as the release names it.
function asset(platform = process.platform, arch = process.arch) {
  const goos = { darwin: "darwin", linux: "linux", win32: "windows" }[platform];
  const goarch = { x64: "amd64", arm64: "arm64" }[arch];
  if (!goos) die(`the rowsafe CLI runs on macOS, Linux and Windows (this is ${platform})`);
  if (!goarch) die(`the rowsafe CLI is built for x86-64 and ARM64 (this is ${arch})`);
  return `rowsafe-${goos}-${goarch}${goos === "windows" ? ".exe" : ""}`;
}

function cacheRoot() {
  if (process.env.ROWSAFE_CACHE_DIR) return process.env.ROWSAFE_CACHE_DIR;
  const home = os.homedir();
  if (process.platform === "win32") {
    return path.join(process.env.LOCALAPPDATA || path.join(home, "AppData", "Local"), "rowsafe", "cache");
  }
  if (process.platform === "darwin") return path.join(home, "Library", "Caches", "rowsafe");
  return path.join(process.env.XDG_CACHE_HOME || path.join(home, ".cache"), "rowsafe");
}

// sumFor finds file's SHA-256 in a SHA256SUMS text ("<hex>  <name>", or
// "<hex> *<name>" for binary mode).
function sumFor(sums, file) {
  for (const line of sums.split(/\r?\n/)) {
    const m = line.match(/^([0-9a-f]{64}) [ *](.+)$/);
    if (m && m[2] === file) return m[1];
  }
  return "";
}

async function get(url) {
  let lastErr;
  for (let i = 0; i < 3; i++) {
    try {
      const res = await fetch(url, { redirect: "follow", signal: AbortSignal.timeout(300_000) });
      if (res.ok) return Buffer.from(await res.arrayBuffer());
      lastErr = new Error(`${url}: HTTP ${res.status}`);
      if (res.status === 404) break;
    } catch (err) {
      lastErr = err;
    }
    await new Promise((r) => setTimeout(r, 1000 * (i + 1)));
  }
  throw lastErr;
}

async function ensureBinary(version) {
  const file = asset();
  const dir = path.join(cacheRoot(), version);
  const bin = path.join(dir, process.platform === "win32" ? "rowsafe.exe" : "rowsafe");
  if (fs.existsSync(bin)) return bin;

  const base = (process.env.ROWSAFE_DOWNLOAD_BASE || `https://github.com/${REPO}/releases/download`).replace(/\/+$/, "");
  let sums = "";
  const bundled = path.join(__dirname, "..", "SHA256SUMS");
  if (version === PKG.version && fs.existsSync(bundled)) {
    sums = fs.readFileSync(bundled, "utf8");
  } else {
    try {
      sums = (await get(`${base}/v${version}/SHA256SUMS`)).toString("utf8");
    } catch (err) {
      die(`couldn't download the SHA256SUMS of rowsafe ${version} (${err.message}). Is ${version} a release? See https://github.com/${REPO}/releases`);
    }
  }
  const want = sumFor(sums, file);
  if (!want) die(`${file} isn't in the SHA256SUMS of rowsafe ${version}: this release has no CLI for this computer`);

  process.stderr.write(`Downloading rowsafe ${version} for this computer (first run only)...\n`);
  let data;
  try {
    data = await get(`${base}/v${version}/${file}`);
  } catch (err) {
    die(`couldn't download ${file} (${err.message})`);
  }
  const got = crypto.createHash("sha256").update(data).digest("hex");
  if (got !== want) die(`the download doesn't match the release's SHA256SUMS (got ${got}, want ${want}); nothing was saved`);

  // Write next to the final name, then rename: a second run started at the
  // same time never sees half a file.
  fs.mkdirSync(dir, { recursive: true });
  const tmp = `${bin}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, data, { mode: 0o755 });
  try {
    fs.renameSync(tmp, bin);
  } catch (err) {
    fs.rmSync(tmp, { force: true });
    if (!fs.existsSync(bin)) throw err; // another run won the race otherwise
  }
  return bin;
}

async function main() {
  const version = (process.env.ROWSAFE_VERSION || PKG.version).replace(/^v/, "");
  if (!/^\d+\.\d+\.\d+$/.test(version)) {
    die(`${version} isn't a release version (want MAJOR.MINOR.PATCH)`);
  }
  const bin = await ensureBinary(version);
  const child = spawn(bin, process.argv.slice(2), { stdio: "inherit", windowsHide: false });
  // The terminal sends Ctrl-C to the whole group; the CLI handles it. Other
  // signals sent to this wrapper are passed on.
  for (const sig of ["SIGTERM", "SIGHUP"]) {
    process.on(sig, () => child.kill(sig));
  }
  process.on("SIGINT", () => {});
  child.on("error", (err) => die(`couldn't run ${bin}: ${err.message}`));
  child.on("exit", (code, signal) => {
    if (signal) {
      process.removeAllListeners(signal);
      process.kill(process.pid, signal);
      return;
    }
    process.exit(code ?? 1);
  });
}

if (require.main === module) {
  main().catch((err) => die(err.message));
}

module.exports = { asset, sumFor, cacheRoot };
