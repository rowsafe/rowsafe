// The npm wrapper against a fake release served on 127.0.0.1: it downloads
// the binary for this computer, checks it against SHA256SUMS, caches it,
// passes arguments, stdout and the exit code through, and refuses a binary
// that doesn't match. Needs Go to build the stand-in CLI.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { execFileSync, spawn } = require("node:child_process");

const { asset, sumFor } = require("../bin/rowsafe.js");

const WRAPPER = path.join(__dirname, "..", "bin", "rowsafe.js");
const VERSION = "9.8.7";

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "rowsafe-npm-"));
const release = path.join(tmp, "release", `v${VERSION}`);
fs.mkdirSync(release, { recursive: true });
const file = asset();
execFileSync("go", ["build", "-o", path.join(release, file), path.join(__dirname, "testdata", "fake", "main.go")], {
  env: { ...process.env, CGO_ENABLED: "0", GOWORK: "off" },
  stdio: "inherit",
});
const binary = fs.readFileSync(path.join(release, file));
const sha = crypto.createHash("sha256").update(binary).digest("hex");
fs.writeFileSync(path.join(release, "SHA256SUMS"), `${"0".repeat(64)}  rowsafe-other\n${sha}  ${file}\n`);

let requests = [];
let tamper = false;
const server = http.createServer((req, res) => {
  requests.push(req.url);
  const p = path.join(tmp, "release", decodeURIComponent(req.url));
  if (!p.startsWith(path.join(tmp, "release")) || !fs.existsSync(p)) {
    res.writeHead(404).end();
    return;
  }
  let body = fs.readFileSync(p);
  if (tamper && p.endsWith(file)) body = Buffer.concat([body, Buffer.from("x")]);
  res.writeHead(200).end(body);
});

let base;
test.before(async () => {
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${server.address().port}`;
});
test.after(() => {
  server.close();
  fs.rmSync(tmp, { recursive: true, force: true });
});

// exec runs a wrapper without blocking: the fake release is served from
// this same process.
function exec(script, args, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [script, ...args], { env });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("error", reject);
    child.on("close", (status) => resolve({ status, stdout, stderr }));
  });
}

function run(args, env = {}) {
  return exec(WRAPPER, args, { ...process.env, ROWSAFE_DOWNLOAD_BASE: base, ROWSAFE_VERSION: VERSION, ...env });
}

test("asset names match the release", () => {
  assert.equal(asset("linux", "x64"), "rowsafe-linux-amd64");
  assert.equal(asset("darwin", "arm64"), "rowsafe-darwin-arm64");
  assert.equal(asset("win32", "x64"), "rowsafe-windows-amd64.exe");
  assert.equal(asset("win32", "arm64"), "rowsafe-windows-arm64.exe");
});

test("SHA256SUMS lines, text and binary mode", () => {
  const a = "a".repeat(64);
  assert.equal(sumFor(`${a}  rowsafe-linux-amd64\n`, "rowsafe-linux-amd64"), a);
  assert.equal(sumFor(`${a} *rowsafe-linux-amd64\r\n`, "rowsafe-linux-amd64"), a);
  assert.equal(sumFor(`${a}  rowsafe-linux-amd64.sig\n`, "rowsafe-linux-amd64"), "");
});

test("downloads, checks, caches and runs the CLI", async () => {
  const cache = path.join(tmp, "cache-ok");
  requests = [];
  const r = await run(["pulse", "postgres://u@h/db", "--json"], { ROWSAFE_CACHE_DIR: cache, ROWSAFE_FAKE_EXIT: "3" });
  assert.equal(r.status, 3, r.stderr);
  assert.deepEqual(JSON.parse(r.stdout), ["pulse", "postgres://u@h/db", "--json"]);
  assert.match(r.stderr, /Downloading rowsafe 9\.8\.7/);
  assert.deepEqual(requests, [`/v${VERSION}/SHA256SUMS`, `/v${VERSION}/${file}`]);

  // Second run: from the cache, nothing downloaded, nothing on stderr.
  requests = [];
  const again = await run(["version"], { ROWSAFE_CACHE_DIR: cache });
  assert.equal(again.status, 0, again.stderr);
  assert.deepEqual(JSON.parse(again.stdout), ["version"]);
  assert.equal(again.stderr, "");
  assert.deepEqual(requests, []);
});

test("refuses a binary that doesn't match SHA256SUMS and saves nothing", async () => {
  const cache = path.join(tmp, "cache-bad");
  tamper = true;
  try {
    const r = await run(["version"], { ROWSAFE_CACHE_DIR: cache });
    assert.equal(r.status, 1);
    assert.match(r.stderr, /doesn't match the release's SHA256SUMS/);
    assert.equal(r.stdout, "");
    assert.deepEqual(fs.existsSync(path.join(cache, VERSION)) ? fs.readdirSync(path.join(cache, VERSION)) : [], []);
  } finally {
    tamper = false;
  }
});

test("a version that isn't released says so", async () => {
  const r = await run(["version"], { ROWSAFE_CACHE_DIR: path.join(tmp, "cache-missing"), ROWSAFE_VERSION: "1.2.3" });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /couldn't download the SHA256SUMS of rowsafe 1\.2\.3/);
});

test("a published package checks against its own SHA256SUMS", async () => {
  // As the release workflow publishes it: the package's version is the
  // release's, and the release's SHA256SUMS is in the package.
  const pkg = path.join(tmp, "pkg");
  fs.mkdirSync(path.join(pkg, "bin"), { recursive: true });
  fs.copyFileSync(WRAPPER, path.join(pkg, "bin", "rowsafe.js"));
  const meta = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "package.json"), "utf8"));
  fs.writeFileSync(path.join(pkg, "package.json"), JSON.stringify({ ...meta, version: VERSION }));
  fs.copyFileSync(path.join(release, "SHA256SUMS"), path.join(pkg, "SHA256SUMS"));

  requests = [];
  const env = { ...process.env, ROWSAFE_DOWNLOAD_BASE: base, ROWSAFE_CACHE_DIR: path.join(tmp, "cache-pkg") };
  delete env.ROWSAFE_VERSION;
  const r = await exec(path.join(pkg, "bin", "rowsafe.js"), ["status"], env);
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(JSON.parse(r.stdout), ["status"]);
  assert.deepEqual(requests, [`/v${VERSION}/${file}`]);

  // A SHA256SUMS in the package that disagrees with the download wins.
  fs.writeFileSync(path.join(pkg, "SHA256SUMS"), `${"f".repeat(64)}  ${file}\n`);
  const bad = await exec(path.join(pkg, "bin", "rowsafe.js"), ["status"], {
    ...env,
    ROWSAFE_CACHE_DIR: path.join(tmp, "cache-pkg-bad"),
  });
  assert.equal(bad.status, 1);
  assert.match(bad.stderr, /doesn't match/);
});
