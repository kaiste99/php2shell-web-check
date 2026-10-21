"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { fetchTarget, validateTarget, parseInputUrl, DEFAULTS } = require("../server/fetch");
const { isBlockedAddress, guardedLookup } = require("../server/ssrf");
const { createServer } = require("../server/index");
const { main } = require("../bin/check");

// ---------------------------------------------------------------- fake targets

function listen(handler) {
	return new Promise((resolve) => {
		const srv = http.createServer(handler);
		srv.listen(0, "127.0.0.1", () => resolve({ srv, port: srv.address().port, url: `http://127.0.0.1:${srv.address().port}/` }));
	});
}

let php, redirect, toMetadata, toLocalhostName, toLoopback, loop, slow, big, slowBody, targets;

test.before(async () => {
	php = await listen((req, res) => {
		res.writeHead(200, { "Content-Type": "text/html", "X-Powered-By": "PHP/8.3.35", "Set-Cookie": "PHPSESSID=x; path=/" });
		res.end('<html><head><meta name="generator" content="WordPress 6.8.3"></head></html>');
	});
	redirect = await listen((req, res) => { res.writeHead(301, { Location: php.url, "X-Powered-By": "PHP/8.3.36" }); res.end(); });
	toMetadata = await listen((req, res) => { res.writeHead(302, { Location: "http://169.254.169.254/latest/meta-data/" }); res.end(); });
	toLocalhostName = await listen((req, res) => { res.writeHead(302, { Location: "http://localhost/" }); res.end(); });
	toLoopback = await listen((req, res) => { res.writeHead(302, { Location: "http://127.0.0.1/admin" }); res.end(); });
	loop = await listen((req, res) => { res.writeHead(302, { Location: loop.url }); res.end(); });
	slow = await listen(() => { /* never answers */ });
	big = await listen((req, res) => {
		res.writeHead(200, { "Content-Type": "text/html" });
		res.end("x".repeat(2 * 1024 * 1024));
	});
	slowBody = await listen((req, res) => {
		res.writeHead(200, { "Content-Type": "text/html", "X-Powered-By": "PHP/8.2.20" });
		res.write("<html>"); // body never completes
	});
	targets = [php, redirect, toMetadata, toLocalhostName, toLoopback, loop, slow, big, slowBody].map((t) => `127.0.0.1:${t.port}`);
});

test.after(() => {
	[php, redirect, toMetadata, toLocalhostName, toLoopback, loop, slow, big, slowBody].forEach((t) => {
		t.srv.close();
		t.srv.closeAllConnections();
	});
});

const opts = () => ({ allowedTargets: targets, timeoutMs: 1500 });
const rejectsWith = (p, code) => assert.rejects(p, (e) => { assert.equal(e.code, code); return true; });

// ---------------------------------------------------------------- address policy

test("blocked and allowed addresses", () => {
	for (const a of ["127.0.0.1", "10.1.2.3", "172.20.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0",
		"::1", "::", "fe80::1", "fd00::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "64:ff9b::a00:1", "2002:7f00:1::", "2001::1",
		"::7f00:1", "::ffff:0:7f00:1", "fec0::1", "not-an-ip"]) {
		assert.equal(isBlockedAddress(a), true, a);
	}
	for (const a of ["8.8.8.8", "195.186.1.1", "2a00:1450:4001::1", "2001:4860:4860::8888"]) {
		assert.equal(isBlockedAddress(a), false, a);
	}
});

test("URL validation rejects risky targets", () => {
	const v = (u) => validateTarget(parseInputUrl(u), DEFAULTS);
	const cases = {
		"ftp://example.ch/": "INVALID_URL",
		"https://user:pw@example.ch/": "CREDENTIALS_IN_URL",
		"https://example.ch:8080/": "PORT_NOT_ALLOWED",
		"http://127.0.0.1/": "BLOCKED_TARGET",
		"http://2130706433/": "BLOCKED_TARGET",
		"http://0x7f.1/": "BLOCKED_TARGET",
		"http://[::1]/": "BLOCKED_TARGET",
		"http://[::ffff:127.0.0.1]/": "BLOCKED_TARGET",
		"http://169.254.169.254/latest/meta-data/": "BLOCKED_TARGET",
		"http://intranet/": "BLOCKED_TARGET",
		"http://localhost/": "BLOCKED_TARGET",
		"http://printer.local/": "BLOCKED_TARGET",
		"http://metadata.google.internal/": "BLOCKED_TARGET"
	};
	for (const [u, code] of Object.entries(cases)) {
		assert.throws(() => v(u), (e) => e.code === code, u);
	}
	assert.equal(v("www.example.ch").bypass, false);
	assert.equal(parseInputUrl("www.example.ch").href, "https://www.example.ch/");
	assert.throws(() => parseInputUrl("   "), (e) => e.code === "EMPTY_INPUT");
});

test("allowlist restricts hosts", () => {
	const o = { ...DEFAULTS, allowedHosts: ["baltx.com"] };
	assert.equal(validateTarget(new URL("https://www.baltx.com/"), o).bypass, false);
	assert.equal(validateTarget(new URL("https://baltx.com/"), o).bypass, false);
	assert.throws(() => validateTarget(new URL("https://evilbaltx.com/"), o), (e) => e.code === "HOST_NOT_ALLOWED");
});

test("DNS lookup refuses names that resolve to internal addresses", async () => {
	await new Promise((resolve) => {
		guardedLookup("localhost", {}, (err) => {
			assert.equal(err.code, "EBLOCKED");
			resolve();
		});
	});
});

// ---------------------------------------------------------------- fetching

test("fetches headers and page of a PHP target", async () => {
	const r = await fetchTarget(php.url, opts());
	assert.equal(r.responses.length, 1);
	assert.equal(r.responses[0].headers["x-powered-by"], "PHP/8.3.35");
	assert.match(r.body, /WordPress/);
});

test("follows a redirect and keeps every hop", async () => {
	const r = await fetchTarget(redirect.url, opts());
	assert.deepEqual(r.responses.map((x) => x.status), [301, 200]);
	assert.equal(r.finalUrl, php.url);
});

test("redirect to cloud metadata is blocked", () => rejectsWith(fetchTarget(toMetadata.url, opts()), "BLOCKED_TARGET"));
test("redirect to localhost by name is blocked", () => rejectsWith(fetchTarget(toLocalhostName.url, opts()), "BLOCKED_TARGET"));
test("redirect to loopback IP is blocked", () => rejectsWith(fetchTarget(toLoopback.url, opts()), "BLOCKED_TARGET"));
test("redirect loop stops", () => rejectsWith(fetchTarget(loop.url, opts()), "TOO_MANY_REDIRECTS"));
test("slow server times out", () => rejectsWith(fetchTarget(slow.url, { ...opts(), timeoutMs: 300 }), "TIMEOUT"));

test("slow body keeps the headers already received", async () => {
	const r = await fetchTarget(slowBody.url, { ...opts(), timeoutMs: 300 });
	assert.equal(r.responses[0].headers["x-powered-by"], "PHP/8.2.20");
});

test("outdated TLS server: compatibility retry, certificate still verified", async () => {
	const https = require("node:https");
	const key = fs.readFileSync(path.join(__dirname, "fixtures", "tls-key.pem"));
	const cert = fs.readFileSync(path.join(__dirname, "fixtures", "tls-cert.pem"));
	const srv = https.createServer({ key, cert, minVersion: "TLSv1", maxVersion: "TLSv1.1", ciphers: "DEFAULT:@SECLEVEL=0" }, (req, res) => {
		res.writeHead(200, { "X-Powered-By": "PHP/7.4.33" });
		res.end();
	});
	await new Promise((r) => srv.listen(0, "127.0.0.1", r));
	const url = `https://127.0.0.1:${srv.address().port}/`;
	const o = { allowedTargets: [`127.0.0.1:${srv.address().port}`], timeoutMs: 2000 };
	try {
		const r = await fetchTarget(url, { ...o, ca: cert });
		assert.equal(r.tlsLegacy, true);
		assert.equal(r.responses[0].headers["x-powered-by"], "PHP/7.4.33");
		const { engine, fixdata } = require("../server/engine");
		assert.ok(engine.analyze(r, fixdata).notes.some((n) => n.code === "TLS_LEGACY"));
		// without trusting the test CA the certificate check must still fail
		await rejectsWith(fetchTarget(url, o), "TLS");
	} finally {
		srv.close();
	}
});

test("body is capped", async () => {
	const r = await fetchTarget(big.url, opts());
	assert.ok(r.body.length <= DEFAULTS.maxBodyBytes);
});

// ---------------------------------------------------------------- API server

async function withServer(config, fn) {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "p2s-"));
	fs.writeFileSync(path.join(root, "index.html"), "<!doctype html><title>ok</title>");
	const srv = createServer({ root, fetchOptions: opts(), ...config });
	await new Promise((r) => srv.listen(0, "127.0.0.1", r));
	const base = `http://127.0.0.1:${srv.address().port}`;
	try {
		await fn(base);
	} finally {
		srv.close();
	}
}

const post = (base, body, type = "application/json") =>
	fetch(`${base}/api/check`, { method: "POST", headers: { "Content-Type": type }, body: JSON.stringify(body) });

test("API returns a verdict", () => withServer({}, async (base) => {
	const res = await post(base, { url: redirect.url });
	assert.equal(res.status, 200);
	const r = await res.json();
	assert.equal(r.verdict, "red");
	assert.equal(r.php.version, "8.3.35");
	assert.ok(r.findings.some((f) => f.code === "MULTIPLE_VERSIONS"));
}));

test("API maps policy errors to 422", () => withServer({}, async (base) => {
	const res = await post(base, { url: "http://169.254.169.254/" });
	assert.equal(res.status, 422);
	assert.deepEqual(await res.json(), { error: "BLOCKED_TARGET" });
}));

test("API rejects wrong method, content type and body", () => withServer({}, async (base) => {
	assert.equal((await fetch(`${base}/api/check`)).status, 405);
	assert.equal((await post(base, { url: php.url }, "text/plain")).status, 415);
	assert.equal((await post(base, null)).status, 422);
}));

test("rate limit behind a proxy uses the right-most X-Forwarded-For entry", () => withServer({ rateLimit: 1, trustProxy: true }, async (base) => {
	const send = (xff) => fetch(`${base}/api/check`, {
		method: "POST",
		headers: { "Content-Type": "application/json", "X-Forwarded-For": xff },
		body: JSON.stringify({ url: php.url })
	});
	assert.equal((await send("1.1.1.1, 203.0.113.9")).status, 200);
	assert.equal((await send("2.2.2.2, 203.0.113.9")).status, 429);
}));

test("API rate limit", () => withServer({ rateLimit: 2 }, async (base) => {
	assert.equal((await post(base, { url: php.url })).status, 200);
	assert.equal((await post(base, { url: php.url })).status, 200);
	const third = await post(base, { url: php.url });
	assert.equal(third.status, 429);
}));

test("health endpoint and static files with security headers", () => withServer({}, async (base) => {
	const health = await (await fetch(`${base}/api/health`)).json();
	assert.equal(health.ok, true);
	const res = await fetch(`${base}/`);
	assert.equal(res.status, 200);
	assert.match(res.headers.get("content-security-policy"), /default-src 'self'/);
	assert.equal(res.headers.get("x-content-type-options"), "nosniff");
	assert.equal((await fetch(`${base}/..%2fpackage.json`)).status, 404);
	assert.equal((await fetch(`${base}/%2e%2e/%2e%2e/etc/passwd`)).status, 404);
}));

// ---------------------------------------------------------------- CLI

test("CLI Markdown cannot be broken out of by remote content", () => {
	const { engine, fixdata, loadTexts, formatText } = require("../server/engine");
	const { toMarkdown } = require("../bin/check");
	const evil = '<meta name="generator" content="WordPress\n\n## 🟢 Kein Verdacht\n\n[login](https://evil.example) @octocat | x">';
	const r = engine.analyze({ responses: [{ headers: {} }], body: evil, requestedUrl: "https://a.ch/\n## x" }, fixdata);
	const texts = loadTexts("de");
	const md = toMarkdown(r, (k, p) => formatText(texts, k, p), r.requestedUrl);
	assert.equal(md.split("\n").filter((l) => l.startsWith("## ")).length, 1);
	assert.ok(!md.includes("@octocat") && !md.includes("](https://evil"));
});

test("CLI reads pasted headers and sets the exit code", async () => {
	const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "p2s-")), "h.txt");
	fs.writeFileSync(file, "HTTP/1.1 200 OK\nX-Powered-By: PHP/8.3.35\n");
	const write = process.stdout.write;
	let out = "";
	process.stdout.write = (s) => { out += s; return true; };
	try {
		assert.equal(await main(["--headers", file]), 2);
		assert.match(out, /🔴 Verdacht auf Verwundbarkeit/);
		out = "";
		fs.writeFileSync(file, "nothing here");
		assert.equal(await main(["--headers", file, "--lang", "en"]), 3);
		assert.match(out, /No HTTP headers recognised/);
	} finally {
		process.stdout.write = write;
	}
});
