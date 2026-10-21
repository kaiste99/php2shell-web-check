"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { engine, fixdata, loadTexts, formatText } = require("../server/engine");

const run = (headers, body) => engine.analyze({ responses: [{ status: 200, headers }], body }, fixdata);
const codes = (list) => list.map((x) => x.code);

// Test matrix from the Definition of Done (README).
const MATRIX = [
	["official image, below fix", { "x-powered-by": "PHP/8.3.35" }, "red", "UPSTREAM_BELOW_FIX"],
	["official image, fixed", { "x-powered-by": "PHP/8.3.36" }, "green", "UPSTREAM_FIXED"],
	["8.5 fixed", { "x-powered-by": "PHP/8.5.12" }, "green", "UPSTREAM_FIXED"],
	["8.2 one below fix", { "x-powered-by": "PHP/8.2.34" }, "red", "UPSTREAM_BELOW_FIX"],
	["newer branch", { "x-powered-by": "PHP/8.6.0" }, "green", "NEWER_BRANCH"],
	["EOL without distro hint", { "x-powered-by": "PHP/7.4.33" }, "red", "EOL_BRANCH"],
	["Ubuntu 24.04 package", { "x-powered-by": "PHP/8.3.6-0ubuntu0.24.04.12", server: "Apache/2.4.58 (Ubuntu)" }, "orange", "DISTRO_UNCONFIRMED"],
	["Ubuntu, version without suffix", { "x-powered-by": "PHP/8.3.6", server: "Apache/2.4.58 (Ubuntu)" }, "orange", "BACKPORT_POSSIBLE"],
	["Debian 13 fixed package", { "x-powered-by": "PHP/8.4.27-1~deb13u1" }, "green", "UPSTREAM_FIXED"],
	["Debian 13 old package", { "x-powered-by": "PHP/8.4.24-1~deb13u1" }, "red", "DISTRO_BELOW_FIX"],
	["Debian 12, no fix yet", { "x-powered-by": "PHP/8.2.34-1~deb12u1" }, "red", "DISTRO_NO_FIX"],
	["RHEL, plain version", { "x-powered-by": "PHP/8.2.13", server: "Apache/2.4.57 (Red Hat Enterprise Linux)" }, "orange", "BACKPORT_POSSIBLE"],
	["sury build below fix", { "x-powered-by": "PHP/8.3.35-1+ubuntu24.04.1+deb.sury.org+1", server: "nginx (Ubuntu)" }, "red", "UPSTREAM_BELOW_FIX"],
	["sury build fixed", { "x-powered-by": "PHP/8.3.36-1+ubuntu24.04.1+deb.sury.org+1" }, "green", "UPSTREAM_FIXED"],
	["PHP version in Server header", { server: "Apache/2.4.29 (Ubuntu) PHP/7.2.24-0ubuntu0.18.04.17" }, "orange", "DISTRO_UNCONFIRMED"],
	["expose_php=Off, session cookie", { server: "nginx", "set-cookie": ["PHPSESSID=abc; path=/"] }, "orange", "PHP_NO_VERSION"],
	["LiteSpeed without version", { server: "LiteSpeed" }, "orange", "PHP_NO_VERSION"],
	["CDN, nothing visible", { server: "cloudflare", "cf-ray": "8a1b-ZRH" }, "grey", "NO_PHP_SIGNAL"],
	["static site", { server: "nginx/1.27.0", "content-type": "text/html" }, "grey", "NO_PHP_SIGNAL"]
];

for (const [name, headers, verdict, finding] of MATRIX) {
	test(`matrix: ${name} -> ${verdict}`, () => {
		const r = run(headers);
		assert.equal(r.verdict, verdict);
		assert.ok(codes(r.findings).includes(finding), `expected ${finding}, got ${codes(r.findings)}`);
	});
}

test("every result has a reason, a next step and the remote-limits note", () => {
	for (const [, headers] of MATRIX) {
		const r = run(headers);
		assert.ok(["red", "orange", "green", "grey"].includes(r.verdict));
		assert.ok(r.findings.length > 0);
		assert.ok(r.actions.length > 0);
		assert.ok(codes(r.notes).includes("REMOTE_LIMITS"));
	}
});

test("red verdict recommends patch, restart and mitigation", () => {
	const r = run({ "x-powered-by": "PHP/8.4.20" });
	assert.deepEqual(codes(r.actions).slice(0, 3), ["PATCH", "RESTART", "MITIGATE"]);
	assert.ok(codes(r.actions).includes("HIDE_VERSION"));
});

test("EOL branch adds upgrade advice", () => {
	assert.ok(codes(run({ "x-powered-by": "PHP/7.4.33" }).actions).includes("EOL_UPGRADE"));
	assert.ok(codes(run({ "x-powered-by": "PHP/8.1.2-1ubuntu2.20" }).actions).includes("EOL_UPGRADE"));
});

test("CDN is reported as a note", () => {
	const r = run({ server: "cloudflare", "cf-ray": "x", "x-powered-by": "PHP/8.3.36" });
	assert.equal(r.verdict, "green");
	const cdn = r.notes.find((n) => n.code === "CDN");
	assert.deepEqual(cdn.params, ["Cloudflare"]);
});

test("worst version along a redirect chain wins", () => {
	const r = engine.analyze({
		responses: [
			{ status: 301, headers: { "x-powered-by": ["PHP/8.3.36"] } },
			{ status: 200, headers: { "x-powered-by": ["PHP/8.2.20"] } }
		]
	}, fixdata);
	assert.equal(r.verdict, "red");
	assert.equal(r.php.version, "8.2.20");
	assert.ok(codes(r.findings).includes("MULTIPLE_VERSIONS"));
});

test("WordPress detected from page body", () => {
	const r = run({ server: "Apache" }, '<html><head><meta content="WordPress 6.8.3" name="generator"></head></html>');
	assert.equal(r.verdict, "orange");
	assert.match(r.findings[0].params[0], /WordPress 6\.8\.3/);
});

test("redirect to another host is noted", () => {
	const r = engine.analyze({ responses: [{ headers: {} }], requestedUrl: "https://a.ch/", finalUrl: "https://www.b.ch/" }, fixdata);
	assert.ok(codes(r.notes).includes("REDIRECTED"));
});

test("parseHeaderBlock reads curl -sIL output with redirects", () => {
	const text = [
		"HTTP/1.1 301 Moved Permanently",
		"Server: Apache/2.4.58 (Ubuntu)",
		"Location: https://www.example.ch/",
		"",
		"HTTP/2 200 ",
		"x-powered-by: PHP/8.3.6-0ubuntu0.24.04.12",
		"set-cookie: PHPSESSID=abc; path=/",
		"set-cookie: other=1",
		"not a header line"
	].join("\r\n");
	const responses = engine.parseHeaderBlock(text);
	assert.equal(responses.length, 2);
	assert.equal(responses[0].status, 301);
	assert.deepEqual(responses[1].headers["set-cookie"], ["PHPSESSID=abc; path=/", "other=1"]);
	const r = engine.analyze({ responses }, fixdata);
	assert.equal(r.verdict, "orange");
});

test("parseHeaderBlock accepts headers without status line", () => {
	const responses = engine.parseHeaderBlock("X-Powered-By: PHP/8.4.10\nServer: nginx");
	assert.equal(engine.analyze({ responses }, fixdata).verdict, "red");
	assert.equal(engine.parseHeaderBlock("hello world").length, 0);
});

test("parsePhpVersion", () => {
	assert.equal(engine.parsePhpVersion("PHP/7.4.33, PleskLin").raw, "7.4.33");
	assert.equal(engine.parsePhpVersion("PHP/8.3.6-0ubuntu0.24.04.13").suffix, "-0ubuntu0.24.04.13");
	assert.equal(engine.parsePhpVersion("nginx"), null);
});

test("compareDeb follows dpkg ordering", () => {
	const c = engine.compareDeb;
	assert.equal(c("8.4.27-1~deb13u1", "8.4.27-1~deb13u1"), 0);
	assert.equal(c("8.4.27-1~deb13u2", "8.4.27-1~deb13u1"), 1);
	assert.equal(c("8.4.27-1", "8.4.27-1~deb13u1"), 1);
	assert.equal(c("8.3.6-0ubuntu0.24.04.13", "8.3.6-0ubuntu0.24.04.9"), 1);
	assert.equal(c("8.3.6-0ubuntu0.24.04.12", "8.3.6-0ubuntu0.24.04.13"), -1);
	assert.equal(c("1:1.0-1", "2.0-1"), 1);
	assert.equal(c("1.0a-1", "1.0-1"), 1);
});

test("fix data is consistent", () => {
	for (const v of Object.values(fixdata.upstreamFixed)) assert.match(v, /^\d+\.\d+\.\d+$/);
	for (const d of fixdata.distros) {
		assert.ok(["fixed", "no-fix", "unconfirmed"].includes(d.status), d.id);
		assert.ok(d.status !== "fixed" || d.fixed, `${d.id}: fixed version missing`);
		assert.match(d.source, /^https:\/\//);
		new RegExp(d.match);
	}
});

test("every code has a text in both languages", () => {
	const all = new Set(["PHP_VERSION_FOUND", "MULTIPLE_VERSIONS", "PHP_NO_VERSION", "NO_PHP_SIGNAL"]);
	const keys = [];
	for (const lang of ["en", "de"]) {
		const texts = loadTexts(lang);
		for (const [, headers] of MATRIX) {
			const r = run(headers);
			r.findings.forEach((f) => keys.push(`finding.${f.code}`));
			r.actions.forEach((a) => keys.push(`action.${a.code}`));
			r.notes.forEach((n) => keys.push(`note.${n.code}`));
			keys.push(`verdict.${r.verdict}.title`, `verdict.${r.verdict}.text`);
		}
		all.forEach((c) => keys.push(`finding.${c}`));
		for (const k of keys) assert.ok(texts[k], `${lang}: missing ${k}`);
		assert.equal(formatText(texts, "finding.UPSTREAM_BELOW_FIX", ["8.3.1", "8.3.36"]).includes("8.3.36"), true);
	}
});

test("texts contain no single quotes (UI5 MessageFormat escape)", () => {
	for (const lang of ["en", "de"]) {
		for (const [k, v] of Object.entries(loadTexts(lang))) assert.ok(!v.includes("'"), `${lang}: ${k}`);
	}
});
