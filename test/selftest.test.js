"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { engine, fixdata, loadTexts } = require("../server/engine");

const out = (o) => Object.entries(o).map(([k, v]) => `${k} = ${v}`).join("\n");
const codes = (list) => list.map((x) => x.code);
const BASE = { PHP_SAPI: "fpm-fcgi", OS_RELEASE: "?", memory_limit: "'256M'", "session.upload_progress.enabled": "'1'", fatal_error_backtraces: "false" };

test("vulnerable PHP-FPM with upload progress on -> red, upload path open", () => {
	const r = engine.analyzeSelftest(out({ PHP_VERSION: "8.3.20", ...BASE }), fixdata);
	assert.equal(r.kind, "selftest");
	assert.equal(r.verdict, "red");
	assert.ok(codes(r.findings).includes("A_RISK_MEDIUM"));
	assert.ok(codes(r.findings).includes("A_MEMORY_LIMITED"));
	assert.ok(codes(r.findings).includes("B_UPLOAD_ON"));
	assert.equal(r.actions[0].code, "DELETE_FILE");
	assert.ok(["PATCH", "HOSTER", "RESTART", "SELFTEST_UPLOAD_OFF", "SELFTEST_MEMORY"].every((c) => codes(r.actions).includes(c)));
});

test("patched version -> green, recommends keeping upload progress off", () => {
	const r = engine.analyzeSelftest(out({ PHP_VERSION: "8.3.36", ...BASE }), fixdata);
	assert.equal(r.verdict, "green");
	assert.deepEqual(codes(r.actions), ["DELETE_FILE", "SELFTEST_UPLOAD_KEEP_OFF"]);
});

test("mod_php on 8.5 with fatal_error_backtraces -> all confirmed paths reported", () => {
	const r = engine.analyzeSelftest(out({ PHP_VERSION: "8.5.10", ...BASE, PHP_SAPI: "apache2handler", fatal_error_backtraces: "'1'", memory_limit: "'-1'" }), fixdata);
	assert.equal(r.verdict, "red");
	for (const c of ["A_RISK_HIGH", "A_MEMORY_UNLIMITED", "B_BACKTRACES_ON", "B_MODPHP_INI"]) assert.ok(codes(r.findings).includes(c), c);
	assert.ok(codes(r.actions).includes("SELFTEST_BACKTRACES_OFF"));
	assert.ok(!codes(r.actions).includes("SELFTEST_MEMORY"));
});

test("Ubuntu build without package suffix -> orange, not a false red", () => {
	const r = engine.analyzeSelftest(out({ PHP_VERSION: "8.3.6", ...BASE, OS_RELEASE: "ubuntu 24.04" }), fixdata);
	assert.equal(r.verdict, "orange");
	assert.ok(codes(r.findings).includes("BACKPORT_POSSIBLE"));
	assert.ok(codes(r.actions).includes("LOCAL_CHECK"));
});

test("Docker image on Debian base (os-release debian) is not treated as backport", () => {
	const r = engine.analyzeSelftest(out({ PHP_VERSION: "8.5.8", ...BASE, PHP_SAPI: "apache2handler", OS_RELEASE: "debian 13" }), fixdata);
	assert.equal(r.verdict, "red");
	assert.ok(codes(r.findings).includes("UPSTREAM_BELOW_FIX"));
});

test("upload progress off closes the session path", () => {
	const r = engine.analyzeSelftest(out({ PHP_VERSION: "8.4.10", ...BASE, "session.upload_progress.enabled": "''" }), fixdata);
	assert.ok(codes(r.findings).includes("B_UPLOAD_OFF"));
	assert.ok(!codes(r.actions).includes("SELFTEST_UPLOAD_OFF"));
});

test("pasted PHP code and garbage are rejected with a clear code", () => {
	assert.throws(() => engine.analyzeSelftest("<?php\nphpinfo();", fixdata), (e) => e.code === "PASTED_CODE");
	assert.throws(() => engine.analyzeSelftest("hello", fixdata), (e) => e.code === "SELFTEST_INVALID");
});

test("self-test texts exist in both languages", () => {
	const cases = [
		{ PHP_VERSION: "8.3.20", ...BASE },
		{ PHP_VERSION: "8.3.36", ...BASE },
		{ PHP_VERSION: "8.5.10", ...BASE, PHP_SAPI: "apache2handler", fatal_error_backtraces: "'0'", memory_limit: "'-1'", "session.upload_progress.enabled": "'0'" },
		{ PHP_VERSION: "8.3.6", ...BASE, OS_RELEASE: "debian 12", PHP_SAPI: "cgi-fcgi" },
		{ PHP_VERSION: "7.4.33", ...BASE, PHP_SAPI: "litespeed", fatal_error_backtraces: "'1'" }
	];
	for (const lang of ["en", "de"]) {
		const t = loadTexts(lang);
		for (const k of ["mode.selftest", "selftest.intro", "selftest.step1", "selftest.step2", "selftest.step3", "selftest.step4",
			"selftest.copy", "selftest.copied", "error.PASTED_CODE", "error.SELFTEST_INVALID"]) assert.ok(t[k], `${lang}: ${k}`);
		for (const c of cases) {
			const r = engine.analyzeSelftest(out(c), fixdata);
			const keys = [`verdict.${r.verdict}.title.selftest`, `verdict.${r.verdict}.text.selftest`,
				...r.findings.map((f) => `finding.${f.code}`), ...r.actions.map((a) => `action.${a.code}`), ...r.notes.map((n) => `note.${n.code}`)];
			for (const k of keys) assert.ok(t[k], `${lang}: missing ${k}`);
		}
	}
});
