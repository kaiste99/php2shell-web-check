#!/usr/bin/env node
"use strict";
// CLI and GitHub Actions entry point.
//   node bin/check.js https://www.example.ch [--lang de|en] [--json]
//   curl -sIL https://www.example.ch | node bin/check.js --headers -
// Exit code: 0 green/grey, 1 orange, 2 red, 3 error.
const fs = require("node:fs");
const { engine, fixdata, loadTexts, formatText } = require("../server/engine");
const { fetchTarget, CheckError } = require("../server/fetch");

const ICON = { red: "🔴", orange: "🟠", green: "🟢", grey: "⚪" };
const EXIT = { red: 2, orange: 1, green: 0, grey: 0 };

// Remote-controlled strings end up in Markdown: one line only, markup neutralised.
const esc = (s) => String(s).replace(/[\r\n\t\f\v]+/g, " ").replace(/[<>&|`*_[\]\\@]/g, (c) => `&#${c.charCodeAt(0)};`);

function parseArgs(argv) {
	const args = { lang: "de", json: false, headers: null, url: null };
	for (let i = 0; i < argv.length; i++) {
		const a = argv[i];
		if (a === "--json") args.json = true;
		else if (a === "--lang") args.lang = argv[++i];
		else if (a === "--headers") args.headers = argv[++i];
		else if (!args.url) args.url = a;
	}
	return args;
}

function toMarkdown(r, t, target) {
	// Own texts: only "*" needs escaping (e.g. "php*"). Remote values: everything.
	const own = (s) => s.replace(/\*/g, "\\*");
	const list = (items, kind, prefix) => items.map((x) => `${prefix} ${own(t(`${kind}.${x.code}`, x.params.map(esc)))}`).join("\n");
	const out = [
		`## ${ICON[r.verdict]} ${t(`verdict.${r.verdict}.title`)}`,
		"",
		target ? `${t("checkedUrl", [esc(target)])}\n` : "",
		t(`verdict.${r.verdict}.text`),
		"",
		`### ${t("section.findings")}`,
		list(r.findings, "finding", "-"),
		"",
		`### ${t("section.actions")}`,
		list(r.actions, "action", "1."),
		"",
		`### ${t("section.notes")}`,
		list(r.notes, "note", "-")
	];
	if (r.signals.length) {
		out.push("", `<details><summary>${t("section.signals")}</summary>`, "",
			`| ${t("col.header")} | ${t("col.value")} |`, "| --- | --- |",
			...r.signals.map((s) => `| ${esc(s.name)} | ${esc(s.value)} |`), "", "</details>");
	}
	return out.join("\n") + "\n";
}

async function main(argv) {
	const args = parseArgs(argv);
	const texts = loadTexts(args.lang);
	const t = (key, params) => formatText(texts, key, (params || []).map(String));
	let input;
	try {
		if (args.headers) {
			const text = fs.readFileSync(args.headers === "-" ? 0 : args.headers, "utf8");
			input = { responses: engine.parseHeaderBlock(text) };
			if (!input.responses.length) throw new CheckError("NO_HEADERS");
		} else {
			input = await fetchTarget(args.url);
		}
	} catch (err) {
		const code = err instanceof CheckError ? err.code : "NETWORK";
		process.stderr.write(`error=${code}${err && err.detail ? `:${err.detail}` : ""}\n`);
		if (args.json) process.stdout.write(JSON.stringify({ error: code }) + "\n");
		else process.stdout.write(`## ⚠️ ${t("error.title")}\n\n${esc(args.url || args.headers || "")}: ${t(`error.${code}`)}\n`);
		return 3;
	}
	const result = engine.analyze(input, fixdata);
	process.stderr.write(`result=${result.verdict}\n`);
	process.stdout.write(args.json ? JSON.stringify(result, null, 2) + "\n" : toMarkdown(result, t, input.requestedUrl));
	return EXIT[result.verdict];
}

if (require.main === module) {
	main(process.argv.slice(2)).then(
		(code) => { process.exitCode = code; },
		(err) => { console.error(err); process.exitCode = 3; }
	);
}

module.exports = { main, toMarkdown };
