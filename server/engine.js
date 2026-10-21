"use strict";
// Loads the shared UI5 engine module (webapp/engine/php2shell.js) in Node
// by providing a minimal sap.ui.define, plus the fix data and i18n texts.
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const WEBAPP = path.join(__dirname, "..", "webapp");

function loadEngine() {
	const file = path.join(WEBAPP, "engine", "php2shell.js");
	const wrapper = vm.runInThisContext(`(function (sap) {${fs.readFileSync(file, "utf8")}\n})`, { filename: file });
	let api;
	wrapper({ ui: { define: (deps, factory) => { api = factory(); } } });
	return api;
}

function loadFixdata() {
	return JSON.parse(fs.readFileSync(path.join(WEBAPP, "model", "fixdata.json"), "utf8"));
}

/** Minimal .properties reader (key=value, # comments, \ line continuation). */
function loadTexts(lang) {
	const read = (name) => {
		const file = path.join(WEBAPP, "i18n", name);
		if (!fs.existsSync(file)) return {};
		const out = {};
		fs.readFileSync(file, "utf8").replace(/\\\r?\n\s*/g, "").split(/\r?\n/).forEach((line) => {
			const m = /^\s*([^#!=:\s][^=:]*?)\s*[=:]\s*(.*)$/.exec(line);
			if (m) out[m[1]] = m[2];
		});
		return out;
	};
	const base = read("i18n.properties");
	return lang && lang !== "en" ? { ...base, ...read(`i18n_${lang}.properties`) } : base;
}

/** Same placeholder rules as UI5's getText: {0}, {1}; '' is a literal quote. */
function formatText(texts, key, params = []) {
	const pattern = texts[key];
	if (pattern === undefined) return key;
	return pattern.replace(/\{(\d+)\}/g, (_, i) => (params[i] !== undefined ? String(params[i]) : "")).replace(/''/g, "'");
}

module.exports = { engine: loadEngine(), fixdata: loadFixdata(), loadTexts, formatText };
