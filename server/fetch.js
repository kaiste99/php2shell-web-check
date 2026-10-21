"use strict";
// Passive fetch: one GET per hop like a browser, manual redirects, every hop
// re-validated, hard time and size limits. Returns raw headers for the engine.
const http = require("node:http");
const https = require("node:https");
const net = require("node:net");
const crypto = require("node:crypto");
const { isBlockedAddress, guardedLookup } = require("./ssrf");
const { version } = require("../package.json");

const DEFAULTS = {
	timeoutMs: 8000,
	maxRedirects: 3,
	maxBodyBytes: 256 * 1024,
	userAgent: `php2shell-web-check/${version} (+https://github.com/kaiste99/php2shell-web-check)`,
	allowedHosts: [], // optional allowlist (domain and its subdomains); empty = all public hosts
	allowedTargets: [], // tests only: exact "host:port" pairs that skip the address policy
	ca: undefined // tests only: extra trusted CA
};

// Second attempt for servers that only speak outdated TLS (old protocol versions,
// no secure renegotiation). Certificates are still verified.
const TLS_COMPAT = {
	minVersion: "TLSv1",
	ciphers: "DEFAULT:@SECLEVEL=0",
	secureOptions: crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT
};

class CheckError extends Error {
	constructor(code, detail) {
		super(code);
		this.code = code;
		this.detail = detail; // low-level error code, for diagnostics only
	}
}

function parseInputUrl(input) {
	let s = String(input || "").trim();
	if (!s) throw new CheckError("EMPTY_INPUT");
	if (s.length > 2048) throw new CheckError("INVALID_URL");
	if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = `https://${s}`;
	try {
		return new URL(s);
	} catch {
		throw new CheckError("INVALID_URL");
	}
}

function validateTarget(u, opts) {
	if (u.protocol !== "http:" && u.protocol !== "https:") throw new CheckError("INVALID_URL");
	if (u.username || u.password) throw new CheckError("CREDENTIALS_IN_URL");
	const host = u.hostname.replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
	if (!host) throw new CheckError("INVALID_URL");
	const port = u.port || (u.protocol === "https:" ? "443" : "80");
	if (opts.allowedTargets.includes(`${host}:${port}`)) return { bypass: true };

	if (port !== "80" && port !== "443") throw new CheckError("PORT_NOT_ALLOWED");
	if (net.isIP(host)) {
		if (isBlockedAddress(host)) throw new CheckError("BLOCKED_TARGET");
	} else if (!host.includes(".") || /\.(localhost|local|internal|lan|home\.arpa)$/.test(host)) {
		throw new CheckError("BLOCKED_TARGET");
	}
	if (opts.allowedHosts.length && !opts.allowedHosts.some((a) => host === a || host.endsWith(`.${a}`))) {
		throw new CheckError("HOST_NOT_ALLOWED");
	}
	return { bypass: false };
}

function mapError(err) {
	if (err instanceof CheckError) return err;
	const code = String(err && err.code || "");
	if (code === "EBLOCKED") return new CheckError("BLOCKED_TARGET", code);
	if (["ENOTFOUND", "EAI_AGAIN", "ENODATA", "EAI_NONAME"].includes(code)) return new CheckError("DNS", code);
	if (code === "ETIMEDOUT") return new CheckError("TIMEOUT", code);
	if (code === "EPROTO" || /CERT|SSL|TLS|SELF_SIGNED|UNABLE_TO_VERIFY/i.test(code)) return new CheckError("TLS", code);
	return new CheckError("NETWORK", code || undefined);
}

function requestOnce(u, opts, target, tlsCompat) {
	return new Promise((resolve, reject) => {
		const isHttps = u.protocol === "https:";
		const lib = isHttps ? https : http;
		let finishBody = null; // set once headers are in: a slow body must not discard them
		const req = lib.request(u, {
			method: "GET",
			agent: false,
			lookup: target.bypass ? undefined : guardedLookup,
			...(isHttps ? { ca: opts.ca, ...(tlsCompat ? TLS_COMPAT : {}) } : {}),
			headers: {
				"User-Agent": opts.userAgent,
				Accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
				"Accept-Encoding": "identity"
			}
		}, (res) => {
			const isRedirect = res.statusCode >= 300 && res.statusCode < 400 && res.headers.location;
			const isHtml = /text\/html|application\/xhtml/i.test(res.headers["content-type"] || "");
			const chunks = [];
			let size = 0;
			let settled = false;
			const finish = () => {
				if (settled) return;
				settled = true;
				clearTimeout(deadline);
				res.destroy();
				resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") });
			};
			if (isRedirect || !isHtml) return finish();
			finishBody = finish;
			res.on("data", (chunk) => {
				chunks.push(chunk.subarray(0, opts.maxBodyBytes - size));
				size += chunk.length;
				if (size >= opts.maxBodyBytes) finish();
			});
			res.on("end", finish);
			res.on("close", finish);
			res.on("error", finish);
		});
		const deadline = setTimeout(() => (finishBody ? finishBody() : req.destroy(new CheckError("TIMEOUT"))), opts.timeoutMs);
		req.on("error", (err) => {
			clearTimeout(deadline);
			reject(mapError(err));
		});
		req.end();
	});
}

async function requestWithTlsFallback(u, opts, target, state) {
	try {
		return await requestOnce(u, opts, target, false);
	} catch (err) {
		const certProblem = /CERT|SELF_SIGNED|UNABLE_TO_VERIFY/i.test(err.detail || "");
		if (err.code !== "TLS" || certProblem || u.protocol !== "https:") throw err;
		const res = await requestOnce(u, opts, target, true);
		state.tlsLegacy = true;
		return res;
	}
}

/** @returns {Promise<{requestedUrl, finalUrl, responses: [{url, status, headers}], body, tlsLegacy}>} */
async function fetchTarget(input, options = {}) {
	const opts = { ...DEFAULTS, ...options };
	let u = parseInputUrl(input);
	const requestedUrl = u.href;
	const responses = [];
	const state = { tlsLegacy: false };
	for (let hop = 0; ; hop++) {
		const target = validateTarget(u, opts);
		const res = await requestWithTlsFallback(u, opts, target, state);
		responses.push({ url: u.href, status: res.status, headers: res.headers });
		const location = res.headers.location;
		if (res.status >= 300 && res.status < 400 && location) {
			if (hop >= opts.maxRedirects) throw new CheckError("TOO_MANY_REDIRECTS");
			try {
				u = new URL(location, u);
			} catch {
				throw new CheckError("INVALID_URL");
			}
			continue;
		}
		return { requestedUrl, finalUrl: u.href, responses, body: res.body, tlsLegacy: state.tlsLegacy };
	}
}

module.exports = { fetchTarget, validateTarget, parseInputUrl, CheckError, DEFAULTS };
