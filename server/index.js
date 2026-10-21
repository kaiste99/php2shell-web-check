"use strict";
// HTTP server without runtime dependencies: serves the built UI5 app (dist/)
// and the check API. Configuration via environment, see README.
const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const { pipeline } = require("node:stream");
const { engine, fixdata } = require("./engine");
const { fetchTarget, CheckError } = require("./fetch");

const MIME = {
	".html": "text/html; charset=utf-8",
	".js": "text/javascript; charset=utf-8",
	".json": "application/json; charset=utf-8",
	".css": "text/css; charset=utf-8",
	".properties": "text/plain; charset=utf-8",
	".xml": "application/xml; charset=utf-8",
	".svg": "image/svg+xml",
	".png": "image/png",
	".ico": "image/x-icon",
	".woff2": "font/woff2",
	".woff": "font/woff",
	".ttf": "font/ttf"
};

const SECURITY_HEADERS = {
	"Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
	"X-Content-Type-Options": "nosniff",
	"Referrer-Policy": "no-referrer",
	"Cross-Origin-Opener-Policy": "same-origin",
	"Permissions-Policy": "camera=(), microphone=(), geolocation=()"
};

function send(res, status, headers, body) {
	res.writeHead(status, { ...SECURITY_HEADERS, ...headers });
	res.end(body);
}

function json(res, status, data) {
	send(res, status, { "Content-Type": MIME[".json"], "Cache-Control": "no-store" }, JSON.stringify(data));
}

function readJson(req, limit) {
	return new Promise((resolve, reject) => {
		const chunks = [];
		let size = 0;
		req.on("data", (c) => {
			size += c.length;
			if (size > limit) {
				reject(new CheckError("INVALID_URL"));
				req.destroy();
			} else chunks.push(c);
		});
		req.on("end", () => {
			try {
				resolve(JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"));
			} catch {
				reject(new CheckError("INVALID_URL"));
			}
		});
		req.on("error", reject);
	});
}

function serveStatic(root, pathname, req, res) {
	let rel;
	try {
		rel = decodeURIComponent(pathname);
	} catch {
		return send(res, 400, {}, "Bad Request");
	}
	let file = path.join(root, path.normalize(rel));
	if (rel.includes("\0") || (file !== root && !file.startsWith(root + path.sep))) {
		return send(res, 404, {}, "Not Found");
	}
	fs.stat(file, (err, stat) => {
		if (!err && stat.isDirectory()) {
			file = path.join(file, "index.html");
		}
		fs.stat(file, (err2, stat2) => {
			if (err2 || !stat2.isFile()) return send(res, 404, {}, "Not Found");
			const ext = path.extname(file);
			res.writeHead(200, {
				...SECURITY_HEADERS,
				"Content-Type": MIME[ext] || "application/octet-stream",
				"Content-Length": stat2.size,
				"Cache-Control": ext === ".html" ? "no-cache" : "public, max-age=3600"
			});
			if (req.method === "HEAD") return res.end();
			// pipeline closes the file on client abort and handles read errors
			pipeline(fs.createReadStream(file), res, () => {});
		});
	});
}

function createServer(config = {}) {
	const cfg = {
		root: path.resolve(config.root || path.join(__dirname, "..", "dist")),
		rateLimit: Number.isFinite(config.rateLimit) && config.rateLimit > 0 ? config.rateLimit : 20, // per client and minute
		trustProxy: config.trustProxy ?? false,
		fetchOptions: config.fetchOptions || {}
	};
	const hits = new Map();

	function isLimited(client) {
		const now = Date.now();
		if (hits.size > 10000) hits.clear();
		const recent = (hits.get(client) || []).filter((t) => now - t < 60000);
		if (recent.length >= cfg.rateLimit) return true;
		recent.push(now);
		hits.set(client, recent);
		return false;
	}

	// Behind a trusted reverse proxy the right-most X-Forwarded-For entry is the
	// one the proxy appended; entries further left are client-controlled.
	function clientOf(req) {
		if (!cfg.trustProxy) return req.socket.remoteAddress;
		const forwarded = String(req.headers["x-forwarded-for"] || "").split(",").map((s) => s.trim()).filter(Boolean);
		return forwarded[forwarded.length - 1] || req.socket.remoteAddress;
	}

	return http.createServer(async (req, res) => {
		try {
			const { pathname } = new URL(req.url, "http://localhost");
			if (pathname === "/api/health") {
				return json(res, 200, { ok: true, asOf: fixdata.asOf });
			}
			if (pathname === "/api/check") {
				if (req.method !== "POST") return json(res, 405, { error: "API" });
				if (!/^application\/json/i.test(req.headers["content-type"] || "")) return json(res, 415, { error: "API" });
				if (isLimited(clientOf(req))) return json(res, 429, { error: "RATE_LIMIT" });
				const body = await readJson(req, 4096);
				const fetched = await fetchTarget(body && typeof body === "object" ? body.url : null, cfg.fetchOptions);
				return json(res, 200, engine.analyze(fetched, fixdata));
			}
			if (req.method !== "GET" && req.method !== "HEAD") return send(res, 405, {}, "Method Not Allowed");
			return serveStatic(cfg.root, pathname, req, res);
		} catch (err) {
			if (err instanceof CheckError) return json(res, 422, { error: err.code });
			console.error(err);
			return json(res, 500, { error: "API" });
		}
	});
}

if (require.main === module) {
	const env = process.env;
	const config = {
		trustProxy: env.TRUST_PROXY === "1",
		rateLimit: env.RATE_LIMIT ? Number(env.RATE_LIMIT) : undefined,
		fetchOptions: {
			allowedHosts: (env.ALLOWED_HOSTS || "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean)
		}
	};
	const server = createServer(config);
	const host = env.HOST || "127.0.0.1";
	const port = Number(env.PORT || 8080);
	if (!fs.existsSync(path.join(__dirname, "..", "dist", "index.html"))) {
		console.warn("dist/ fehlt: zuerst `npm run build` ausführen (oder `npm start`).");
	}
	server.listen(port, host, () => console.log(`PHP2Shell Web Check: http://${host}:${port}/`));
}

module.exports = { createServer };
