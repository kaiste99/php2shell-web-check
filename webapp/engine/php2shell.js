/*
 * PHP2Shell signal analysis (CVE-2026-109618, CVE-2026-109619).
 *
 * Pure functions, no I/O. The same file runs in the browser (as a UI5 module)
 * and in Node (loaded via server/engine.js). Output is structured codes and
 * parameters; all texts live in webapp/i18n/*.properties.
 */
sap.ui.define([], function () {
	"use strict";

	var RANK = { green: 1, orange: 2, red: 3 };

	var COOKIE_RE = /^(PHPSESSID|laravel_session|ci_session|fe_typo_user|be_typo_user|wordpress_\w*|wp-settings-[\w-]*|S?SESS[0-9a-f]{32}|PrestaShop-\w+|OCSESSID|MOODLESESSION)$/i;

	// [header, value regex or null, label]
	var PHP_HEADER_HINTS = [
		["x-pingback", null, "WordPress (X-Pingback)"],
		["link", /api\.w\.org/i, "WordPress (REST-Link)"],
		["x-drupal-cache", null, "Drupal"],
		["x-drupal-dynamic-cache", null, "Drupal"],
		["x-generator", /drupal|typo3|wordpress|joomla|contao/i, "X-Generator"],
		["x-magento-tags", null, "Magento"],
		["x-litespeed-cache", null, "LiteSpeed Cache"]
	];

	var CDN_RULES = [
		["cf-ray", null, "Cloudflare"],
		["server", /^cloudflare/i, "Cloudflare"],
		["x-amz-cf-id", null, "Amazon CloudFront"],
		["x-fastly-request-id", null, "Fastly"],
		["x-served-by", /cache-/i, "Fastly"],
		["server", /AkamaiGHost|AkamaiNetStorage/i, "Akamai"],
		["x-akamai-transformed", null, "Akamai"],
		["x-azure-ref", null, "Azure Front Door"],
		["x-sucuri-id", null, "Sucuri"],
		["via", null, "Proxy (Via)"]
	];

	var CMS_GENERATOR_RE = /wordpress|joomla|drupal|typo3|contao|prestashop|shopware|magento|phpbb|mediawiki|nextcloud|craft cms|processwire/i;

	// ---------------------------------------------------------------- versions

	/** "PHP/8.3.6-0ubuntu0.24.04.13" -> { upstream, parts, branch, suffix, raw } */
	function parsePhpVersion(text) {
		var m = /\bPHP\/(\d+)\.(\d+)\.(\d+)([0-9A-Za-z.+~-]*)/i.exec(String(text || ""));
		if (!m) {
			return null;
		}
		var parts = [+m[1], +m[2], +m[3]];
		return {
			upstream: parts.join("."),
			parts: parts,
			branch: parts[0] + "." + parts[1],
			suffix: m[4],
			raw: parts.join(".") + m[4]
		};
	}

	/** Numeric dotted compare: "8.3.36" vs "8.3.6" */
	function compareVersion(a, b) {
		var pa = String(a).split(".").map(Number), pb = String(b).split(".").map(Number);
		for (var i = 0; i < Math.max(pa.length, pb.length); i++) {
			var d = (pa[i] || 0) - (pb[i] || 0);
			if (d) {
				return d < 0 ? -1 : 1;
			}
		}
		return 0;
	}

	function isDigit(c) {
		return c !== undefined && c >= "0" && c <= "9";
	}

	function debOrder(c) {
		if (c === undefined || isDigit(c)) {
			return 0;
		}
		if (c === "~") {
			return -1;
		}
		if (/[A-Za-z]/.test(c)) {
			return c.charCodeAt(0);
		}
		return c.charCodeAt(0) + 256;
	}

	// dpkg's verrevcmp()
	function compareDebPart(a, b) {
		var i = 0, j = 0;
		while (i < a.length || j < b.length) {
			var firstDiff = 0;
			while ((i < a.length && !isDigit(a[i])) || (j < b.length && !isDigit(b[j]))) {
				var ac = debOrder(a[i]), bc = debOrder(b[j]);
				if (ac !== bc) {
					return ac - bc;
				}
				i++;
				j++;
			}
			while (a[i] === "0") {
				i++;
			}
			while (b[j] === "0") {
				j++;
			}
			while (isDigit(a[i]) && isDigit(b[j])) {
				if (!firstDiff) {
					firstDiff = a.charCodeAt(i) - b.charCodeAt(j);
				}
				i++;
				j++;
			}
			if (isDigit(a[i])) {
				return 1;
			}
			if (isDigit(b[j])) {
				return -1;
			}
			if (firstDiff) {
				return firstDiff;
			}
		}
		return 0;
	}

	function splitDeb(v) {
		var epoch = 0, rest = String(v), c = rest.indexOf(":");
		if (c > -1) {
			epoch = parseInt(rest.slice(0, c), 10) || 0;
			rest = rest.slice(c + 1);
		}
		var d = rest.lastIndexOf("-");
		return {
			epoch: epoch,
			upstream: d > -1 ? rest.slice(0, d) : rest,
			revision: d > -1 ? rest.slice(d + 1) : "0"
		};
	}

	/** Debian package version compare (epoch:upstream-revision, "~" sorts first). */
	function compareDeb(a, b) {
		var pa = splitDeb(a), pb = splitDeb(b);
		var r = (pa.epoch - pb.epoch) || compareDebPart(pa.upstream, pb.upstream) || compareDebPart(pa.revision, pb.revision);
		return r < 0 ? -1 : r > 0 ? 1 : 0;
	}

	function distroFromText(text) {
		var t = String(text || "");
		if (/ubuntu/i.test(t)) {
			return "Ubuntu";
		}
		if (/debian|~deb\d/i.test(t)) {
			return "Debian";
		}
		if (/red ?hat|rhel|centos|almalinux|rocky|cloudlinux|fedora|amazon linux|\.el\d/i.test(t)) {
			return "RHEL/CentOS/Alma/Rocky";
		}
		return null;
	}

	// ---------------------------------------------------------------- headers

	function addHeader(headers, name, value) {
		var key = String(name).toLowerCase();
		(headers[key] = headers[key] || []).push(String(value));
	}

	function getHeader(headers, name) {
		var v = headers && headers[name];
		if (v === undefined || v === null) {
			return [];
		}
		return Array.isArray(v) ? v.map(String) : [String(v)];
	}

	/**
	 * Parses pasted header text, e.g. the output of `curl -sIL https://example.ch`
	 * or "Copy response headers" from browser dev tools. Each HTTP status line
	 * starts a new response (redirect chains).
	 */
	function parseHeaderBlock(text) {
		var responses = [], current = null;
		String(text || "").split(/\r?\n/).forEach(function (rawLine) {
			var line = rawLine.trim();
			if (!line) {
				return;
			}
			var status = /^HTTP\/[\d.]+\s+(\d{3})/i.exec(line);
			if (status) {
				current = { status: +status[1], headers: {} };
				responses.push(current);
				return;
			}
			var m = /^([!#$%&'*+.^_`|~0-9A-Za-z-]+):\s*(.*)$/.exec(line);
			if (!m) {
				return;
			}
			if (!current) {
				current = { status: null, headers: {} };
				responses.push(current);
			}
			addHeader(current.headers, m[1], m[2]);
		});
		return responses;
	}

	// ---------------------------------------------------------------- signals

	function collectSignals(responses, body) {
		var versions = [], hints = [], cdn = [], shown = [], distro = null;

		// Remote-controlled text: single line, bounded length
		function clean(value, max) {
			return String(value).replace(/\s+/g, " ").trim().slice(0, max);
		}
		function show(name, value) {
			var v = clean(value, 200);
			if (shown.length < 40 && !shown.some(function (s) { return s.name === name && s.value === v; })) {
				shown.push({ name: name, value: v });
			}
		}
		function hint(label) {
			label = clean(label, 80);
			if (hints.indexOf(label) === -1) {
				hints.push(label);
			}
		}

		(responses || []).forEach(function (r) {
			var h = r.headers || {};

			getHeader(h, "x-powered-by").forEach(function (val) {
				show("X-Powered-By", val);
				var v = parsePhpVersion(val);
				if (v) {
					v.source = "X-Powered-By";
					versions.push(v);
				} else if (/php/i.test(val)) {
					hint("X-Powered-By: " + val.slice(0, 60));
				}
			});

			getHeader(h, "server").forEach(function (val) {
				show("Server", val);
				var v = parsePhpVersion(val);
				if (v) {
					v.source = "Server";
					versions.push(v);
				}
				if (/litespeed/i.test(val)) {
					hint("LiteSpeed");
				}
				distro = distro || distroFromText(val);
			});

			getHeader(h, "set-cookie").forEach(function (val) {
				var name = val.split("=")[0].trim();
				if (COOKIE_RE.test(name)) {
					hint("Cookie " + name);
					show("Set-Cookie", name + "=…");
				}
			});

			PHP_HEADER_HINTS.forEach(function (rule) {
				getHeader(h, rule[0]).forEach(function (val) {
					if (!rule[1] || rule[1].test(val)) {
						hint(rule[2]);
						show(rule[0], val);
					}
				});
			});

			CDN_RULES.forEach(function (rule) {
				getHeader(h, rule[0]).forEach(function (val) {
					if ((!rule[1] || rule[1].test(val)) && cdn.indexOf(rule[2]) === -1) {
						cdn.push(rule[2]);
						show(rule[0], val);
					}
				});
			});
		});

		var html = String(body || "");
		(html.match(/<meta\b[^>]*>/gi) || []).forEach(function (tag) {
			if (/name\s*=\s*["']?generator/i.test(tag)) {
				var c = /content\s*=\s*["']([^"']*)/i.exec(tag);
				if (c && CMS_GENERATOR_RE.test(c[1])) {
					hint("Generator: " + c[1].slice(0, 60));
					show("meta generator", c[1]);
				}
			}
		});
		if (/\/wp-(content|includes)\//i.test(html)) {
			hint("WordPress (/wp-content/)");
		}

		return { versions: versions, hints: hints, cdn: cdn, distro: distro, shown: shown };
	}

	// ---------------------------------------------------------------- verdict

	function evaluateVersion(v, serverDistro, fix) {
		var fixed = fix.upstreamFixed[v.branch];
		var branches = Object.keys(fix.upstreamFixed).sort(compareVersion);

		function result(verdict, code, params, eol) {
			return { verdict: verdict, finding: { code: code, params: params }, v: v, eol: !!eol };
		}

		if (fixed && compareVersion(v.upstream, fixed) >= 0) {
			return result("green", "UPSTREAM_FIXED", [v.upstream, fixed]);
		}
		if (!fixed && compareVersion(v.branch, branches[branches.length - 1]) > 0) {
			return result("green", "NEWER_BRANCH", [v.upstream]);
		}

		var d = (fix.distros || []).filter(function (x) { return new RegExp(x.match).test(v.raw); })[0];
		if (d) {
			if (d.status === "fixed" && d.fixed) {
				return compareDeb(v.raw, d.fixed) >= 0
					? result("green", "DISTRO_FIXED", [d.label, v.raw, d.fixed])
					: result("red", "DISTRO_BELOW_FIX", [d.label, v.raw, d.fixed], !fixed);
			}
			if (d.status === "no-fix") {
				return result("red", "DISTRO_NO_FIX", [d.label, v.raw], !fixed);
			}
			return result("orange", "DISTRO_UNCONFIRMED", [d.label, v.raw], !fixed);
		}

		// deb.sury.org builds ship upstream releases, no backports
		var build = /sury/i.test(v.suffix) ? null : (distroFromText(v.suffix) || (v.suffix ? v.suffix : null) || serverDistro);
		if (build) {
			return result("orange", "BACKPORT_POSSIBLE", [v.upstream, build], !fixed);
		}
		if (!fixed) {
			return result("red", "EOL_BRANCH", [v.upstream], true);
		}
		return result("red", "UPSTREAM_BELOW_FIX", [v.upstream, fixed]);
	}

	function hostOf(url) {
		var m = /^[a-z]+:\/\/([^/:?#]+)/i.exec(String(url || ""));
		return m ? m[1].toLowerCase() : "";
	}

	/**
	 * @param {object} input  { responses: [{status, headers}], body?, requestedUrl?, finalUrl? }
	 * @param {object} fix    content of webapp/model/fixdata.json
	 */
	function analyze(input, fix) {
		input = input || {};
		var sig = collectSignals(input.responses, input.body);
		var findings = [], actions = [], notes = [];
		var verdict, php = { detected: false }, eol = false;

		if (sig.versions.length) {
			var evals = sig.versions.map(function (v) { return evaluateVersion(v, sig.distro, fix); });
			var worst = evals.reduce(function (w, e) { return RANK[e.verdict] > RANK[w.verdict] ? e : w; });
			verdict = worst.verdict;
			eol = evals.some(function (e) { return e.eol; });
			php = { detected: true, version: worst.v.upstream, raw: worst.v.raw, source: worst.v.source };
			findings.push({ code: "PHP_VERSION_FOUND", params: [worst.v.raw, worst.v.source] });
			findings.push(worst.finding);
			var raws = sig.versions.map(function (v) { return v.raw; }).filter(function (r, i, a) { return a.indexOf(r) === i; });
			if (raws.length > 1) {
				findings.push({ code: "MULTIPLE_VERSIONS", params: [raws.join(", ")] });
			}
		} else if (sig.hints.length) {
			verdict = "orange";
			php = { detected: true };
			findings.push({ code: "PHP_NO_VERSION", params: [sig.hints.join(", ")] });
		} else {
			verdict = "grey";
			findings.push({ code: "NO_PHP_SIGNAL", params: [] });
		}

		var fixedList = Object.keys(fix.upstreamFixed).sort(compareVersion).reverse()
			.map(function (b) { return fix.upstreamFixed[b]; }).join(", ");

		if (verdict === "red") {
			actions.push({ code: "PATCH", params: [fixedList] }, { code: "RESTART", params: [] }, { code: "MITIGATE", params: [] });
		} else if (verdict === "orange") {
			actions.push({ code: "LOCAL_CHECK", params: [] }, { code: "PATCH", params: [fixedList] }, { code: "MITIGATE", params: [] });
		} else if (verdict === "green") {
			actions.push({ code: "CHECK_ALL_NODES", params: [] });
		} else {
			actions.push({ code: "LOCAL_CHECK", params: [] });
		}
		if (eol) {
			actions.push({ code: "EOL_UPGRADE", params: [] });
		}
		if (sig.versions.length) {
			actions.push({ code: "HIDE_VERSION", params: [] });
		}

		notes.push({ code: "REMOTE_LIMITS", params: [] });
		if (sig.cdn.length) {
			notes.push({ code: "CDN", params: [sig.cdn.join(", ")] });
		}
		if (input.tlsLegacy) {
			notes.push({ code: "TLS_LEGACY", params: [] });
		}
		if (input.finalUrl && hostOf(input.finalUrl) !== hostOf(input.requestedUrl)) {
			notes.push({ code: "REDIRECTED", params: [input.finalUrl] });
		}
		notes.push({ code: "DATA_AS_OF", params: [fix.asOf] });

		return {
			verdict: verdict,
			php: php,
			findings: findings,
			actions: actions,
			notes: notes,
			signals: sig.shown,
			requestedUrl: input.requestedUrl || null,
			finalUrl: input.finalUrl || null
		};
	}

	return {
		analyze: analyze,
		parseHeaderBlock: parseHeaderBlock,
		parsePhpVersion: parsePhpVersion,
		compareVersion: compareVersion,
		compareDeb: compareDeb
	};
});
