sap.ui.define([
	"sap/ui/core/mvc/Controller",
	"sap/ui/model/json/JSONModel",
	"sap/ui/Device",
	"sap/m/MessageToast",
	"sap/base/strings/formatMessage",
	"baltx/php2shell/engine/php2shell"
], function (Controller, JSONModel, Device, MessageToast, formatMessage, engine) {
	"use strict";

	var MAX_PASTE = 64 * 1024;

	// Prints only what the self-test needs, no full phpinfo()
	var SELFTEST_CODE = [
		"<?php",
		"// PHP2Shell-Selbsttest (CVE-2026-109618, CVE-2026-109619). Nach dem Aufruf sofort loeschen!",
		"header('Content-Type: text/plain; charset=utf-8');",
		"header('Cache-Control: no-store');",
		"header('X-Robots-Tag: noindex');",
		"echo 'PHP_VERSION = ', PHP_VERSION, \"\\n\";",
		"echo 'PHP_SAPI = ', PHP_SAPI, \"\\n\";",
		"$os = @parse_ini_file('/etc/os-release');",
		"echo 'OS_RELEASE = ', isset($os['ID']) ? $os['ID'] . ' ' . (isset($os['VERSION_ID']) ? $os['VERSION_ID'] : '') : '?', \"\\n\";",
		"foreach (['memory_limit', 'session.upload_progress.enabled', 'fatal_error_backtraces',",
		"          'post_max_size', 'max_input_nesting_level'] as $k) {",
		"    echo $k, ' = ', var_export(ini_get($k), true), \"\\n\";",
		"}",
		""
	].join("\n");

	function randomFileName() {
		var bytes = new Uint8Array(5);
		window.crypto.getRandomValues(bytes);
		return "php2shell-check-" + Array.prototype.map.call(bytes, function (b) {
			return ("0" + b.toString(16)).slice(-2);
		}).join("") + ".php";
	}
	var VERDICTS = {
		red: { icon: "sap-icon://error", color: "Negative" },
		orange: { icon: "sap-icon://alert", color: "Critical" },
		green: { icon: "sap-icon://sys-enter-2", color: "Positive" },
		grey: { icon: "sap-icon://question-mark", color: "Neutral" }
	};

	function failure(code) {
		var e = new Error(code);
		e.code = code;
		return e;
	}

	return Controller.extend("baltx.php2shell.controller.Main", {

		onInit: function () {
			this.getView().addStyleClass(Device.support.touch ? "sapUiSizeCozy" : "sapUiSizeCompact");
			this._model = new JSONModel({
				mode: "url",
				url: "",
				headersText: "",
				busy: false,
				apiAvailable: null,
				result: null,
				error: null,
				intro: "",
				footer: "",
				selftestFile: randomFileName(),
				selftestCode: SELFTEST_CODE,
				selftestText: ""
			});
			this.getView().setModel(this._model, "view");

			var fixModel = this.getOwnerComponent().getModel("fix");
			fixModel.dataLoaded().then(this._applyFixData.bind(this));
			this._pingApi();
		},

		_text: function (key, params) {
			return this.getOwnerComponent().getModel("i18n").getResourceBundle().getText(key, params);
		},

		_fix: function () {
			return this.getOwnerComponent().getModel("fix").getData();
		},

		_applyFixData: function () {
			var fix = this._fix();
			var fixed = Object.keys(fix.upstreamFixed).sort(engine.compareVersion).reverse()
				.map(function (b) { return fix.upstreamFixed[b]; }).join(", ");
			this._model.setProperty("/intro", this._text("intro", [fixed]));
			this._model.setProperty("/footer", this._text("footer.disclaimer") + " " + this._text("note.DATA_AS_OF", [fix.asOf]));
		},

		// The URL check needs server/index.js. On static hosting (GitHub Pages)
		// only the header mode is available.
		_pingApi: function () {
			var model = this._model;
			fetch("api/health", { headers: { Accept: "application/json" } })
				.then(function (res) { return res.ok ? res.json() : null; })
				.catch(function () { return null; })
				.then(function (data) {
					var available = !!(data && data.ok);
					model.setProperty("/apiAvailable", available);
					if (!available) {
						model.setProperty("/mode", "headers");
					}
				});
		},

		onModeChange: function () {
			this._model.setProperty("/error", null);
		},

		formatText: function (pattern, value) {
			return pattern ? formatMessage(pattern, [value]) : "";
		},

		onCopySelftest: function () {
			var text = this._text("selftest.copied");
			navigator.clipboard.writeText(SELFTEST_CODE).then(function () {
				MessageToast.show(text);
			}, function () {
				this.byId("selftestCode").focus();
			}.bind(this));
		},

		onCheck: function () {
			var model = this._model;
			model.setProperty("/error", null);
			model.setProperty("/result", null);
			model.setProperty("/busy", true);

			this._runCheck()
				.then(this._showResult.bind(this))
				.catch(function (err) {
					var key = "error." + (err && err.code ? err.code : "NETWORK");
					var text = this._text(key);
					model.setProperty("/error", text === key ? this._text("error.API") : text);
				}.bind(this))
				.finally(function () {
					model.setProperty("/busy", false);
				});
		},

		_runCheck: function () {
			var model = this._model;
			var fix = this._fix();

			if (model.getProperty("/mode") === "selftest") {
				var output = String(model.getProperty("/selftestText") || "").slice(0, MAX_PASTE);
				if (!output.trim()) {
					return Promise.reject(failure("EMPTY_INPUT"));
				}
				try {
					return Promise.resolve(engine.analyzeSelftest(output, fix));
				} catch (e) {
					return Promise.reject(e);
				}
			}

			if (model.getProperty("/mode") === "headers") {
				var text = String(model.getProperty("/headersText") || "").slice(0, MAX_PASTE);
				if (!text.trim()) {
					return Promise.reject(failure("EMPTY_INPUT"));
				}
				if (/<\?php/i.test(text)) {
					return Promise.reject(failure("PASTED_CODE"));
				}
				var responses = engine.parseHeaderBlock(text);
				if (!responses.length) {
					return Promise.reject(failure("NO_HEADERS"));
				}
				return Promise.resolve(engine.analyze({ responses: responses }, fix));
			}

			var url = String(model.getProperty("/url") || "").trim();
			if (!url) {
				return Promise.reject(failure("EMPTY_INPUT"));
			}
			return fetch("api/check", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ url: url })
			}).then(function (res) {
				return res.json().catch(function () { return { error: "API" }; }).then(function (data) {
					if (!res.ok) {
						throw failure(data.error || "API");
					}
					return data;
				});
			}, function () {
				throw failure("NETWORK");
			});
		},

		_showResult: function (result) {
			var t = this._text.bind(this);
			var texts = function (kind, list, numbered) {
				return list.map(function (item, i) {
					var line = t(kind + "." + item.code, item.params);
					return { text: numbered ? (i + 1) + ". " + line : line };
				});
			};
			var look = VERDICTS[result.verdict];
			var suffix = result.kind === "selftest" ? ".selftest" : "";

			this._model.setProperty("/result", {
				verdict: result.verdict,
				icon: look.icon,
				color: look.color,
				title: t("verdict." + result.verdict + ".title" + suffix),
				text: t("verdict." + result.verdict + ".text" + suffix),
				checked: result.requestedUrl ? t("checkedUrl", [result.requestedUrl]) : "",
				findings: texts("finding", result.findings),
				actions: texts("action", result.actions, true),
				notes: texts("note", result.notes),
				signals: result.signals
			});

			var box = this.byId("verdictBox");
			Object.keys(VERDICTS).forEach(function (v) {
				box.removeStyleClass("p2sVerdict-" + v);
			});
			box.addStyleClass("p2sVerdict-" + result.verdict);
		}
	});
});
