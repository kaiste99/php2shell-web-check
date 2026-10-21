sap.ui.define([
	"sap/ui/core/mvc/Controller",
	"sap/ui/model/json/JSONModel",
	"sap/ui/Device",
	"baltx/php2shell/engine/php2shell"
], function (Controller, JSONModel, Device, engine) {
	"use strict";

	var MAX_PASTE = 64 * 1024;
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
				footer: ""
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

			if (model.getProperty("/mode") === "headers") {
				var text = String(model.getProperty("/headersText") || "").slice(0, MAX_PASTE);
				if (!text.trim()) {
					return Promise.reject(failure("EMPTY_INPUT"));
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

			this._model.setProperty("/result", {
				verdict: result.verdict,
				icon: look.icon,
				color: look.color,
				title: t("verdict." + result.verdict + ".title"),
				text: t("verdict." + result.verdict + ".text"),
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
