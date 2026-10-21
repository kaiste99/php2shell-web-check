sap.ui.define([
	"sap/ui/core/UIComponent",
	"sap/ui/core/Theming"
], function (UIComponent, Theming) {
	"use strict";

	return UIComponent.extend("baltx.php2shell.Component", {
		metadata: {
			manifest: "json",
			interfaces: ["sap.ui.core.IAsyncContentCreation"]
		},

		init: function () {
			UIComponent.prototype.init.apply(this, arguments);
			// Follow the operating system: Horizon light or dark
			var dark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)");
			var apply = function () {
				Theming.setTheme(dark && dark.matches ? "sap_horizon_dark" : "sap_horizon");
			};
			apply();
			if (dark && dark.addEventListener) {
				dark.addEventListener("change", apply);
			}
		}
	});
});
