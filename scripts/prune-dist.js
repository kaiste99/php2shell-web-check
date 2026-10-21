"use strict";
// Removes build output that the self-contained app never loads at runtime:
// debug sources, source maps, theme sources, test helpers, unused themes.
const fs = require("node:fs");
const path = require("node:path");

const dist = path.join(__dirname, "..", "dist");
const dropFile = /(-dbg(\.[\w-]+)?\.js|\.map|\.less)$/;
const dropDir = new Set(["test-resources", path.join("resources", "sap", "ui", "test")]);

let removed = 0;
function walk(dir) {
	for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
		const full = path.join(dir, entry.name);
		const rel = path.relative(dist, full);
		if (entry.isDirectory()) {
			if (dropDir.has(rel) || entry.name === "sap_hcb") {
				fs.rmSync(full, { recursive: true });
				removed++;
			} else walk(full);
		} else if (dropFile.test(entry.name)) {
			fs.rmSync(full);
			removed++;
		}
	}
}

walk(dist);
console.log(`prune-dist: ${removed} Einträge entfernt`);
