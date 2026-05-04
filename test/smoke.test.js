import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const packageJson = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));

assert.equal(packageJson.main, "dist/index.js");
assert.equal(packageJson.scripts.start, "node dist/index.js");

console.log("smoke tests passed");
