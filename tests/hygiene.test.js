import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { loadProgress, saveProgress, markComplete, isUnlocked, isComplete, emptyProgress, resetProgress } from "../js/engine/state.js";
import levels from "../levels/index.js";

const root = join(fileURLToPath(new URL(".", import.meta.url)), "..");

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (name === "node_modules" || name.startsWith(".")) continue;
    const p = join(dir, name);
    statSync(p).isDirectory() ? walk(p, out) : out.push(p);
  }
  return out;
}

const files = walk(root);
const jsFiles = files.filter((f) => f.endsWith(".js") && !relative(root, f).startsWith("tests"));
const sourceFiles = [...jsFiles, join(root, "index.html"), ...files.filter((f) => f.endsWith(".css"))];

test("no HTML string injection APIs anywhere in the game", () => {
  for (const f of sourceFiles) {
    const text = readFileSync(f, "utf8");
    assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/.test(text), `${relative(root, f)}`);
  }
});

test("no http/https URLs in js/ or index.html (source links live in level data only)", () => {
  const targets = [...jsFiles.filter((f) => relative(root, f).startsWith("js")), join(root, "index.html")];
  for (const f of targets) {
    assert.ok(!/https?:\/\//i.test(readFileSync(f, "utf8")), `${relative(root, f)}`);
  }
});

test("css loads nothing from outside the site", () => {
  for (const f of files.filter((x) => x.endsWith(".css"))) {
    const text = readFileSync(f, "utf8");
    assert.ok(!/https?:\/\//i.test(text));
    assert.ok(!/@import/.test(text));
    for (const m of text.matchAll(/url\(([^)]+)\)/g)) assert.ok(!/^["']?(https?:|\/\/|data:)/i.test(m[1]), m[1]);
  }
});

test("index.html has the strict CSP meta and no inline script or style", () => {
  const html = readFileSync(join(root, "index.html"), "utf8");
  assert.match(html, /http-equiv="Content-Security-Policy"\s+content="default-src 'self'/);
  assert.ok(!/<script(?![^>]*\bsrc=)[^>]*>/i.test(html), "inline script");
  assert.ok(!/<style/i.test(html), "inline style element");
  assert.ok(!/\sstyle=/i.test(html), "inline style attribute");
  assert.ok(!/\son[a-z]+=/i.test(html), "inline handler");
});

test("the terminal is labelled as simulated", () => {
  const ui = readFileSync(join(root, "js/ui/terminal-view.js"), "utf8");
  assert.match(ui, /simulated — nothing here touches a real system/);
});

function memoryStorage() {
  const m = new Map();
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k) };
}

test("progress persists, unlocks in order, and survives broken storage", () => {
  const st = memoryStorage();
  const p = loadProgress(st);
  assert.deepEqual(p, emptyProgress());
  assert.equal(isUnlocked(p, levels, 0), true);
  assert.equal(isUnlocked(p, levels, 1), false);
  markComplete(p, levels[0].id);
  assert.equal(saveProgress(p, st), true);
  const q = loadProgress(st);
  assert.ok(isComplete(q, levels[0].id));
  assert.equal(isUnlocked(q, levels, 1), true);
  assert.equal(resetProgress(st), true);
  assert.deepEqual(loadProgress(st), emptyProgress());

  const broken = { getItem() { throw new Error("denied"); }, setItem() { throw new Error("denied"); }, removeItem() { throw new Error("denied"); } };
  assert.deepEqual(loadProgress(broken), emptyProgress());
  assert.equal(saveProgress(p, broken), false);
  assert.equal(resetProgress(broken), false);

  const junk = memoryStorage();
  junk.setItem("purple-path:v1", "{not json");
  assert.deepEqual(loadProgress(junk), emptyProgress());
  assert.deepEqual(loadProgress(null), emptyProgress());
});
