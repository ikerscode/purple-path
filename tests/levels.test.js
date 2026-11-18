import { test } from "node:test";
import assert from "node:assert/strict";
import levels from "../levels/index.js";
import { runCommand, newTerminal, BUILTINS } from "../js/engine/terminal.js";
import { newSession, applyInput, matchesAnswer } from "../js/engine/checks.js";
import { defineLevelTests } from "./helpers/level-suite.js";


test("there are levels and they are ordered contiguously with unique ids", () => {
  assert.ok(levels.length >= 2);
  const ids = levels.map((l) => l.id);
  assert.equal(new Set(ids).size, ids.length, "ids unique");
  levels.forEach((l, i) => assert.equal(l.order, i + 1, `order of ${l.id}`));
  levels.forEach((l) => assert.match(l.id, /^\d{2}-[a-z0-9-]+$/));
});

for (const level of levels) defineLevelTests(level);

test("built-ins work", () => {
  const level = levels[0];
  const term = newTerminal(level);
  const run = (l) => runCommand(level, term, l);

  assert.deepEqual(BUILTINS.slice().sort(), ["cat", "cd", "clear", "help", "hint", "ls", "pwd", "whoami"]);
  assert.match(run("help").output, /hint/);
  assert.equal(run("whoami").output, level.world.user);
  assert.equal(run("pwd").output, level.world.cwd);
  assert.equal(run("clear").clear, true);
  assert.equal(run("").output, "");
  assert.equal(run("   ").output, "");

  const ls = run("ls").output.split("\n");
  assert.ok(ls.includes("README.txt"));
  assert.ok(ls.includes("engagement"), "directories are listed without a trailing slash");
  assert.ok(!ls.some((n) => n.endsWith("/")));
  assert.deepEqual(run("ls -a").output.split("\n").slice(0, 2), [".", ".."]);
  assert.equal(run("ls -A").output, run("ls").output);
  for (const l of ["ls -l", "ls -la", "ls -F", "ls -p engagement"]) {
    const r = run(l);
    assert.equal(r.handled, false, l);
    assert.match(r.output, /not modelled/);
  }
  assert.ok(run("ls engagement").output.includes("scope.txt"));
  assert.match(run("ls nope").output, /No such file/);

  const cat = run("cat README.txt");
  assert.ok(cat.output.length > 0);
  assert.deepEqual(cat.events, [`read:${level.world.cwd}/README.txt`]);
  assert.match(run("cat missing.txt").output, /No such file/);
  const bare = run("cat");
  assert.match(bare.output, /^\[simulation\] cat needs a file name/);
  assert.doesNotMatch(bare.output, /missing file operand/);
  assert.deepEqual(bare.events, []);
  assert.match(run("cat engagement").output, /Is a directory/);
  assert.match(run("cat /home/analyst/engagement/scope.txt").output, /AUTHORISATION/);

  assert.equal(run("cd engagement").output, "");
  assert.equal(run("pwd").output, `${level.world.cwd}/engagement`);
  assert.ok(run("cat scope.txt").events[0].endsWith("/engagement/scope.txt"));
  run("cd ..");
  assert.equal(run("pwd").output, level.world.cwd);
  assert.equal(run("cd nowhere").output, "bash: cd: nowhere: No such file or directory");

  const h1 = run("hint").output;
  const h2 = run("hint").output;
  assert.match(h1, /^hint 1\//);
  assert.match(h2, /^hint 2\//);
  for (let i = 0; i < 6; i++) run("hint");
  assert.match(run("hint").output, new RegExp(`^hint ${level.hints.length}/`));

  const unknown = run("rm -rf /");
  assert.equal(unknown.handled, false);
  assert.match(unknown.output, /not modelled/);
  assert.deepEqual(unknown.events, []);
});

test("commands are matched case-insensitively on a whitespace-collapsed line", () => {
  const level = levels[0];
  const term = newTerminal(level);
  const r = runCommand(level, term, "   NMAP    192.0.2.10  ");
  assert.deepEqual(r.events, ["scanned:192.0.2.10"]);
  assert.match(r.output, /^Starting Nmap 7\.98 /);
});

test("answers: case-insensitive, trimmed, string or array", () => {
  assert.ok(matchesAnswer({ value: "Two" }, "  two "));
  assert.ok(matchesAnswer({ value: ["2", "two"] }, "TWO"));
  assert.equal(matchesAnswer({ value: ["2", "two"] }, "three"), false);
  assert.equal(matchesAnswer({ value: "x" }, ""), false);
});

test("answer objectives are not satisfied by a wrong answer", () => {
  const level = levels[0];
  const s = newSession(level);
  const r = applyInput(level, s, "5");
  assert.equal(r.completed.length, 0);
  assert.equal(s.done.has("count-hosts"), false);
});

test("level 2: dig shows the records, scanning the listed hosts ends the engagement", () => {
  const level = levels[1];
  const t = newTerminal(level);
  assert.equal(runCommand(level, t, "dig +short MX northwind.example").output, "10 mx1.mail-provider.example.\n20 mx2.mail-provider.example.");
  assert.equal(runCommand(level, t, "dig northwind.example NS +short").events[0], "dns:ns");
  assert.equal(runCommand(level, t, "dig +short A vpn.northwind.example").output, "203.0.113.20");
  assert.equal(runCommand(level, t, "dig +short A nothing.northwind.example").output, "");
  assert.equal(runCommand(level, t, "dig +short A example.org").handled, false);
  assert.equal(runCommand(level, t, "dig MX northwind.example").handled, false, "only +short is modelled");
  assert.equal(runCommand(level, t, "nmap 203.0.113.20").terminated, true);
});

test("level 2: SOA, AXFR, ANY and IXFR are not modelled rather than answered with empty output", () => {
  const level = levels[1];
  const t = newTerminal(level);
  for (const l of [
    "dig +short SOA northwind.example",
    "dig +short AXFR northwind.example",
    "dig +short ANY northwind.example",
    "dig +short IXFR northwind.example",
    "dig +short ixfr=1 northwind.example",
    "dig +short SOA nothing.northwind.example",
    "dig +short northwind.example SOA",
  ]) {
    const r = runCommand(level, t, l);
    assert.equal(r.handled, false, l);
    assert.match(r.output, /not modelled/, l);
  }
  assert.equal(runCommand(level, t, "dig +short AAAA northwind.example").output, "");
});

test("out-of-scope message does not claim traffic was sent", () => {
  for (const level of levels) assert.doesNotMatch(level.outOfScope.message, /sent traffic/);
});
