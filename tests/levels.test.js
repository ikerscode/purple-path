import { test } from "node:test";
import assert from "node:assert/strict";
import levels from "../levels/index.js";
import { runCommand, newTerminal, BUILTINS } from "../js/engine/terminal.js";
import { runSolution, newSession, applyInput, isChallengeComplete, checkDefence, checkQuiz, matchesAnswer } from "../js/engine/checks.js";

const TIERS = ["beginner", "intermediate", "advanced"];
const RFC5737 = [/^192\.0\.2\.\d{1,3}$/, /^198\.51\.100\.\d{1,3}$/, /^203\.0\.113\.\d{1,3}$/];
const IPV4_IN_TEXT = /\b(\d{1,3}\.){3}\d{1,3}\b/g;

const isStr = (v) => typeof v === "string" && v.trim().length > 0;
const isStrArr = (v) => Array.isArray(v) && v.length > 0 && v.every(isStr);

function noFunctions(value, path) {
  if (typeof value === "function") assert.fail(`function in level data at ${path}`);
  if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) noFunctions(v, `${path}.${k}`);
  }
}

function checkShape(check, where) {
  assert.ok(check && typeof check === "object", `${where}: check object`);
  assert.ok(["event", "answer", "choice"].includes(check.type), `${where}: check type`);
  if (check.type === "event") {
    assert.ok(isStr(check.value), `${where}: event value`);
  } else if (check.type === "answer") {
    assert.ok(isStr(check.value) || isStrArr(check.value), `${where}: answer value`);
  } else {
    assert.ok(isStr(check.value), `${where}: choice value`);
    assert.ok(Array.isArray(check.options) && check.options.length >= 2, `${where}: choice options`);
    assert.ok(check.options.includes(check.value), `${where}: choice value must be one of the options`);
    assert.equal(new Set(check.options).size, check.options.length, `${where}: duplicate options`);
  }
}

test("there are levels and they are ordered contiguously with unique ids", () => {
  assert.ok(levels.length >= 2);
  const ids = levels.map((l) => l.id);
  assert.equal(new Set(ids).size, ids.length, "ids unique");
  levels.forEach((l, i) => assert.equal(l.order, i + 1, `order of ${l.id}`));
  levels.forEach((l) => assert.match(l.id, /^\d{2}-[a-z0-9-]+$/));
});

for (const level of levels) {
  test(`${level.id}: schema`, () => {
    noFunctions(level, level.id);
    assert.ok(TIERS.includes(level.tier));
    assert.ok(isStr(level.title) && isStr(level.term));
    for (const k of ["what", "why", "example"]) assert.ok(isStr(level.card[k]), `card.${k}`);
    assert.ok(level.world && typeof level.world === "object");
    assert.ok(Array.isArray(level.world.hosts));
    assert.ok(level.world.files && typeof level.world.files === "object");
    assert.ok(isStr(level.world.user) && isStr(level.world.cwd));
    for (const h of level.world.hosts) {
      assert.ok(isStr(h.ip) && isStr(h.hostname) && typeof h.inScope === "boolean");
      assert.ok(Array.isArray(h.services));
      for (const s of h.services) {
        assert.ok(Number.isInteger(s.port) && isStr(s.proto) && isStr(s.state) && isStr(s.service));
        assert.equal(typeof s.version, "string");
      }
    }
    assert.ok(Array.isArray(level.commands) && level.commands.length > 0);
    for (const c of level.commands) {
      assert.equal(typeof c.match, "string");
      assert.equal(typeof c.output, "string");
      assert.ok(c.event === undefined || isStr(c.event));
    }
    assert.ok(level.outOfScope && isStrArr(level.outOfScope.hosts) && isStr(level.outOfScope.message));
    assert.ok(Array.isArray(level.objectives) && level.objectives.length > 0);
    const objIds = level.objectives.map((o) => o.id);
    assert.equal(new Set(objIds).size, objIds.length, "objective ids unique");
    for (const o of level.objectives) {
      assert.ok(isStr(o.id) && isStr(o.prompt) && isStr(o.success));
      checkShape(o.check, `objective ${o.id}`);
    }
    assert.ok(isStr(level.defence.prompt) && isStr(level.defence.explanation));
    assert.ok(["choice", "answer"].includes(level.defence.check.type));
    checkShape(level.defence.check, "defence");
    assert.ok(isStr(level.quiz.question) && isStr(level.quiz.explanation));
    assert.equal(level.quiz.options.length, 4);
    assert.ok(level.quiz.options.every(isStr));
    assert.ok(Number.isInteger(level.quiz.answer) && level.quiz.answer >= 0 && level.quiz.answer < 4);
    assert.ok(Array.isArray(level.glossary) && level.glossary.length > 0);
    for (const g of level.glossary) assert.ok(isStr(g.term) && isStr(g.definition));
    assert.ok(isStrArr(level.hints) && level.hints.length >= 2);
    assert.ok(isStrArr(level.solution));
    assert.ok(Array.isArray(level.sources));
  });

  test(`${level.id}: sources >= 5, all https, each with a claim`, () => {
    assert.ok(level.sources.length >= 5, `has ${level.sources.length} sources`);
    for (const s of level.sources) {
      assert.ok(isStr(s.claim), "claim");
      assert.ok(isStr(s.url) && s.url.startsWith("https://"), `https: ${s.url}`);
      assert.doesNotThrow(() => new URL(s.url));
    }
  });

  test(`${level.id}: every command match compiles`, () => {
    for (const c of level.commands) assert.doesNotThrow(() => new RegExp(c.match, "i"), c.match);
  });

  test(`${level.id}: only RFC 5737 addresses and .example/.test names`, () => {
    const text = JSON.stringify(level);
    const ips = new Set([...level.world.hosts.map((h) => h.ip), ...level.outOfScope.hosts.filter((h) => /^\d/.test(h))]);
    for (const m of text.match(IPV4_IN_TEXT) || []) {
      assert.ok(RFC5737.some((re) => re.test(m)), `non-documentation address ${m}`);
    }
    for (const ip of ips) assert.ok(RFC5737.some((re) => re.test(ip)), `host ip ${ip}`);
    for (const h of level.world.hosts) assert.match(h.hostname, /\.(example|test)$/);
    for (const h of level.outOfScope.hosts.filter((x) => !/^\d/.test(x))) assert.match(h, /\.(example|test)$/);
  });

  test(`${level.id}: solution completes every objective and the defence`, () => {
    const r = runSolution(level);
    assert.equal(r.session.terminated, false, "solution must not end the engagement");
    assert.ok(r.challengeDone, `objectives incomplete: ${level.objectives.filter((o) => !r.session.done.has(o.id)).map((o) => o.id)}`);
    assert.ok(r.defenceDone, "defence not completed by solution");
    assert.ok(checkQuiz(level, level.quiz.answer));
    for (let i = 0; i < 4; i++) if (i !== level.quiz.answer) assert.equal(checkQuiz(level, i), false);
  });

  test(`${level.id}: wrong defence answers fail, solution defence passes`, () => {
    for (const opt of level.defence.check.options || []) {
      assert.equal(checkDefence(level, opt), opt === level.defence.check.value);
    }
  });

  test(`${level.id}: objectives are not complete before any input`, () => {
    const s = newSession(level);
    assert.equal(isChallengeComplete(level, s), false);
  });

  test(`${level.id}: every out-of-scope host ends the engagement`, () => {
    for (const host of level.outOfScope.hosts) {
      for (const line of [`nmap ${host}`, `ping ${host}`, `cat ${host}`, `dig +short A ${host}`, `NMAP   ${host.toUpperCase()}`]) {
        const s = newSession(level);
        const r = applyInput(level, s, line);
        assert.equal(r.terminated, true, `${line} should terminate`);
        assert.equal(s.terminated, true);
        assert.match(r.output, /ENGAGEMENT TERMINATED/);
        assert.ok(r.events.includes("terminated:out-of-scope"));
        // once terminated, nothing else runs and nothing completes
        const again = applyInput(level, s, level.solution[0]);
        assert.equal(again.terminated, true);
        assert.equal(again.completed.length, 0);
      }
    }
  });

  test(`${level.id}: out-of-scope hosts are not mistaken for similar addresses`, () => {
    for (const host of level.outOfScope.hosts.filter((h) => /^\d/.test(h))) {
      const s = newSession(level);
      const r = applyInput(level, s, `nmap ${host}0`);
      assert.equal(r.terminated, false);
    }
  });

  test(`${level.id}: out-of-scope host inside a CIDR range ends the engagement`, () => {
    const ip = level.outOfScope.hosts.find((h) => /^\d/.test(h));
    if (!ip) return;
    const parts = ip.split(".");
    const s = newSession(level);
    const r = applyInput(level, s, `nmap ${parts[0]}.${parts[1]}.${parts[2]}.0/24`);
    assert.equal(r.terminated, true);
  });

  test(`${level.id}: the solution never names an out-of-scope host`, () => {
    for (const step of level.solution) {
      for (const h of level.outOfScope.hosts) assert.ok(!step.toLowerCase().includes(h.toLowerCase()));
    }
  });

  test(`${level.id}: world files are well formed and cwd exists`, () => {
    for (const [p, c] of Object.entries(level.world.files)) {
      assert.ok(p.startsWith("/"), p);
      assert.equal(typeof c, "string");
    }
    assert.ok(Object.keys(level.world.files).some((p) => p.startsWith(level.world.cwd + "/")));
  });
}

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
