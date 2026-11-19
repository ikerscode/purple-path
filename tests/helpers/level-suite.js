import { test } from "node:test";
import assert from "node:assert/strict";
import { newSession, applyInput, isChallengeComplete, checkDefence, checkQuiz, runSolution } from "../../js/engine/checks.js";

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

// The generic per-level checks (schema, sources, solvability, out-of-scope behaviour).
// levels.test.js runs them for every level registered in levels/index.js.
export function defineLevelTests(level) {
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
      assert.ok(c.caseSensitive === undefined || typeof c.caseSensitive === "boolean");
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
    const text = JSON.stringify(level).replace(/\b(sections?|sec\.)\s+\d+(\.\d+)+/gi, "");
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
