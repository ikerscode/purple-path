// Level 4 is checked here directly because it is not yet registered in levels/index.js.
// The generic checks mirror the ones in levels.test.js; the rest cover level 4's own data.
import { test } from "node:test";
import assert from "node:assert/strict";
import level from "../levels/04-hashing.js";
import { newTerminal, runCommand } from "../js/engine/terminal.js";
import { runSolution, newSession, applyInput, isChallengeComplete, checkDefence, checkQuiz } from "../js/engine/checks.js";

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

test("04-hashing: id and order", () => {
  assert.equal(level.id, "04-hashing");
  assert.equal(level.order, 4);
  assert.match(level.id, /^\d{2}-[a-z0-9-]+$/);
});

test("04-hashing: schema", () => {
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
  assert.equal(new Set(level.quiz.options).size, 4, "quiz options are distinct");
  assert.ok(Number.isInteger(level.quiz.answer) && level.quiz.answer >= 0 && level.quiz.answer < 4);
  assert.ok(Array.isArray(level.glossary) && level.glossary.length > 0);
  for (const g of level.glossary) assert.ok(isStr(g.term) && isStr(g.definition));
  assert.ok(isStrArr(level.hints) && level.hints.length >= 2);
  assert.ok(isStrArr(level.solution));
  assert.ok(Array.isArray(level.sources));
});

test("04-hashing: sources >= 5, all https, each with a claim", () => {
  assert.ok(level.sources.length >= 5, `has ${level.sources.length} sources`);
  for (const s of level.sources) {
    assert.ok(isStr(s.claim), "claim");
    assert.ok(isStr(s.url) && s.url.startsWith("https://"), `https: ${s.url}`);
    assert.doesNotThrow(() => new URL(s.url));
  }
});

test("04-hashing: every command match compiles", () => {
  for (const c of level.commands) assert.doesNotThrow(() => new RegExp(c.match, "i"), c.match);
});

test("04-hashing: only RFC 5737 addresses and .example/.test names", () => {
  // Document section numbers such as "section 3.1.1.2" have the shape of a dotted quad; drop them before scanning.
  const text = JSON.stringify(level).replace(/\b(sections?|sec\.)\s+\d+(\.\d+)+/gi, "");
  const ips = new Set([...level.world.hosts.map((h) => h.ip), ...level.outOfScope.hosts.filter((h) => /^\d/.test(h))]);
  for (const m of text.match(IPV4_IN_TEXT) || []) {
    assert.ok(RFC5737.some((re) => re.test(m)), `non-documentation address ${m}`);
  }
  for (const ip of ips) assert.ok(RFC5737.some((re) => re.test(ip)), `host ip ${ip}`);
  for (const h of level.world.hosts) assert.match(h.hostname, /\.(example|test)$/);
  for (const h of level.outOfScope.hosts.filter((x) => !/^\d/.test(x))) assert.match(h, /\.(example|test)$/);
});

test("04-hashing: solution completes every objective and the defence", () => {
  const r = runSolution(level);
  assert.equal(r.session.terminated, false, "solution must not end the engagement");
  assert.ok(r.challengeDone, `objectives incomplete: ${level.objectives.filter((o) => !r.session.done.has(o.id)).map((o) => o.id)}`);
  assert.ok(r.defenceDone, "defence not completed by solution");
  assert.ok(checkQuiz(level, level.quiz.answer));
  for (let i = 0; i < 4; i++) if (i !== level.quiz.answer) assert.equal(checkQuiz(level, i), false);
});

test("04-hashing: wrong defence answers fail, solution defence passes", () => {
  for (const opt of level.defence.check.options || []) {
    assert.equal(checkDefence(level, opt), opt === level.defence.check.value);
  }
});

test("04-hashing: objectives are not complete before any input", () => {
  assert.equal(isChallengeComplete(level, newSession(level)), false);
});

test("04-hashing: every excluded host ends the engagement and is not confused with a neighbour", () => {
  for (const host of level.outOfScope.hosts) {
    for (const line of [`nmap ${host}`, `ping ${host}`, `cat ${host}`, `dig +short A ${host}`, `NMAP   ${host.toUpperCase()}`]) {
      const s = newSession(level);
      const r = applyInput(level, s, line);
      assert.equal(r.terminated, true, `${line} should terminate`);
      assert.match(r.output, /ENGAGEMENT TERMINATED/);
      assert.ok(r.events.includes("terminated:out-of-scope"));
      const again = applyInput(level, s, level.solution[0]);
      assert.equal(again.terminated, true);
      assert.equal(again.completed.length, 0);
    }
  }
  for (const host of level.outOfScope.hosts.filter((h) => /^\d/.test(h))) {
    const r = applyInput(level, newSession(level), `nmap ${host}0`);
    assert.equal(r.terminated, false);
  }
  const ip = level.outOfScope.hosts.find((h) => /^\d/.test(h));
  const p = ip.split(".");
  assert.equal(applyInput(level, newSession(level), `nmap ${p[0]}.${p[1]}.${p[2]}.0/24`).terminated, true);
});

test("04-hashing: the solution never names an excluded host", () => {
  for (const step of level.solution) {
    for (const h of level.outOfScope.hosts) assert.ok(!step.toLowerCase().includes(h.toLowerCase()));
  }
});

test("04-hashing: out-of-scope message describes naming, not traffic", () => {
  assert.doesNotMatch(level.outOfScope.message, /sent traffic/);
  assert.match(level.outOfScope.message, /named/);
});

test("04-hashing: world files are well formed and cwd exists", () => {
  for (const [p, c] of Object.entries(level.world.files)) {
    assert.ok(p.startsWith("/"), p);
    assert.equal(typeof c, "string");
  }
  assert.ok(Object.keys(level.world.files).some((p) => p.startsWith(level.world.cwd + "/")));
});

// ---- Level 4 data: every stored value is structurally valid for its format ----

function usersRows() {
  const text = level.world.files["/home/analyst/review/users.csv"];
  assert.ok(text.endsWith("\n"), "export ends with a newline, like a real file");
  const lines = text.slice(0, -1).split("\n");
  assert.equal(lines[0], "id,username,pw_store");
  // Minimal CSV reading: the third field may be double-quoted and contain commas (RFC 4180).
  return lines.slice(1).map((l) => {
    const m = /^(\d+),([a-z]+),(?:"([^"]*)"|([^,"]*))$/.exec(l);
    assert.ok(m, `row parses: ${l}`);
    return { id: Number(m[1]), username: m[2], value: m[3] ?? m[4], quoted: m[3] !== undefined };
  });
}

test("04-hashing: users.csv has five well-formed rows", () => {
  const rows = usersRows();
  assert.deepEqual(rows.map((r) => r.username), ["rcarter", "mokafor", "dpatel", "lnguyen", "sbrown"]);
  assert.deepEqual(rows.map((r) => r.id), [1, 2, 3, 4, 5]);
  for (const r of rows) assert.equal(r.quoted, r.value.includes(","), `${r.username}: quoted exactly when it contains a comma`);
});

test("04-hashing: each stored value has the structure of the kind it is classified as", () => {
  const byName = Object.fromEntries(usersRows().map((r) => [r.username, r.value]));

  // v1 plaintext: readable text with no format prefix
  assert.match(byName.rcarter, /^[A-Za-z0-9-]+$/);
  assert.ok(!byName.rcarter.startsWith("$") && !byName.rcarter.startsWith("enc1:"));

  // v3: "enc1:" then base64 of 12-byte nonce + ciphertext + 16-byte tag, so at least 28 bytes
  assert.match(byName.mokafor, /^enc1:[A-Za-z0-9+/]+={0,2}$/);
  const raw = Buffer.from(byName.mokafor.slice(5), "base64");
  assert.equal(raw.toString("base64"), byName.mokafor.slice(5), "base64 round-trips");
  assert.ok(raw.length >= 12 + 16, "nonce + tag fit");

  // v2: 64 lowercase hex characters, nothing else
  assert.match(byName.dpatel, /^[0-9a-f]{64}$/);

  // v4: bcrypt, crypt(5): \$2[abxy]\$[0-9]{2}\$[./A-Za-z0-9]{53}, with cost 04..31
  assert.match(byName.lnguyen, /^\$2[abxy]\$[0-9]{2}\$[./A-Za-z0-9]{53}$/);
  assert.ok(byName.lnguyen.startsWith("$2b$"));
  const cost = Number(byName.lnguyen.slice(4, 6));
  assert.ok(cost >= 4 && cost <= 31, `cost ${cost}`);

  // v5: Argon2id in the PHC format: $argon2id$v=19$m=..,t=..,p=..$salt$hash, B64 without padding
  const m = /^\$argon2id\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/.exec(byName.sbrown);
  assert.ok(m, "argon2id PHC string shape");
  assert.ok(["16", "19"].includes(m[1]), "PHC versions are 16 and 19");
  assert.ok(Number(m[2]) >= 1 && Number(m[3]) >= 1 && Number(m[4]) >= 1 && Number(m[4]) <= 255);
  assert.equal(m[5].length % 4 === 1, false, "salt length is a valid unpadded B64 length");
  assert.equal(m[6].length % 4 === 1, false, "hash length is a valid unpadded B64 length");
  assert.ok(m[5].length >= 11 && m[5].length <= 64, "salt 8..48 bytes");
  assert.ok(m[6].length >= 16 && m[6].length <= 86, "hash 12..64 bytes");
  // the parameters match the OWASP minimum configuration quoted in the defence explanation
  assert.deepEqual([m[2], m[3], m[4]], ["19456", "2", "1"]);
  assert.match(level.defence.explanation, /m=19456 \(19 MiB\), t=2, p=1/);
});

test("04-hashing: no two stored values are identical", () => {
  const values = usersRows().map((r) => r.value);
  assert.equal(new Set(values).size, values.length);
});

test("04-hashing: auth.conf describes exactly the five kinds that appear", () => {
  const conf = level.world.files["/home/analyst/review/auth.conf"];
  for (const kind of ["v1", "v2", "v3", "v4", "v5"]) assert.match(conf, new RegExp(`^${kind}  `, "m"));
  assert.match(conf, /64 lowercase hex characters/);
  assert.match(conf, /function name was not recorded/);
  assert.match(conf, /prefix "enc1:"/);
});

test("04-hashing: wc -l matches the real line count of the export", () => {
  const text = level.world.files["/home/analyst/review/users.csv"];
  const lines = text.split("\n").length - 1;
  const term = newTerminal(level);
  const rel = runCommand(level, term, "wc -l review/users.csv");
  assert.equal(rel.output, `${lines} review/users.csv`);
  assert.deepEqual(rel.events, ["counted:users"]);
  const abs = runCommand(level, term, "wc -l /home/analyst/review/users.csv");
  assert.equal(abs.output, `${lines} /home/analyst/review/users.csv`);
  for (const l of ["wc review/users.csv", "wc -w review/users.csv", "wc -l users.csv", "wc -l review/auth.conf"]) {
    const r = runCommand(level, newTerminal(level), l);
    assert.equal(r.handled, false, l);
    assert.match(r.output, /not modelled/, l);
  }
});

test("04-hashing: reading the files fires the read events the objectives wait for", () => {
  const term = newTerminal(level);
  assert.deepEqual(runCommand(level, term, "cat review/auth.conf").events, ["read:/home/analyst/review/auth.conf"]);
  assert.deepEqual(runCommand(level, term, "cat review/users.csv").events, ["read:/home/analyst/review/users.csv"]);
  assert.match(runCommand(level, term, "cat /etc/shopfront/enc.key").output, /No such file/);
});

test("04-hashing: a typed answer completes only the matching pending objective", () => {
  const s = newSession(level);
  const wrong = applyInput(level, s, "Plaintext: the password itself");
  // it completes only the plaintext objective, in order, and nothing else
  assert.deepEqual(wrong.completed.map((o) => o.id), ["kind-rcarter"]);
  const none = applyInput(level, s, "4");
  assert.equal(none.completed.length, 0);
  assert.equal(s.done.has("count-weak"), false);
});

test("04-hashing: the quiz has one correct option and the other three are distinct from it", () => {
  const right = level.quiz.options[level.quiz.answer];
  assert.equal(level.quiz.options.filter((o) => o === right).length, 1);
});

test("04-hashing: no innerHTML and no plain http URLs in level data", () => {
  const text = JSON.stringify(level);
  assert.ok(!/innerHTML/.test(text));
  assert.ok(!/http:\/\//i.test(text), "no plain http URLs");
});
