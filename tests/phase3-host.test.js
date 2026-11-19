// Behaviour tests for levels 9 (privilege escalation) and 10 (lateral movement): each level's own data and
// the shapes of its simulated commands. The generic suite runs from tests/levels.test.js.
import { test } from "node:test";
import assert from "node:assert/strict";
import privesc from "../levels/09-privesc.js";
import lateral from "../levels/10-lateral.js";
import { newTerminal, runCommand } from "../js/engine/terminal.js";
import { newSession, applyInput, submitObjective, checkDefence, checkQuiz, runSolution, isChallengeComplete } from "../js/engine/checks.js";


const fresh = (level) => {
  const term = newTerminal(level);
  return (line) => runCommand(level, term, line);
};
const notModelled = (r, line) => {
  assert.equal(r.handled, false, line);
  assert.match(r.output, /not modelled/, line);
  assert.deepEqual(r.events, [], line);
  assert.equal(r.terminated, false, line);
};
const objective = (level, id) => level.objectives.find((o) => o.id === id);

// Content that would turn a defence-first level into an attack walkthrough, or print secrets.
function assertNoAttackOrSecretContent(level) {
  const text = JSON.stringify(level);
  assert.ok(!/\$[0-9a-z]{1,10}\$/i.test(text), "no hash-format strings");
  assert.ok(!/\b[0-9a-f]{32,}\b/i.test(text), "no long hex strings");
  assert.ok(!/BEGIN [A-Z ]*PRIVATE KEY/.test(text), "no key material");
  assert.ok(!/!\s*\/bin\/(ba)?sh|-c\s+['"]:|:!\s*\/bin|\bsudo (su|-i|-s|vim|vi|less|find|bash|sh)\b/i.test(text), "no shell-escape or privilege-gaining sequences");
  assert.ok(!/\bsshpass\b|\bssh\s+\S+@\S+/i.test(text), "no login commands");
  assert.ok(!/innerHTML/.test(text));
  assert.ok(!/http:\/\//i.test(text), "no plain http URLs in level data");
}

// ---------------------------------------------------------------- level 9

test("09-privesc: id, order and tier", () => {
  assert.equal(privesc.id, "09-privesc");
  assert.equal(privesc.order, 9);
  assert.equal(privesc.tier, "intermediate");
});

function fragmentRules() {
  const text = privesc.world.files["/home/analyst/review/sudoers-90-ops.txt"];
  return text
    .split("\n")
    .filter((l) => l && !l.startsWith("#"))
    .map((l) => {
      const m = /^(\S+) ALL=\((\w+)\) (NOPASSWD: )?(.+)$/.exec(l);
      assert.ok(m, `rule line parses: ${l}`);
      return { user: m[1], runas: m[2], nopasswd: Boolean(m[3]), cmnd: m[4] };
    });
}

test("09-privesc: sudo -l output follows the sudo 1.9.17p2 listing layout and matches the fragment", () => {
  const rules = fragmentRules();
  assert.equal(rules.length, 3);
  for (const r of rules) assert.equal(r.user, "analyst");
  const run = fresh(privesc);
  const r = run("sudo -l");
  assert.deepEqual(r.events, ["listed:sudo"]);
  const lines = r.output.split("\n");
  // Header, indented Defaults, blank line, second header, then one "    (runas) [TAG: ]command" line per rule.
  assert.equal(lines[0], "Matching Defaults entries for analyst on app01:");
  assert.match(lines[1], /^ {4}\S/);
  assert.equal(lines[2], "");
  assert.equal(lines[3], "User analyst may run the following commands on app01:");
  const ruleLines = lines.slice(4);
  assert.deepEqual(
    ruleLines,
    rules.map((x) => `    (${x.runas}) ${x.nopasswd ? "NOPASSWD: " : ""}${x.cmnd}`),
  );
  // the host in the listing is the short name of the in-scope host
  assert.equal(privesc.world.hosts.find((h) => h.inScope).hostname.split(".")[0], "app01");
  // every listed rule is one of the objective options and the broad one is the last rule
  const which = objective(privesc, "which-rule");
  assert.deepEqual(which.check.options, ruleLines.map((l) => l.trim()));
  assert.equal(which.check.value, "(root) NOPASSWD: /usr/bin/vim");
  assert.ok(!r.output.endsWith("\n"));
  // sudo --list is the long form of -l and gives the same listing
  assert.equal(run("sudo --list").output, r.output);
});

test("09-privesc: exactly one rule names a program with no arguments, and the two narrow rules fix their arguments", () => {
  const rules = fragmentRules();
  const noArgs = rules.filter((r) => !r.cmnd.includes(" "));
  assert.deepEqual(noArgs.map((r) => r.cmnd), ["/usr/bin/vim"]);
  assert.deepEqual(rules.filter((r) => r.cmnd.includes(" ")).map((r) => r.cmnd), ["/usr/sbin/nginx -t", "/usr/bin/systemctl reload nginx.service"]);
  // the broad rule is not the first or only rule, so the choice is not given away by position alone
  assert.notEqual(rules.findIndex((r) => r.cmnd === "/usr/bin/vim"), 0);
});

test("09-privesc: sudo variants and other command forms are not modelled, never empty", () => {
  const run = fresh(privesc);
  for (const l of [
    "sudo -ll",
    "sudo -l -U analyst",
    "sudo -l vim",
    "sudo -n -l",
    "sudo -l -l",
    "SUDO -L",
    "sudo -V",
    "sudo vim",
    "sudo -i",
    "sudo su",
    "sudo cat /etc/shadow",
    "sudoedit /etc/nginx/conf.d/shop.conf",
    "sudo -e /etc/nginx/conf.d/shop.conf",
    "id",
    "visudo -c",
    "vim /etc/nginx/conf.d/shop.conf",
  ]) {
    const r = run(l);
    notModelled(r, l);
    assert.notEqual(r.output.trim(), "", l);
  }
});

test("09-privesc: reading the fragment fires the event the objective waits for; unrelated paths do not exist", () => {
  const run = fresh(privesc);
  assert.deepEqual(run("cat review/sudoers-90-ops.txt").events, ["read:/home/analyst/review/sudoers-90-ops.txt"]);
  assert.match(run("cat /etc/sudoers").output, /No such file/);
  assert.match(run("cat /etc/sudoers.d/90-ops").output, /No such file/);
  assert.equal(run("whoami").output, "analyst");
});

test("09-privesc: naming the other team's host ends the review with a message about naming", () => {
  for (const l of ["cat hrdb01.example.test", "ping 198.51.100.60", "sudo -l -h hrdb01.example.test"]) {
    const r = runCommand(privesc, newTerminal(privesc), l);
    assert.equal(r.terminated, true, l);
    assert.match(r.output, /ENGAGEMENT TERMINATED/);
  }
  assert.match(privesc.outOfScope.message, /named/);
  assert.doesNotMatch(privesc.outOfScope.message, /sent traffic/);
  // reading the brief, which names the host, is not touching it
  const r = runCommand(privesc, newTerminal(privesc), "cat brief.txt");
  assert.equal(r.terminated, false);
  assert.match(r.output, /hrdb01\.example\.test/);
});

test("09-privesc: wrong answers are rejected and complete nothing", () => {
  const s = newSession(privesc);
  applyInput(privesc, s, "sudo -l");
  applyInput(privesc, s, "cat review/sudoers-90-ops.txt");
  for (const [id, wrong] of [
    ["count-nopasswd", ["0", "1", "2", "4", "all"]],
    ["technique", ["T1548", "T1548.001", "T1068", "T1548.003x", "t1548.03"]],
  ]) {
    for (const w of wrong) assert.equal(submitObjective(privesc, s, id, w).ok, false, `${id}: ${w}`);
  }
  const which = objective(privesc, "which-rule").check;
  for (const opt of which.options.filter((o) => o !== which.value)) assert.equal(submitObjective(privesc, s, "which-rule", opt).ok, false, opt);
  for (const id of ["why-broad", "impact"]) {
    const c = objective(privesc, id).check;
    assert.equal(c.options.length, 4);
    assert.equal(c.options.filter((o) => o === c.value).length, 1);
    for (const opt of c.options.filter((o) => o !== c.value)) assert.equal(submitObjective(privesc, s, id, opt).ok, false, `${id}: ${opt}`);
  }
  assert.equal(s.done.has("which-rule"), false);
  assert.equal(s.done.has("why-broad"), false);
  assert.equal(s.done.has("impact"), false);
  // typed into the terminal, a wrong option also completes nothing
  for (const opt of objective(privesc, "why-broad").check.options.slice(1)) {
    assert.equal(applyInput(privesc, s, opt).completed.length, 0, opt);
  }
  // every wrong defence is rejected, only the sudoedit entry passes
  const d = privesc.defence.check;
  assert.equal(d.options.length, 4);
  for (const opt of d.options) assert.equal(checkDefence(privesc, opt), opt === d.value);
  assert.equal(checkDefence(privesc, "analyst ALL=(root) NOPASSWD: /usr/bin/vim"), false);
  assert.equal(checkDefence(privesc, ""), false);
});

test("09-privesc: the defence options are sudoers lines; only the correct one is sudoedit with one named file", () => {
  const options = privesc.defence.check.options;
  for (const o of options) assert.match(o, /^analyst ALL=\((root|ALL)\) (NOPASSWD: )?\S/, o);
  const edit = options.filter((o) => /\) sudoedit /.test(o));
  assert.deepEqual(edit, [privesc.defence.check.value]);
  assert.match(privesc.defence.check.value, /^analyst ALL=\(root\) sudoedit \/etc\/nginx\/conf\.d\/shop\.conf$/);
  assert.doesNotMatch(privesc.defence.check.value, /NOPASSWD/);
  // the distractors still run an editor, a pager, or any command as root
  const others = options.filter((o) => o !== privesc.defence.check.value);
  assert.ok(others.some((o) => /\/usr\/bin\/vim /.test(o)));
  assert.ok(others.some((o) => /\/usr\/bin\/less /.test(o)));
  assert.ok(others.some((o) => /\(ALL\) NOPASSWD: ALL$/.test(o)));
});

test("09-privesc: full playthrough completes, and the quiz has one correct option", () => {
  const r = runSolution(privesc);
  assert.ok(r.challengeDone && r.defenceDone);
  assert.equal(r.session.terminated, false);
  assert.ok(checkQuiz(privesc, privesc.quiz.answer));
  assert.equal(new Set(privesc.quiz.options).size, 4);
  assert.equal(isChallengeComplete(privesc, newSession(privesc)), false);
});

test("09-privesc: defence-first, no attack sequences, hashes or credentials", () => {
  assertNoAttackOrSecretContent(privesc);
  // the only modelled command is the listing
  assert.deepEqual(privesc.commands.map((c) => c.match), ["^sudo (-l|--list)$"]);
  assert.equal(privesc.commands[0].caseSensitive, true);
});

test("09-privesc: sources cover sudoers(5), sudo(8), ATT&CK, GTFOBins, NIST and NCSC", () => {
  const urls = privesc.sources.map((s) => s.url);
  for (const part of ["www.sudo.ws/docs/man/sudoers.man/", "www.sudo.ws/docs/man/sudo.man/", "attack.mitre.org/techniques/T1548/003/", "gtfobins.org/", "SP.800-53r5.pdf", "www.ncsc.gov.uk/"]) {
    assert.ok(urls.some((u) => u.includes(part)), part);
  }
  assert.ok(privesc.sources.length >= 10);
});

// ---------------------------------------------------------------- level 10

test("10-lateral: id, order and tier", () => {
  assert.equal(lateral.id, "10-lateral");
  assert.equal(lateral.order, 10);
  assert.equal(lateral.tier, "intermediate");
});

test("10-lateral: wc -l matches the real line count of the audit note; other forms are not modelled", () => {
  const text = lateral.world.files["/home/analyst/review/audit-note.txt"];
  assert.ok(text.endsWith("\n"), "the file ends with a newline, like a real text file");
  const lines = text.split("\n").length - 1;
  const run = fresh(lateral);
  const rel = run("wc -l review/audit-note.txt");
  assert.equal(rel.output, `${lines} review/audit-note.txt`);
  assert.deepEqual(rel.events, ["counted:note"]);
  assert.equal(run("wc -l /home/analyst/review/audit-note.txt").output, `${lines} /home/analyst/review/audit-note.txt`);
  for (const l of ["wc review/audit-note.txt", "wc -w review/audit-note.txt", "wc -l audit-note.txt", "wc -l review/ssh-summary.txt", "WC -L review/audit-note.txt"]) {
    notModelled(run(l), l);
  }
});

test("10-lateral: logins and scans of in-scope hosts are not modelled, never empty", () => {
  const run = fresh(lateral);
  for (const l of [
    "ssh app02.example.test",
    "ssh svc-backup@app02.example.test",
    "ssh -i key svc-backup@files02.example.test",
    "ssh files02.example.test hostname",
    "scp file svc-backup@192.0.2.62:/tmp",
    "sshpass -p x ssh 192.0.2.61",
    "nmap 192.0.2.61",
    "ping files02.example.test",
    "curl https://app02.example.test/",
    "su - svc-backup",
    "id svc-backup",
    "grep svc-backup review/audit-note.txt",
  ]) {
    const r = run(l);
    notModelled(r, l);
    assert.notEqual(r.output.trim(), "", l);
  }
});

test("10-lateral: naming the excluded host ends the engagement in every form, but reading the scope file does not", () => {
  for (const l of [
    "cat billing01.example.test",
    "ping 198.51.100.62",
    "ssh billing01.example.test",
    "ssh svc-backup@billing01.example.test",
    "ssh svc-backup@198.51.100.62",
    "nmap 198.51.100.0/24",
    "curl https://billing01.example.test/",
    "BILLING01.EXAMPLE.TEST",
  ]) {
    const r = runCommand(lateral, newTerminal(lateral), l);
    assert.equal(r.terminated, true, l);
    assert.match(r.output, /ENGAGEMENT TERMINATED/, l);
    assert.ok(r.events.includes("terminated:out-of-scope"), l);
  }
  const run = fresh(lateral);
  const scope = run("cat engagement/scope.txt");
  assert.equal(scope.terminated, false);
  assert.match(scope.output, /198\.51\.100\.62/);
  assert.match(scope.output, /billing01\.example\.test/);
  assert.deepEqual(scope.events, ["read:/home/analyst/engagement/scope.txt"]);
  // a neighbouring name or address is not the excluded host
  for (const l of ["ping 198.51.100.620", "ping 198.51.100.6", "cat billing02.example.test", "ping 192.0.2.61"]) {
    assert.equal(runCommand(lateral, newTerminal(lateral), l).terminated, false, l);
  }
  // the engagement stays ended
  const s = newSession(lateral);
  applyInput(lateral, s, "ping billing01.example.test");
  const again = applyInput(lateral, s, "cat engagement/scope.txt");
  assert.equal(again.terminated, true);
  assert.equal(again.completed.length, 0);
  assert.match(lateral.outOfScope.message, /named/);
  assert.doesNotMatch(lateral.outOfScope.message, /sent traffic/);
});

test("10-lateral: scope, note and summary agree about which hosts are in scope", () => {
  const scope = lateral.world.files["/home/analyst/engagement/scope.txt"];
  const note = lateral.world.files["/home/analyst/review/audit-note.txt"];
  const ssh = lateral.world.files["/home/analyst/review/ssh-summary.txt"];
  const inScope = lateral.world.hosts.filter((h) => h.inScope);
  const out = lateral.world.hosts.filter((h) => !h.inScope);
  assert.equal(inScope.length, 2);
  assert.equal(out.length, 1);
  for (const h of inScope) {
    assert.match(scope, new RegExp(`IN SCOPE[\\s\\S]*${h.ip.replace(/\./g, "\\.")}\\s+${h.hostname.replace(/\./g, "\\.")}[\\s\\S]*EXCLUSION LIST`));
    assert.ok(note.includes(h.hostname), `note names ${h.hostname}`);
    assert.ok(ssh.includes(h.hostname), `summary names ${h.hostname}`);
  }
  // the excluded host is listed under the exclusion list and appears in neither review file
  assert.match(scope, new RegExp(`EXCLUSION LIST[\\s\\S]*${out[0].ip.replace(/\./g, "\\.")}\\s+${out[0].hostname.replace(/\./g, "\\.")}`));
  assert.ok(!note.includes(out[0].hostname) && !note.includes(out[0].ip));
  assert.ok(!ssh.includes(out[0].hostname) && !ssh.includes(out[0].ip));
  assert.deepEqual(lateral.outOfScope.hosts.sort(), [out[0].ip, out[0].hostname].sort());
  // the range the summary gives contains both in-scope hosts and not the excluded one
  const [base] = "192.0.2.0/24".split("/");
  for (const h of inScope) assert.ok(h.ip.startsWith(base.replace(/0$/, "")));
  assert.ok(!out[0].ip.startsWith("192.0.2."));
  assert.ok(objective(lateral, "reach").check.value.includes("192.0.2.0/24"));
  assert.equal(ssh.split("192.0.2.0/24").length - 1, 2, "both host rows give the same range");
});

test("10-lateral: the note describes the shared password without printing a password or a hash", () => {
  const note = lateral.world.files["/home/analyst/review/audit-note.txt"];
  assert.match(note, /same password configured on\s+both in-scope hosts/);
  assert.match(note, /deliberately not\s+included/);
  assert.doesNotMatch(note, /password\s*[:=]/i);
  assertNoAttackOrSecretContent(lateral);
  // the audit does not claim to have compared hashes, which would not show reuse for salted hashes
  assert.doesNotMatch(note, /hash(es)? (match|are the same|compare)/i);
});

test("10-lateral: wrong answers are rejected and complete nothing", () => {
  const s = newSession(lateral);
  for (const f of ["engagement/scope.txt", "review/audit-note.txt", "review/ssh-summary.txt"]) applyInput(lateral, s, `cat ${f}`);
  for (const [id, wrong] of [
    ["count-hosts", ["1", "3", "0", "one", "both"]],
    ["reach", ["192.0.2.0/25", "192.0.2.61", "198.51.100.0/24", "192.0.2.0", "any"]],
    ["technique-ssh", ["T1021", "T1021.001", "T1078", "T1021.004x", "T1021.04"]],
  ]) {
    for (const w of wrong) assert.equal(submitObjective(lateral, s, id, w).ok, false, `${id}: ${w}`);
  }
  for (const id of ["tactic", "impact"]) {
    const c = objective(lateral, id).check;
    assert.equal(c.options.length, 4);
    assert.equal(c.options.filter((o) => o === c.value).length, 1);
    for (const opt of c.options.filter((o) => o !== c.value)) assert.equal(submitObjective(lateral, s, id, opt).ok, false, `${id}: ${opt}`);
  }
  assert.equal(objective(lateral, "tactic").check.value, "TA0008 Lateral Movement");
  // typed answers complete only the matching pending objective
  const typed = applyInput(lateral, s, "2");
  assert.deepEqual(typed.completed.map((o) => o.id), ["count-hosts"]);
  assert.equal(applyInput(lateral, s, "2").completed.length, 0);
  // wrong defences
  const d = lateral.defence.check;
  assert.equal(d.options.length, 4);
  for (const opt of d.options) assert.equal(checkDefence(lateral, opt), opt === d.value);
  assert.equal(checkDefence(lateral, "Give svc-backup a different, unique credential on each host"), false);
});

test("10-lateral: the correct defence names all three measures and the distractors do not", () => {
  const d = lateral.defence.check;
  assert.match(d.value, /unique credential on each host/);
  assert.match(d.value, /multi-factor authentication/);
  assert.match(d.value, /where the system supports it/);
  assert.match(d.value, /restrict which accounts and which networks can reach SSH/);
  for (const o of d.options.filter((x) => x !== d.value)) {
    assert.doesNotMatch(o, /unique credential/);
    assert.doesNotMatch(o, /multi-factor/);
  }
});

test("10-lateral: full playthrough completes, and the quiz has one correct option", () => {
  const r = runSolution(lateral);
  assert.ok(r.challengeDone && r.defenceDone);
  assert.equal(r.session.terminated, false);
  assert.ok(checkQuiz(lateral, lateral.quiz.answer));
  assert.equal(new Set(lateral.quiz.options).size, 4);
});

test("10-lateral: sources cover ATT&CK, NCSC, NIST and sshd_config", () => {
  const urls = lateral.sources.map((s) => s.url);
  for (const part of [
    "attack.mitre.org/tactics/TA0008/",
    "attack.mitre.org/techniques/T1021/004/",
    "attack.mitre.org/techniques/T1078/",
    "attack.mitre.org/techniques/T1078/003/",
    "www.ncsc.gov.uk/guidance/preventing-lateral-movement",
    "SP.800-53r5.pdf",
    "pages.nist.gov/800-63-4/sp800-63b.html",
    "man.openbsd.org/sshd_config",
  ]) {
    assert.ok(urls.some((u) => u.includes(part)), part);
  }
  assert.ok(lateral.sources.length >= 10);
});
