// Behaviour tests for levels 7 (SQL injection) and 8 (XSS): each level's own data and the shapes of its
// simulated commands. The generic schema/sources/solvability suite runs from tests/levels.test.js.
import { test } from "node:test";
import assert from "node:assert/strict";
import sqli from "../levels/07-sqli.js";
import xss from "../levels/08-xss.js";
import { newTerminal, runCommand } from "../js/engine/terminal.js";
import { newSession, applyInput, submitObjective, checkDefence, checkQuiz, runSolution } from "../js/engine/checks.js";


const fresh = (level) => {
  const term = newTerminal(level);
  return (line) => runCommand(level, term, line);
};
const notModelled = (r, line) => {
  assert.equal(r.handled, false, line);
  assert.match(r.output, /not modelled/, line);
  assert.deepEqual(r.events, [], line);
};

// Content that would amount to a working attack string is not allowed anywhere in the two levels.
const PAYLOAD_PATTERNS = [
  /\bUNION\b/i,
  /\bOR\s+1\s*=\s*1/i,
  /'\s*OR\s*'/i,
  /\bDROP\s+TABLE\b/i,
  /alert\s*\(/i,
  /\bonerror\b/i,
  /\bonload\b/i,
  /\bonfocus\b/i,
  /javascript:/i,
  /document\.cookie/i,
  /fromCharCode/i,
  /<script>\s*[A-Za-z_$][\w$.]*\s*\(/i,
  /<img\b/i,
];

for (const level of [sqli, xss]) {
  test(`${level.id}: no attack strings anywhere in the level data`, () => {
    const text = JSON.stringify(level);
    for (const re of PAYLOAD_PATTERNS) assert.ok(!re.test(text), `${re} found`);
  });

  test(`${level.id}: no innerHTML, and no plain http URLs in the teaching text or the sources`, () => {
    const text = JSON.stringify([level.card, level.defence, level.quiz, level.glossary, level.sources]);
    assert.ok(!/innerHTML/.test(JSON.stringify(level)));
    assert.ok(!/http:\/\//i.test(text), "no plain http URLs in cards, defence, quiz, glossary or sources");
    assert.ok(!/eval\(|document\.write/.test(JSON.stringify(level)));
  });

  test(`${level.id}: at least five distinct source pages, and the quiz options are distinct`, () => {
    const urls = level.sources.map((s) => s.url);
    assert.ok(new Set(urls).size >= 5, `${new Set(urls).size} distinct pages`);
    assert.equal(new Set(level.quiz.options).size, 4);
    assert.equal(level.tier, "intermediate");
  });

  test(`${level.id}: every wrong option is rejected for every choice objective, and for the defence`, () => {
    for (const o of level.objectives.filter((x) => x.check.type === "choice")) {
      for (const opt of o.check.options) {
        const s = newSession(level);
        const r = submitObjective(level, s, o.id, opt);
        assert.equal(r.ok, opt === o.check.value, `${o.id}: ${opt}`);
      }
    }
    for (const opt of level.defence.check.options) assert.equal(checkDefence(level, opt), opt === level.defence.check.value);
    assert.equal(checkDefence(level, ""), false);
    assert.equal(checkDefence(level, "parameterised queries"), false);
    for (let i = 0; i < 4; i++) assert.equal(checkQuiz(level, i), i === level.quiz.answer);
  });

  test(`${level.id}: the solution does not complete the level out of order or twice`, () => {
    const r = runSolution(level);
    assert.ok(r.challengeDone && r.defenceDone);
    const s = newSession(level);
    for (const step of level.solution.slice(0, level.objectives.length - 1)) applyInput(level, s, step);
    assert.equal(s.done.size < level.objectives.length, true, "one step short is not complete");
  });

  test(`${level.id}: typing text that is not an option completes nothing and prints the not-modelled message`, () => {
    const s = newSession(level);
    for (const line of ["hello", "42", "yes", "no", "sudo su", "rm -rf /", "python3 --version"]) {
      const r = applyInput(level, s, line);
      assert.equal(r.completed.length, 0, line);
      assert.match(r.output, /not modelled/, line);
    }
  });

  test(`${level.id}: built-ins behave, and a missing file gives an error, not empty output`, () => {
    const run = fresh(level);
    assert.match(run("ls").output, /README\.txt/);
    assert.match(run("cat nothing.txt").output, /^cat: nothing\.txt: No such file or directory$/);
    assert.match(run("cat README.txt").output, /Training exercise \(fictional/);
    assert.equal(run("ls -l").handled, false);
  });
}

// ---- Level 7: SQL injection ----

const SQLI_SRC = sqli.world.files["/home/analyst/src/catalogue.py"];

test("07-sqli: the source file is plausible Python and its line numbers match the objective options", () => {
  assert.ok(SQLI_SRC.endsWith("\n"));
  const lines = SQLI_SRC.slice(0, -1).split("\n");
  const sqlLines = lines.map((text, i) => ({ n: i + 1, text })).filter((l) => l.text.includes("SELECT"));
  assert.equal(sqlLines.length, 4);
  const concat = sqlLines.filter((l) => /"\s*\+\s*\w+|\w+\s*\+\s*"/.test(l.text)).map((l) => l.n);
  const bound = sqlLines.filter((l) => /\?"/.test(l.text) && !/\+/.test(l.text)).map((l) => l.n);
  assert.deepEqual(concat, [11, 25]);
  assert.deepEqual(bound, [18, 32]);
  const obj = sqli.objectives.find((o) => o.id === "concat-lines");
  assert.equal(obj.check.value, `Lines ${concat[0]} and ${concat[1]}`);
  assert.ok(obj.check.options.includes(`Lines ${bound[0]} and ${bound[1]}`));
  // the other two options each mix one flawed and one safe line, so they are wrong
  for (const opt of obj.check.options.filter((x) => x !== obj.check.value)) {
    const nums = opt.match(/\d+/g).map(Number);
    assert.ok(nums.some((n) => bound.includes(n)), opt);
  }
  // no other way of building SQL text (f-strings, % formatting, .format) appears in the file
  assert.ok(!/f"|f'|%s|\.format\(/.test(SQLI_SRC));
  // every bound query passes its value as a separate tuple argument
  assert.match(SQLI_SRC, /cur\.execute\(query, \(author,\)\)/);
  assert.match(SQLI_SRC, /cur\.execute\("SELECT id, title FROM books WHERE isbn = \?", \(isbn,\)\)/);
});

test("07-sqli: grep -n SELECT matches the output of real GNU grep 3.12 on this file", () => {
  // Captured with /usr/bin/grep (GNU grep 3.12) run as: grep -n SELECT src/catalogue.py
  const real = [
    '11:    query = "SELECT id, title, price FROM books WHERE title = \'" + title + "\'"',
    '18:    query = "SELECT id, title, price FROM books WHERE author = ?"',
    '25:    query = "SELECT id, title FROM books WHERE price < " + max_price',
    '32:    cur.execute("SELECT id, title FROM books WHERE isbn = ?", (isbn,))',
  ].join("\n");
  const run = fresh(sqli);
  for (const l of [
    "grep -n SELECT src/catalogue.py",
    'grep -n "SELECT" src/catalogue.py',
    "grep -n 'SELECT' src/catalogue.py",
    "grep -n   SELECT   src/catalogue.py",
    "grep -n SELECT /home/analyst/src/catalogue.py",
  ]) {
    const r = run(l);
    assert.equal(r.output, real, l);
    assert.deepEqual(r.events, ["grep:select"], l);
  }
  // independent re-implementation of grep -n over the file text agrees
  const mine = SQLI_SRC.slice(0, -1)
    .split("\n")
    .map((t, i) => [i + 1, t])
    .filter(([, t]) => t.includes("SELECT"))
    .map(([n, t]) => `${n}:${t}`)
    .join("\n");
  assert.equal(mine, real);
});

test("07-sqli: other grep forms are not modelled (never empty output)", () => {
  const run = fresh(sqli);
  for (const l of [
    "grep SELECT src/catalogue.py",
    "grep -n select src/catalogue.py",
    "grep -n -i SELECT src/catalogue.py",
    "grep -ni SELECT src/catalogue.py",
    "grep -c SELECT src/catalogue.py",
    "grep -n execute src/catalogue.py",
    "grep -n SELECT src/other.py",
    "grep -n SELECT src",
    "grep -n SELECT *",
    "grep -rn SELECT .",
    "grep -n SELECT README.txt",
    "grep -H -n SELECT src/catalogue.py",
    "python3 src/catalogue.py",
    "sqlite3 catalogue.db",
    "head -n 5 src/catalogue.py",
    "wc -l src/catalogue.py",
  ]) notModelled(run(l), l);
});

test("07-sqli: reading the files fires the events the objectives wait for", () => {
  const run = fresh(sqli);
  assert.deepEqual(run("cat brief.txt").events, ["read:/home/analyst/brief.txt"]);
  assert.deepEqual(run("cat src/catalogue.py").events, ["read:/home/analyst/src/catalogue.py"]);
  assert.equal(run("cat src/catalogue.py").output, SQLI_SRC.slice(0, -1));
  assert.match(run("cat src/missing.py").output, /No such file or directory/);
  assert.match(run("cat /home/analyst/src").output, /Is a directory/);
});

test("07-sqli: the live database server ends the review however it is named", () => {
  for (const line of [
    "cat db.quillon.example",
    "ping 198.51.100.60",
    "grep -n SELECT 198.51.100.60",
    "nmap 198.51.100.0/24",
    "sqlite3 db.quillon.example",
    "curl https://db.quillon.example:5432/",
    "DB.QUILLON.EXAMPLE",
  ]) {
    const r = runCommand(sqli, newTerminal(sqli), line);
    assert.equal(r.terminated, true, line);
    assert.match(r.output, /live database server/);
    assert.match(r.output, /named/);
    assert.doesNotMatch(r.output, /sent traffic/);
  }
  for (const line of ["cat src/catalogue.py", "grep -n SELECT src/catalogue.py", "ping 198.51.100.600"]) {
    assert.equal(runCommand(sqli, newTerminal(sqli), line).terminated, false, line);
  }
});

test("07-sqli: the fix-name objective accepts the documented names only", () => {
  const obj = sqli.objectives.find((o) => o.id === "fix-name");
  for (const ok of ["Parameterized queries", "parameterised queries", "  prepared   statements ", "PREPARED STATEMENT"]) {
    const s = newSession(sqli);
    assert.equal(submitObjective(sqli, s, obj.id, ok).ok, true, ok);
  }
  for (const bad of ["escaping", "input validation", "stored procedures", "a web application firewall", "queries", "parameter", ""]) {
    const s = newSession(sqli);
    assert.equal(submitObjective(sqli, s, obj.id, bad).ok, false, bad);
  }
});

test("07-sqli: category options name the 2021 list correctly and the right one is A03", () => {
  const obj = sqli.objectives.find((o) => o.id === "category");
  assert.equal(obj.check.value, "A03:2021 Injection");
  assert.deepEqual(obj.check.options.map((o) => o.split(" ")[0]), ["A01:2021", "A02:2021", "A03:2021", "A05:2021"]);
});

test("07-sqli: the defence prompt and options keep OWASP's qualifiers", () => {
  const d = sqli.defence;
  assert.match(d.check.value, /placeholders/);
  assert.match(d.check.value, /extra layers/);
  assert.match(d.explanation, /complements parameter binding but does not replace it/);
  assert.match(d.explanation, /strongly discouraged/);
  assert.match(d.explanation, /when the code cannot be fixed/);
  assert.match(d.explanation, /not a complete defense/);
  assert.match(d.explanation, /hard-coded constant/);
});

// ---- Level 8: XSS ----

const XSS_TEMPLATE = xss.world.files["/home/analyst/webapp/templates/search.html"];

// Captured from a real local Flask app (Flask 3.1.3, Jinja2 3.1.6, Werkzeug 3.1.9, Python 3.14.8)
// serving this template on 127.0.0.1, fetched with curl 8.22.0 (curl -si, CR removed, Date replaced).
const REAL_BODY = [
  "<!doctype html>",
  '<html lang="en">',
  "<head><title>Search - Fellside Outfitters</title></head>",
  "<body>",
  "<h1>Results for boots</h1>",
  '<form action="/search" method="get">',
  '<input type="text" name="q" value="boots">',
  '<button type="submit">Search</button>',
  "</form>",
  "<script>",
  'var lastSearch = "boots";',
  "</script>",
  "</body>",
  "</html>",
].join("\n");

test("08-xss: the template has three placeholders, one with escaping switched off, in three contexts", () => {
  const ph = [...XSS_TEMPLATE.matchAll(/\{\{[^}]*\}\}/g)].map((m) => m[0]);
  assert.deepEqual(ph, ["{{ q|safe }}", "{{ q }}", "{{ q }}"]);
  assert.match(XSS_TEMPLATE, /<h1>Results for \{\{ q\|safe \}\}<\/h1>/);
  assert.match(XSS_TEMPLATE, /<input type="text" name="q" value="\{\{ q \}\}">/, "quoted attribute");
  assert.match(XSS_TEMPLATE, /var lastSearch = "\{\{ q \}\}";/);
  assert.equal(XSS_TEMPLATE.endsWith("\n"), true);
  // the app has one route and passes the term unchanged to the template
  const app = xss.world.files["/home/analyst/webapp/app.py"];
  assert.equal((app.match(/@app\.route/g) || []).length, 1);
  assert.match(app, /@app\.route\("\/search"\)/);
  assert.match(app, /render_template\("search\.html", q=q\)/);
});

test("08-xss: the simulated curl response matches the real response format and captured body", () => {
  const run = fresh(xss);
  const r = run('curl -i "http://192.0.2.80:5000/search?q=boots"');
  assert.deepEqual(r.events, ["http:search-headers"]);
  const [head, ...rest] = r.output.split("\n\n");
  const body = rest.join("\n\n");
  assert.equal(body, REAL_BODY);
  const lines = head.split("\n");
  assert.equal(lines[0], "HTTP/1.1 200 OK");
  assert.match(lines[1], /^Server: Werkzeug\/3\.1\.9 Python\/3\.14\.8$/);
  assert.match(lines[2], /^Date: [A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT$/);
  assert.equal(lines[3], "Content-Type: text/html; charset=utf-8");
  assert.equal(lines[4], `Content-Length: ${Buffer.byteLength(body)}`);
  assert.equal(lines[4], "Content-Length: 310");
  assert.equal(lines[5], "Connection: close");
  assert.equal(lines.length, 6);
  // the date is a real Thursday
  const d = new Date(lines[2].slice(6));
  assert.equal(d.getUTCDay(), 4);
  assert.match(lines[2], /^Date: Thu,/);
  // no CSP header, which is what the csp-header objective relies on
  assert.ok(!/content-security-policy/i.test(head));
});

test("08-xss: the body shown for the ordinary term equals the template with each placeholder replaced", () => {
  const rendered = XSS_TEMPLATE.slice(0, -1).replace(/\{\{ q(\|safe)? \}\}/g, "boots");
  assert.equal(rendered, REAL_BODY);
  assert.equal((REAL_BODY.match(/boots/g) || []).length, 3);
});

test("08-xss: curl forms: -i variants and body-only variants, quoted or not", () => {
  const run = fresh(xss);
  const url = "http://192.0.2.80:5000/search?q=boots";
  for (const l of [`curl -i ${url}`, `curl -i "${url}"`, `curl -i '${url}'`, `curl -si "${url}"`, `curl -s -i "${url}"`, `curl -i -s "${url}"`, `curl  -i   "${url}"`]) {
    const r = run(l);
    assert.deepEqual(r.events, ["http:search-headers"], l);
    assert.match(r.output, /^HTTP\/1\.1 200 OK\nServer: Werkzeug/, l);
  }
  for (const l of [`curl ${url}`, `curl "${url}"`, `curl -s "${url}"`]) {
    const r = run(l);
    assert.deepEqual(r.events, ["http:search"], l);
    assert.equal(r.output, REAL_BODY, l);
  }
});

test("08-xss: any other curl form, term, path, host spelling or option is not modelled", () => {
  const run = fresh(xss);
  for (const l of [
    'curl -i "http://192.0.2.80:5000/search?q=socks"',
    'curl -i "http://192.0.2.80:5000/search?q=walking+boots"',
    'curl -i "http://192.0.2.80:5000/search?q="',
    'curl -i "http://192.0.2.80:5000/search"',
    'curl -i "http://192.0.2.80:5000/"',
    'curl -i "http://192.0.2.80:5000/search?q=boots&page=2"',
    'curl -i "http://192.0.2.80/search?q=boots"',
    'curl -i "https://192.0.2.80:5000/search?q=boots"',
    'curl -i "http://staging.fellside.example:5000/search?q=boots"',
    'curl -I "http://192.0.2.80:5000/search?q=boots"',
    'curl -v "http://192.0.2.80:5000/search?q=boots"',
    'curl -X POST "http://192.0.2.80:5000/search?q=boots"',
    'curl -d q=boots "http://192.0.2.80:5000/search"',
    'curl -i -H "Accept: text/html" "http://192.0.2.80:5000/search?q=boots"',
    'curl -i -i "http://192.0.2.80:5000/search?q=boots"',
    'wget "http://192.0.2.80:5000/search?q=boots"',
    'CURL -i "http://192.0.2.80:5000/search?q=boots"',
    "nmap 192.0.2.80",
  ]) notModelled(run(l), l);
});

test("08-xss: only the ordinary word boots is ever used as a search term", () => {
  const text = JSON.stringify({ ...xss, commands: xss.commands.map((c) => c.output) });
  const terms = new Set([...text.matchAll(/[?&]q=([^"'\s&\\]*)/g)].map((m) => m[1]));
  assert.deepEqual([...terms], ["boots"]);
});

test("08-xss: the live shop ends the engagement however it is named, the staging copy does not", () => {
  for (const line of [
    "curl http://www.fellside.example/",
    'curl -i "http://198.51.100.80/search?q=boots"',
    "curl https://www.fellside.example:8443/search",
    "cat www.fellside.example",
    "ping 198.51.100.80",
    "WWW.FELLSIDE.EXAMPLE",
  ]) {
    const r = runCommand(xss, newTerminal(xss), line);
    assert.equal(r.terminated, true, line);
    assert.match(r.output, /live shop/);
    assert.match(r.output, /named/);
    assert.doesNotMatch(r.output, /sent traffic/);
  }
  for (const line of ['curl -i "http://192.0.2.80:5000/search?q=boots"', "cat brief.txt", "ping 198.51.100.800"]) {
    assert.equal(runCommand(xss, newTerminal(xss), line).terminated, false, line);
  }
});

test("08-xss: the three context objectives and three type objectives each have one right option", () => {
  const byId = Object.fromEntries(xss.objectives.map((o) => [o.id, o]));
  assert.equal(byId["ctx-heading"].check.value, "HTML body (text between tags)");
  assert.equal(byId["ctx-input"].check.value, "HTML attribute value");
  assert.equal(byId["ctx-script"].check.value, "JavaScript string");
  assert.equal(byId["type-reflected"].check.value, "Reflected XSS");
  assert.equal(byId["type-stored"].check.value, "Stored XSS");
  assert.equal(byId["type-dom"].check.value, "DOM-based XSS");
  assert.equal(byId["which-unescaped"].check.value.startsWith("The heading"), true);
  assert.equal(byId["which-wrong-context"].check.value.startsWith("The lastSearch variable"), true);
  assert.match(byId["csp-header"].check.value, /^No:/);
  // a typed option completes only the first still-pending objective that expects it
  const s = newSession(xss);
  const r = applyInput(xss, s, "JavaScript string");
  assert.deepEqual(r.completed.map((o) => o.id), ["ctx-script"]);
  assert.equal(applyInput(xss, s, "JavaScript string").completed.length, 0);
});

test("08-xss: the defence keeps the exact qualifiers (encoding matches the context; CSP is not a replacement)", () => {
  const d = xss.defence;
  assert.match(d.check.value, /for each context/);
  assert.match(d.check.value, /extra layer/);
  assert.match(d.explanation, /should not be your primary defense mechanism/);
  assert.match(d.explanation, /not an alternative to sanitizing input/);
  assert.match(d.explanation, /using the wrong method may introduce weaknesses or harm the functionality/);
  assert.match(d.explanation, /unless extra measures are taken/);
  const wrong = d.check.options.filter((o) => o !== d.check.value);
  assert.equal(wrong.length, 3);
  assert.ok(wrong.some((o) => /replaces output encoding/.test(o)));
  assert.ok(wrong.some((o) => /one encoding is correct in every context/.test(o)));
});
