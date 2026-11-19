# purple-path

A browser game that teaches ethical hacking terms, one term per level, from beginner to intermediate. I'm a cyber student and I built it because I learn terms better when I have to use them than when I read a list.

Everything in it is simulated. The terminal is a fake interpreter that reads canned responses from level data. Nothing runs on your machine, nothing is scanned and nothing leaves your browser.

## How to play

There is no build step and no dependencies. The game uses ES modules, and browsers will not load those from a `file://` address, so serve the folder over http. Any static server works:

```
python3 -m http.server 8000 --bind 127.0.0.1
```

Then open `http://127.0.0.1:8000/` in a browser. It also runs from GitHub Pages, which is set up in `.github/workflows/pages.yml`.

Levels unlock in order. Progress is saved in your browser's local storage, so a reload keeps it. If storage is blocked the game still works, it just forgets where you were.

## The levels

| # | Tier | Term |
|---|------|------|
| 1 | Beginner | Scope and rules of engagement |
| 2 | Beginner | Reconnaissance (passive vs active, OSINT) |
| 3 | Beginner | Ports, services and the TCP handshake |
| 4 | Beginner | Hashing vs encryption (storing passwords) |
| 5 | Beginner | Phishing |
| 6 | Intermediate | Enumeration |
| 7 | Intermediate | SQL injection |
| 8 | Intermediate | Cross-site scripting (XSS) |
| 9 | Intermediate | Privilege escalation (a sudo rule that is too broad) |
| 10 | Intermediate | Lateral movement |

Levels 4 and 7 to 10 are defence-first on purpose. They teach how the problem is recognised and fixed, and they do not hand out attack payloads or cracking steps.

## What happens in a level

1. **Card.** The term, why it matters and a short example.
2. **Simulated challenge.** A fake terminal and a list of objectives. Some objectives complete from what you run, some you answer in the panel. Type `help` for the built-in commands and `hint` if you are stuck.
3. **Defence step.** What you just looked at, now from the defender's side: the fix, or how you would spot it.
4. **Quiz.** One question.
5. **Debrief.** The glossary entries for the level unlock, along with the list of sources behind the level.

The glossary page collects the entries you have unlocked.

## Ethics

- Every host, address and name is fictional. IP addresses come only from the documentation ranges in RFC 5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and domain names only use `.example` or `.test`.
- Scope is a mechanic, not a footnote. In level 1, touching a host that is not in the written scope ends the engagement and you have to start again.
- Never test a system you are not authorised to test. In the UK, section 1 of the Computer Misuse Act 1990 makes it an offence to cause a computer to perform a function with intent to secure access to a program or data when that access is unauthorised and you know at the time that it is. Level 1 goes through this, including how the Act describes unauthorised access.
- Real command syntax is taught where a standard course would teach it, but the output is canned and the targets are not real.

## Sources

Every level lists its sources in its level file, and every factual claim in a level is meant to be backed by one of them. The debrief at the end of each level shows them as links that open in a new tab. I prefer standards and official documentation (RFCs, NIST, the Nmap reference guide, man pages, OWASP, PortSwigger, MITRE ATT&CK, NCSC, legislation.gov.uk). The URLs only appear in level data, never in the game code.

## Tests

You need Node 22 or newer. There is nothing to install.

```
node --test tests/*.test.js
```

The tests check every level against the schema, play each level's `solution` through the engine and check that all objectives and the defence step complete, check that each out-of-scope host ends the engagement, and check the hygiene rules: no `innerHTML`, no http(s) URLs in `js/` or `index.html`, and the strict Content Security Policy.

## Adding a level

Each level is one file in `levels/`, named `NN-slug.js`, that exports a plain object with no functions in it. Copy `levels/01-scope.js` as the pattern: it shows every field, from the card and the fake `world` to the `commands`, `objectives`, `defence`, `quiz`, `glossary`, `hints`, `solution` and `sources`. Then add the import to `levels/index.js`. The tests pick the new level up from there: it needs a `solution` that completes it, and at least five `sources`, all over https.

## Licence

The code is MIT licensed, see `LICENSE`.

The game text is set in Fira Code, which is bundled in `fonts/` so that nothing loads from another site. Fira Code is licensed under the SIL Open Font License 1.1, and the licence is in `fonts/OFL.txt`.
