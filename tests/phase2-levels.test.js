import { test } from "node:test";
import assert from "node:assert/strict";
import levels from "../levels/index.js";
import { newTerminal, runCommand } from "../js/engine/terminal.js";

const phishing = levels.find((l) => l.id === "05-phishing");
const enumeration = levels.find((l) => l.id === "06-enumeration");

const fresh = (level) => {
  const term = newTerminal(level);
  return (line) => runCommand(level, term, line);
};
const notModelled = (r, line) => {
  assert.equal(r.handled, false, line);
  assert.match(r.output, /not modelled/, line);
  assert.deepEqual(r.events, [], line);
};

test("level 3: default and version scans, forms, and unmodelled variants", () => {
  const level = levels.find((l) => l.id === "03-ports");
  const run = fresh(level);
  const plain = run("nmap web02.example.test");
  assert.deepEqual(plain.events, ["scanned:192.0.2.30"]);
  assert.match(plain.output, /^Starting Nmap 7\.98 /);
  assert.doesNotMatch(plain.output, /VERSION|Service Info/);
  assert.match(plain.output, /Not shown: 996 closed tcp ports \(conn-refused\)/);
  assert.match(plain.output, /23\/tcp filtered telnet/);
  for (const l of ["nmap -sV 192.0.2.30", "nmap 192.0.2.30 -sV", "NMAP  -sV   web02.example.test"]) {
    const r = run(l);
    assert.deepEqual(r.events, ["versioned:192.0.2.30"], l);
    assert.match(r.output, /Service Info: OSs: Unix, Linux; CPE: cpe:\/o:linux:linux_kernel/);
    assert.match(r.output, /21\/tcp open {5}ftp {5}vsftpd 3\.0\.5/);
  }
  for (const l of ["nmap -sS 192.0.2.30", "nmap -p- 192.0.2.30", "nmap -sV -O 192.0.2.30", "nmap -A 192.0.2.30", "nmap 192.0.2.32"]) notModelled(run(l), l);
  assert.equal(run("nmap 192.0.2.31").terminated, true);
});

test("level 5: dig answers only TXT for the client's own domain; message hosts end the engagement", () => {
  const run = fresh(phishing);
  assert.equal(run("dig +short TXT fernleigh.example").output, '"v=spf1 ip4:192.0.2.25 -all"');
  assert.equal(run("dig +short TXT _dmarc.fernleigh.example").events[0], "dns:dmarc");
  assert.equal(run("dig TXT fernleigh.example +short").events[0], "dns:spf");
  for (const l of [
    "dig TXT fernleigh.example",
    "dig +short A fernleigh.example",
    "dig +short MX fernleigh.example",
    "dig +short ANY fernleigh.example",
    "dig +short TXT mail.fernleigh.example",
    "dig +short TXT selector1._domainkey.fernleigh.example",
    "dig +short TXT fernleigh.example SOA",
  ]) notModelled(run(l), l);
  for (const l of ["dig +short TXT fernleigh-helpdesk.test", "ping portal.fernleigh-helpdesk.test", "nmap 198.51.100.25", "cat mailer.fernleigh-helpdesk.test"]) {
    assert.equal(runCommand(phishing, newTerminal(phishing), l).terminated, true, l);
  }
  assert.equal(run("cat inbox/forwarded.eml").events[0], "read:/home/analyst/inbox/forwarded.eml");
  assert.match(phishing.outOfScope.message, /named a host/);
});

test("level 6: curl and gobuster forms match the captured tool output", () => {
  const run = fresh(enumeration);
  assert.equal(run("curl http://192.0.2.50/robots.txt").events[0], "http:robots");
  assert.equal(run("curl -s http://192.0.2.50/robots.txt").events[0], "http:robots");
  assert.equal(run("curl http://192.0.2.50/backup/").events[0], "http:backup");
  assert.match(run("curl http://192.0.2.50/backup").output, /301 Moved Permanently/);
  assert.match(run("curl http://192.0.2.50/admin").output, /401 Authorization Required/);
  assert.match(run("curl http://192.0.2.50").output, /Larkfield Example Ltd/);
  for (const l of ["curl -I http://192.0.2.50/", "curl -sI http://192.0.2.50", "curl -s -I http://192.0.2.50/"]) {
    const r = run(l);
    assert.equal(r.events[0], "http:headers", l);
    assert.match(r.output, /^HTTP\/1\.1 200 OK\nServer: nginx\/1\.30\.4\n/);
  }
  for (const l of [
    "gobuster dir -u http://192.0.2.50 -w wordlists/small.txt --no-progress",
    "gobuster dir --no-progress -w wordlists/small.txt -u http://192.0.2.50",
    "gobuster dir -u http://192.0.2.50 -w /home/analyst/wordlists/small.txt --no-progress",
  ]) {
    const r = run(l);
    assert.deepEqual(r.events, ["enum:gobuster"], l);
    assert.match(r.output, /^={63}\nGobuster v3\.8\.2\n/);
    assert.match(r.output, /admin {16}\(Status: 401\) \[Size: 179\]/);
  }
  assert.match(run("gobuster dir -u http://192.0.2.50 -w /home/analyst/wordlists/small.txt --no-progress").output, /Wordlist: {16}\/home\/analyst\/wordlists\/small\.txt/);
  for (const l of [
    "gobuster dir -u http://192.0.2.50 -w wordlists/small.txt",
    "gobuster dir -u http://192.0.2.50 -w wordlists/other.txt --no-progress",
    "gobuster dir -u http://192.0.2.50 -w wordlists/small.txt --no-progress -x php",
    "gobuster dir -u http://192.0.2.50 -w wordlists/small.txt --no-progress --no-progress",
    "gobuster dns -d larkfield.example -w wordlists/small.txt",
    "curl -I http://192.0.2.50/robots.txt",
    "curl -i http://192.0.2.50/",
    "curl http://www.larkfield.example/robots.txt",
    "curl http://192.0.2.50/images/",
  ]) notModelled(run(l), l);
  assert.equal(run("curl http://192.0.2.51/").terminated, true);
});

test("level 6: the wordlist file lists the words the simulated check used", () => {
  const words = enumeration.world.files["/home/analyst/wordlists/small.txt"].split("\n");
  for (const w of ["admin", "backup", "images", "robots.txt", "index.html"]) assert.ok(words.includes(w), w);
  assert.equal(words.length, 21);
});

test("a URL naming an out-of-scope host ends the engagement (with or without a port or path)", () => {
  for (const [level, host] of [[enumeration, "192.0.2.51"], [enumeration, "staff.larkfield.example"], [phishing, "portal.fernleigh-helpdesk.test"]]) {
    for (const line of [`curl http://${host}/`, `curl https://${host}:8443/x/y`, `gobuster dir -u http://${host} -w wordlists/small.txt --no-progress`]) {
      const r = runCommand(level, newTerminal(level), line);
      assert.equal(r.terminated, true, line);
    }
  }
  const run = fresh(enumeration);
  assert.equal(run("curl http://192.0.2.510/").terminated, false);
  assert.equal(run("curl http://192.0.2.50/").terminated, false);
});
