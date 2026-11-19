import { test } from "node:test";
import assert from "node:assert/strict";
import levels from "../levels/index.js";
import { runCommand, newTerminal } from "../js/engine/terminal.js";

const level = levels[0];

function fresh() {
  const term = newTerminal(level);
  return (line) => runCommand(level, term, line);
}

test("ls: last of -a / -A wins, as in GNU ls", () => {
  const run = fresh();
  const plain = run("ls").output;
  const aA = run("ls -aA").output.split("\n");
  assert.ok(!aA.includes("."), "-aA must not show .");
  assert.ok(!aA.includes(".."), "-aA must not show ..");
  assert.equal(run("ls -aA").output, plain);
  assert.equal(run("ls -Aa").output.split("\n").slice(0, 2).join(","), ".,..");
  assert.equal(run("ls -a -A").output, plain);
  assert.equal(run("ls -A -a").output.split("\n").slice(0, 2).join(","), ".,..");
});

test("cd: a file is 'Not a directory', a missing path is 'No such file'", () => {
  const run = fresh();
  assert.equal(run("cd README.txt").output, "bash: cd: README.txt: Not a directory");
  assert.equal(run("pwd").output, level.world.cwd, "cwd unchanged after failed cd");
  assert.equal(run("cd nowhere").output, "bash: cd: nowhere: No such file or directory");
});

test("cat: any option is not modelled rather than treated as a file name", () => {
  const run = fresh();
  for (const l of ["cat -n README.txt", "cat -", "cat --help"]) {
    const r = run(l);
    assert.equal(r.handled, false, l);
    assert.match(r.output, /not modelled/, l);
    assert.deepEqual(r.events, [], l);
  }
});
