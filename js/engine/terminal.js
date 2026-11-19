// Fake terminal interpreter. Nothing here executes anything: a command line is
// matched against data in the level file and the canned text is returned.
// No DOM access, so it runs headless under node --test.

export const BUILTINS = ["help", "hint", "clear", "ls", "cat", "whoami", "pwd", "cd"];

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

export function normaliseLine(line) {
  return String(line ?? "").trim().replace(/\s+/g, " ");
}

export function newTerminal(level) {
  const world = level.world || {};
  return {
    cwd: world.cwd || "/",
    user: world.user || "analyst",
    hintIndex: 0,
    terminated: false,
  };
}

function ipToInt(ip) {
  const m = IPV4.exec(ip);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some((p) => p > 255)) return null;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function cidrContains(cidr, ip) {
  const [base, bits] = cidr.split("/");
  const b = ipToInt(base);
  const t = ipToInt(ip);
  const n = Number(bits);
  if (b === null || t === null || !Number.isInteger(n) || n < 0 || n > 32) return false;
  const mask = n === 0 ? 0 : (0xffffffff << (32 - n)) >>> 0;
  return ((b & mask) >>> 0) === ((t & mask) >>> 0);
}

function tokens(line) {
  return line.toLowerCase().split(/[^a-z0-9.:/_-]+/).filter(Boolean).map((t) => t.replace(/\.$/, ""));
}

// True when the line names an out-of-scope host (exact token, or a CIDR range that contains it).
export function touchesOutOfScope(level, line) {
  const hosts = (level.outOfScope && level.outOfScope.hosts) || [];
  if (!hosts.length) return false;
  const toks = tokens(line);
  for (const raw of hosts) {
    const host = raw.toLowerCase();
    for (const t of toks) {
      if (t === host) return true;
      if (t.includes("/") && IPV4.test(host) && cidrContains(t, host)) return true;
      // A URL names its host between "://" and the next "/" (an optional :port is ignored).
      const url = /^[a-z][a-z0-9+.-]*:\/\/([^/]+)/.exec(t);
      if (url && url[1].replace(/:\d+$/, "") === host) return true;
    }
  }
  return false;
}

export function resolvePath(cwd, p) {
  const parts = (p.startsWith("/") ? p : `${cwd}/${p}`).split("/");
  const out = [];
  for (const part of parts) {
    if (!part || part === ".") continue;
    if (part === "..") out.pop();
    else out.push(part);
  }
  return "/" + out.join("/");
}

function listDir(files, dir) {
  const prefix = dir === "/" ? "/" : dir + "/";
  const names = new Set();
  for (const path of Object.keys(files)) {
    if (!path.startsWith(prefix)) continue;
    const rest = path.slice(prefix.length);
    const slash = rest.indexOf("/");
    names.add(slash === -1 ? rest : rest.slice(0, slash));
  }
  return [...names].sort();
}

function isDir(files, p) {
  const prefix = p === "/" ? "/" : p + "/";
  return Object.keys(files).some((f) => f.startsWith(prefix));
}

const UNMODELLED =
  "[simulation] That command is not modelled in this exercise. Type help for the list of built-ins, or hint if you are stuck.";

// Runs one line. Mutates `term` (cwd, hintIndex, terminated) and returns
// { output, events, clear, terminated, handled }.
export function runCommand(level, term, line) {
  const text = normaliseLine(line);
  const result = { output: "", events: [], clear: false, terminated: false, handled: true };
  const world = level.world || {};
  const files = world.files || {};

  if (term.terminated) {
    result.output = "The engagement has ended. Restart the level to try again.";
    result.terminated = true;
    return result;
  }
  if (!text) return result;

  if (touchesOutOfScope(level, text)) {
    term.terminated = true;
    result.terminated = true;
    result.events.push("terminated:out-of-scope");
    result.output = `ENGAGEMENT TERMINATED\n${(level.outOfScope && level.outOfScope.message) || ""}`.trimEnd();
    return result;
  }

  const [cmd, ...rawArgs] = text.split(" ");
  const name = cmd.toLowerCase();
  // bash expands a leading ~ before the command runs; home is the level's starting directory.
  const home = world.cwd || "/";
  const args = rawArgs.map((a) => (a === "~" ? home : a.startsWith("~/") ? home + a.slice(1) : a));

  switch (name) {
    case "help":
      result.output = [
        "Built-in commands:",
        "  help          show this list",
        "  hint          show the next hint",
        "  clear         clear the screen",
        "  ls [path]     list files",
        "  cat <file>    print a file",
        "  cd <dir>      change directory",
        "  pwd           print the working directory",
        "  whoami        print the user name",
        "",
        "Everything here is simulated. The objectives panel says what to do.",
      ].join("\n");
      return result;
    case "hint": {
      const hints = level.hints || [];
      if (!hints.length) {
        result.output = "No hints for this level.";
      } else {
        const i = Math.min(term.hintIndex, hints.length - 1);
        result.output = `hint ${i + 1}/${hints.length}: ${hints[i]}`;
        term.hintIndex = Math.min(term.hintIndex + 1, hints.length - 1);
      }
      return result;
    }
    case "clear":
      result.clear = true;
      return result;
    case "whoami":
      if (args.length) {
        result.handled = false;
        result.output = UNMODELLED;
        return result;
      }
      result.output = term.user;
      return result;
    case "pwd":
      result.output = term.cwd;
      return result;
    case "ls": {
      const flags = args.filter((a) => a.startsWith("-"));
      if (flags.some((f) => !/^-[aA]+$/.test(f))) {
        result.handled = false;
        result.output = UNMODELLED;
        return result;
      }
      // GNU ls: the last of -a / -A given wins.
      const lastDotFlag = flags.flatMap((f) => f.slice(1).split("")).filter((c) => c === "a" || c === "A").pop();
      const showDots = lastDotFlag === "a";
      const targets = args.filter((a) => !a.startsWith("-"));
      if (targets.length > 1) {
        result.handled = false;
        result.output = UNMODELLED;
        return result;
      }
      const target = targets[0];
      const dir = target ? resolvePath(term.cwd, target) : term.cwd;
      if (Object.prototype.hasOwnProperty.call(files, dir)) {
        result.output = target;
      } else if (isDir(files, dir)) {
        result.output = [...(showDots ? [".", ".."] : []), ...listDir(files, dir)].join("\n");
      } else {
        result.output = `ls: cannot access '${target || dir}': No such file or directory`;
      }
      return result;
    }
    case "cd": {
      if (args.length > 1) {
        result.output = "bash: cd: too many arguments";
        return result;
      }
      const dir = args[0] ? resolvePath(term.cwd, args[0]) : (world.cwd || "/");
      if (isDir(files, dir) || dir === "/") term.cwd = dir;
      else if (Object.prototype.hasOwnProperty.call(files, dir)) result.output = `bash: cd: ${args[0]}: Not a directory`;
      else result.output = `bash: cd: ${args[0]}: No such file or directory`;
      return result;
    }
    case "cat": {
      if (!args.length) {
        result.output = "[simulation] cat needs a file name here (real cat would wait to read standard input).";
        return result;
      }
      if (args.some((a) => a.startsWith("-"))) {
        result.handled = false;
        result.output = UNMODELLED;
        return result;
      }
      const lines = [];
      for (const a of args) {
        const path = resolvePath(term.cwd, a);
        if (Object.prototype.hasOwnProperty.call(files, path)) {
          lines.push(files[path].replace(/\n$/, ""));
          result.events.push(`read:${path}`);
        } else if (isDir(files, path)) {
          lines.push(`cat: ${a}: Is a directory`);
        } else {
          lines.push(`cat: ${a}: No such file or directory`);
        }
      }
      result.output = lines.join("\n");
      return result;
    }
    default:
  }

  for (const c of level.commands || []) {
    if (new RegExp(c.match, c.caseSensitive ? "" : "i").test(text)) {
      result.output = c.output;
      if (c.event) result.events.push(c.event);
      return result;
    }
  }

  result.handled = false;
  result.output = UNMODELLED;
  return result;
}
