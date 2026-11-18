// Objective checks and the level session. Pure: no DOM, no storage.
import { newTerminal, runCommand, normaliseLine } from "./terminal.js";

function norm(s) {
  return normaliseLine(s).toLowerCase();
}

// check: { type: "answer" | "choice", value: string | string[] }
export function matchesAnswer(check, input) {
  const given = norm(input);
  if (!given) return false;
  const accepted = Array.isArray(check.value) ? check.value : [check.value];
  return accepted.some((v) => norm(v) === given);
}

export function newSession(level) {
  return {
    terminal: newTerminal(level),
    events: new Set(),
    done: new Set(),
    terminated: false,
  };
}

function refreshEventObjectives(level, session) {
  const fresh = [];
  for (const o of level.objectives) {
    if (session.done.has(o.id)) continue;
    if (o.check.type === "event" && session.events.has(o.check.value)) {
      session.done.add(o.id);
      fresh.push(o);
    }
  }
  return fresh;
}

export function isChallengeComplete(level, session) {
  return level.objectives.every((o) => session.done.has(o.id));
}

// Submits a value for one answer/choice objective (used by the UI controls).
export function submitObjective(level, session, objectiveId, value) {
  const o = level.objectives.find((x) => x.id === objectiveId);
  if (!o || o.check.type === "event" || session.done.has(o.id)) return { ok: false, objective: o };
  if (matchesAnswer(o.check, value)) {
    session.done.add(o.id);
    return { ok: true, objective: o };
  }
  return { ok: false, objective: o };
}

// Feeds one line of player input to the level. Command first; if the terminal
// does not model it, it is tried as an answer to a pending answer/choice objective.
export function applyInput(level, session, input) {
  if (session.terminated) {
    return { output: "The engagement has ended. Restart the level to try again.", events: [], clear: false, terminated: true, completed: [] };
  }
  const r = runCommand(level, session.terminal, input);
  const completed = [];
  if (r.terminated) {
    session.terminated = true;
    return { ...r, completed };
  }
  if (!r.handled) {
    for (const o of level.objectives) {
      if (session.done.has(o.id) || o.check.type === "event") continue;
      if (matchesAnswer(o.check, input)) {
        session.done.add(o.id);
        completed.push(o);
        return { ...r, output: "", handled: true, completed };
      }
    }
    return { ...r, completed };
  }
  for (const e of r.events) session.events.add(e);
  completed.push(...refreshEventObjectives(level, session));
  return { ...r, completed };
}

export function checkDefence(level, value) {
  return matchesAnswer(level.defence.check, value);
}

export function checkQuiz(level, index) {
  return Number(index) === level.quiz.answer;
}

// Headless full playthrough of level.solution: challenge entries first, then the
// defence entry (the first entry after the objectives are all complete).
export function runSolution(level) {
  const session = newSession(level);
  let defenceDone = false;
  const log = [];
  for (const step of level.solution) {
    if (!isChallengeComplete(level, session)) {
      const r = applyInput(level, session, step);
      log.push({ step, terminated: r.terminated, completed: r.completed.map((o) => o.id) });
      if (r.terminated) break;
    } else if (!defenceDone) {
      defenceDone = checkDefence(level, step);
      log.push({ step, defence: defenceDone });
    }
  }
  return { session, challengeDone: isChallengeComplete(level, session), defenceDone, log };
}
