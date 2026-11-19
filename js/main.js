import levels from "../levels/index.js";
import { loadProgress, saveProgress, markComplete, isComplete, isUnlocked } from "./engine/state.js";
import { newSession, isChallengeComplete } from "./engine/checks.js";
import { el, clear, focusHeading, announcer } from "./ui/dom.js";
import { selectView } from "./ui/select.js";
import { cardView, levelHeader, debriefView } from "./ui/cards.js";
import { createTerminalView } from "./ui/terminal-view.js";
import { createObjectivesView } from "./ui/objectives.js";
import { defenceView, quizView } from "./ui/quiz.js";
import { glossaryView } from "./ui/glossary.js";

const root = document.getElementById("main");
const readouts = document.getElementById("readouts");
const progress = loadProgress();
const live = announcer();
document.body.append(live.node);

function setReadouts(items) {
  clear(readouts);
  for (const [k, v] of items) {
    readouts.append(el("li", {}, el("span", { class: "k", text: `${k} ` }), el("span", { class: "v", text: v })));
  }
}

function show(view, items) {
  clear(root);
  root.append(view);
  setReadouts(items);
  focusHeading(root);
  window.scrollTo(0, 0);
}

const done = () => levels.filter((l) => isComplete(progress, l.id)).length;
const summary = () => [["done", `${done()}/${levels.length}`], ["mode", "simulated"]];

function showSelect() {
  show(selectView(levels, progress, showCard), summary());
}

function showGlossary() {
  show(glossaryView(levels, progress, showSelect), summary());
}

function levelReadout(i, step) {
  return [["level", `${String(levels[i].order).padStart(2, "0")}/${String(levels.length).padStart(2, "0")}`], ["step", step], ["mode", "simulated"]];
}

function showCard(i) {
  const level = levels[i];
  if (!isUnlocked(progress, levels, i)) return showSelect();
  show(cardView(level, () => showChallenge(i)), levelReadout(i, "card"));
}

function showChallenge(i) {
  const level = levels[i];
  const session = newSession(level);
  let next = null;
  const reveal = () => {
    if (next && !session.terminated && isChallengeComplete(level, session)) {
      next.hidden = false;
      live.say("All objectives complete. Continue to the defence step.");
    }
  };
  const objectives = createObjectivesView(level, session, live.say, reveal);
  const banner = el("section", { class: "panel fatal", hidden: true, role: "alert" });
  next = el("button", { type: "button", class: "primary", text: "Continue to the defence step", hidden: true, onclick: () => showDefence(i) });
  const terminal = createTerminalView(level, session, (result) => {
    for (const o of result.completed) live.say(`Objective complete: ${o.prompt}`);
    objectives.render();
    if (result.terminated) {
      banner.hidden = false;
      banner.replaceChildren(
        el("h2", { text: "Engagement terminated" }),
        el("p", { text: level.outOfScope.message }),
        el("div", { class: "actions" }, el("button", { type: "button", class: "primary", text: "Restart this level", onclick: () => showChallenge(i) }), el("button", { type: "button", text: "Level select", onclick: showSelect }))
      );
      banner.querySelector("button").focus();
      live.say("Engagement terminated. That command named an out-of-scope host.");
    } else {
      reveal();
    }
  });
  const view = el(
    "div",
    { class: "view" },
    levelHeader(level, "challenge"),
    banner,
    el("div", { class: "challenge-grid" }, terminal.root, objectives.root),
    el("div", { class: "actions" }, next, el("button", { type: "button", text: "Back to the card", onclick: () => showCard(i) }))
  );
  show(view, levelReadout(i, "challenge"));
  terminal.focus();
}

function showDefence(i) {
  show(defenceView(levels[i], () => showQuiz(i)), levelReadout(i, "defence"));
}

function showQuiz(i) {
  show(quizView(levels[i], () => finish(i)), levelReadout(i, "quiz"));
}

function finish(i) {
  markComplete(progress, levels[i].id);
  saveProgress(progress);
  showDebrief(i);
}

function showDebrief(i) {
  const next = levels[i + 1];
  show(
    debriefView(levels[i], next, {
      next: () => showCard(i + 1),
      select: showSelect,
      glossary: showGlossary,
    }),
    levelReadout(i, "debrief")
  );
}

document.getElementById("nav-levels").addEventListener("click", showSelect);
document.getElementById("nav-glossary").addEventListener("click", showGlossary);

showSelect();
