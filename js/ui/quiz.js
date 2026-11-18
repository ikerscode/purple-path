import { el, nextId } from "./dom.js";
import { levelHeader } from "./cards.js";
import { checkDefence, checkQuiz } from "../engine/checks.js";

function choiceGroup(options, name, legend) {
  const fieldset = el("fieldset", { class: "choices" }, el("legend", { text: legend }));
  options.forEach((opt, i) => {
    fieldset.append(
      el("label", { class: "choice" }, el("input", { type: "radio", name, value: String(i) }), el("span", { class: "c-text", text: opt }))
    );
  });
  return fieldset;
}

function pickedIndex(form) {
  const picked = form.querySelector("input:checked");
  return picked ? Number(picked.value) : -1;
}

// Shared shape: a question, a way to answer, retry on a wrong answer, an
// explanation and a continue button once it is right.
function questionView(level, step, heading, prompt, buildControl, evaluate, onDone, doneLabel, explanation) {
  const status = el("p", { class: "status", role: "status" });
  const explain = el("div", { class: "explain", hidden: true });
  const cont = el("button", { type: "button", class: "primary", text: doneLabel, hidden: true, onclick: onDone });
  const submit = el("button", { type: "submit", text: "Check answer" });
  const control = buildControl();
  const form = el("form", { class: "question" }, control.node, el("div", { class: "actions" }, submit, cont), status, explain);
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const value = control.value();
    if (value === null) {
      status.className = "status error";
      status.textContent = "Choose or type an answer first.";
      return;
    }
    if (evaluate(value)) {
      status.className = "status ok";
      status.textContent = "Correct.";
      explain.hidden = false;
      explain.replaceChildren(el("h3", { text: "Why" }), el("p", { text: explanation }));
      submit.hidden = true;
      cont.hidden = false;
      form.querySelectorAll("input").forEach((i) => { i.disabled = true; });
      cont.focus();
    } else {
      status.className = "status error";
      status.textContent = "Not quite. Read the options again and try another.";
    }
  });
  return el(
    "div",
    { class: "view" },
    levelHeader(level, step),
    el("section", { class: "panel" }, el("h2", { text: heading }), el("p", { class: "prompt", text: prompt }), form)
  );
}

export function defenceView(level, onDone) {
  const check = level.defence.check;
  const buildControl = () => {
    if (check.type === "choice") {
      const group = choiceGroup(check.options, nextId("def"), "Choose one");
      return { node: group, value: () => { const i = pickedIndex(group); return i < 0 ? null : check.options[i]; } };
    }
    const input = el("input", { type: "text", class: "text-field", autocomplete: "off", spellcheck: "false", "aria-label": "Your answer" });
    return { node: input, value: () => (input.value.trim() ? input.value : null) };
  };
  return questionView(level, "defence", "Defence", level.defence.prompt, buildControl, (v) => checkDefence(level, v), onDone, "Continue to the quiz", level.defence.explanation);
}

export function quizView(level, onDone) {
  const buildControl = () => {
    const group = choiceGroup(level.quiz.options, nextId("quiz"), "Choose one");
    return { node: group, value: () => { const i = pickedIndex(group); return i < 0 ? null : i; } };
  };
  return questionView(level, "quiz", "Quiz", level.quiz.question, buildControl, (v) => checkQuiz(level, v), onDone, "Finish the level", level.quiz.explanation);
}
