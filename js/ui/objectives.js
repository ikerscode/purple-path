import { el, nextId } from "./dom.js";
import { submitObjective } from "../engine/checks.js";

// Objectives panel. Event objectives complete from terminal activity; answer and
// choice objectives show their own controls (answers also work in the terminal).
export function createObjectivesView(level, session, say, onProgress = () => {}) {
  const list = el("ol", { class: "objectives" });
  const heading = el("h2", { text: "Objectives", tabindex: "-1" });
  const root = el("section", { class: "panel objectives-panel", "aria-label": "Objectives" }, heading, list);
  const notes = new Map();

  function controlFor(o) {
    const note = el("p", { class: "status", role: "status" });
    notes.set(o.id, note);
    const done = () => { render(); heading.focus(); say(`Objective complete: ${o.prompt}`); onProgress(); };
    if (o.check.type === "answer") {
      const id = nextId("ans");
      const input = el("input", { id, class: "text-field", type: "text", autocomplete: "off", autocapitalize: "off", spellcheck: "false", "aria-label": "Your answer" });
      const form = el("form", { class: "inline-form" }, input, el("button", { type: "submit", text: "Answer" }));
      form.addEventListener("submit", (e) => {
        e.preventDefault();
        const r = submitObjective(level, session, o.id, input.value);
        if (r.ok) done();
        else note.textContent = "Not quite. Check the output again, or type hint in the terminal.";
      });
      return [form, note];
    }
    const name = nextId("choice");
    const fieldset = el("fieldset", { class: "choices" }, el("legend", { class: "visually-hidden", text: o.prompt }));
    for (const opt of o.check.options) {
      const input = el("input", { type: "radio", name, value: opt });
      fieldset.append(el("label", { class: "choice" }, input, el("span", { class: "c-text", text: opt })));
    }
    const form = el("form", { class: "choice-form" }, fieldset, el("button", { type: "submit", text: "Answer" }));
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const picked = form.querySelector("input:checked");
      if (!picked) { note.textContent = "Pick an option first."; return; }
      const r = submitObjective(level, session, o.id, picked.value);
      if (r.ok) done();
      else note.textContent = "Not quite. Try another option.";
    });
    return [form, note];
  }

  function render() {
    list.replaceChildren();
    for (const o of level.objectives) {
      const isDone = session.done.has(o.id);
      const mark = el("span", { class: "obj-mark", "aria-hidden": "true" }, isDone ? "[x]" : "[ ]");
      const state = el("span", { class: "visually-hidden", text: isDone ? "Done: " : "To do: " });
      const li = el("li", { class: isDone ? "obj done" : "obj" }, mark, el("div", { class: "obj-body" }, el("p", { class: "obj-prompt" }, state, o.prompt)));
      const body = li.querySelector(".obj-body");
      if (isDone) body.append(el("p", { class: "obj-success", text: o.success }));
      else if (o.check.type !== "event" && !session.terminated) body.append(...controlFor(o));
      list.append(li);
    }
  }

  render();
  return { root, render };
}
