import { el } from "./dom.js";
import { isComplete } from "../engine/state.js";

export function glossaryView(levels, progress, onSelect) {
  const sections = levels.map((level) => {
    const open = isComplete(progress, level.id);
    const head = el("h2", { text: `Level ${String(level.order).padStart(2, "0")}: ${level.term}` });
    if (!open) {
      return el("section", { class: "panel locked" }, head, el("p", { class: "note", text: `Locked. Finish "${level.title}" to unlock ${level.glossary.length} entries.` }));
    }
    return el("section", { class: "panel" }, head, el("dl", { class: "glossary-list" }, level.glossary.flatMap((g) => [el("dt", { text: g.term }), el("dd", { text: g.definition })])));
  });
  return el(
    "div",
    { class: "view" },
    el("div", { class: "level-head" }, el("p", { class: "eyebrow", text: "Reference" }), el("h1", { text: "Glossary" })),
    el("p", { class: "lead", text: "Entries unlock when you finish the level that teaches them." }),
    sections,
    el("div", { class: "actions" }, el("button", { type: "button", text: "Level select", onclick: onSelect }))
  );
}
