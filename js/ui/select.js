import { el } from "./dom.js";
import { isComplete, isUnlocked } from "../engine/state.js";

const TIER_NAMES = { beginner: "Beginner", intermediate: "Intermediate", advanced: "Advanced" };

export function selectView(levels, progress, onOpen) {
  const done = levels.filter((l) => isComplete(progress, l.id)).length;
  const groups = [];
  for (const tier of ["beginner", "intermediate", "advanced"]) {
    const inTier = levels.map((level, index) => ({ level, index })).filter((x) => x.level.tier === tier);
    if (!inTier.length) continue;
    const items = inTier.map(({ level, index }) => {
      const complete = isComplete(progress, level.id);
      const open = isUnlocked(progress, levels, index);
      const status = complete ? "Complete" : open ? "Ready" : `Locked: finish level ${index} first`;
      const btn = el(
        "button",
        { type: "button", class: `level-btn ${complete ? "is-done" : open ? "is-open" : "is-locked"}`, disabled: !open, onclick: () => onOpen(index) },
        el("span", { class: "lv-n", text: String(level.order).padStart(2, "0") }),
        el("span", { class: "lv-main" }, el("span", { class: "lv-title", text: level.title }), el("span", { class: "lv-term", text: level.term })),
        el("span", { class: "lv-status", text: status })
      );
      return el("li", {}, btn);
    });
    groups.push(el("section", { class: "panel" }, el("h2", { text: TIER_NAMES[tier] }), el("ul", { class: "level-list" }, items)));
  }
  return el(
    "div",
    { class: "view" },
    el("div", { class: "level-head" }, el("p", { class: "eyebrow", text: "ethical hacking terms" }), el("h1", { text: "Pick a level" })),
    el("p", { class: "lead", text: "One term per level: a card, a simulated challenge, a defence step, a quiz question, then a debrief with sources. Levels unlock in order." }),
    el("p", { class: "progress-line" }, el("progress", { max: String(levels.length), value: String(done), "aria-label": "Levels completed" }), ` ${done} of ${levels.length} complete`),
    groups,
    el("p", { class: "note", text: "More levels will follow." })
  );
}
