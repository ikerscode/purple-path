import { el } from "./dom.js";

export const STEPS = [
  ["card", "Card"],
  ["challenge", "Challenge"],
  ["defence", "Defence"],
  ["quiz", "Quiz"],
  ["debrief", "Debrief"],
];

export function stepper(current) {
  return el(
    "ol",
    { class: "steps", "aria-label": "Level steps" },
    STEPS.map(([key, name], i) =>
      el("li", { class: key === current ? "step current" : "step", "aria-current": key === current ? "step" : null }, el("span", { class: "step-n", text: String(i + 1) }), el("span", { class: "step-name", text: name }))
    )
  );
}

export function levelHeader(level, step) {
  return el(
    "div",
    { class: "level-head" },
    el("p", { class: "eyebrow", text: `Level ${String(level.order).padStart(2, "0")} // ${level.tier}` }),
    el("h1", { text: level.title }),
    stepper(step)
  );
}

export function cardView(level, onStart) {
  const block = (label, text) => el("section", { class: "card-block" }, el("h2", { text: label }), el("p", { text }));
  return el(
    "div",
    { class: "view" },
    levelHeader(level, "card"),
    el(
      "article",
      { class: "panel term-card" },
      el("p", { class: "term-name" }, el("span", { class: "k", text: "term" }), level.term),
      block("What it is", level.card.what),
      block("Why it matters", level.card.why),
      block("Example", level.card.example),
      el("p", { class: "note", text: "Real testing needs authorisation. Everything in this game is simulated." }),
      el("div", { class: "actions" }, el("button", { type: "button", class: "primary", text: "Start the challenge", onclick: onStart }))
    )
  );
}

function sourceLink(source) {
  const a = el("a", { href: source.url, target: "_blank", rel: "noopener noreferrer" });
  let label = source.url;
  try {
    const u = new URL(source.url);
    label = u.hostname + (u.pathname === "/" ? "" : u.pathname);
  } catch {
    // keep the raw URL as the label
  }
  a.textContent = label;
  return a;
}

export function debriefView(level, nextLevel, handlers) {
  const glossary = el(
    "dl",
    { class: "glossary-list" },
    level.glossary.flatMap((g) => [el("dt", { text: g.term }), el("dd", { text: g.definition })])
  );
  const sources = el(
    "ul",
    { class: "sources" },
    level.sources.map((s) => el("li", {}, el("span", { class: "claim", text: s.claim }), " ", sourceLink(s)))
  );
  return el(
    "div",
    { class: "view" },
    levelHeader(level, "debrief"),
    el(
      "section",
      { class: "panel" },
      el("h2", { text: "Level complete" }),
      el("p", { text: `You have finished "${level.title}". These glossary entries are now unlocked.` }),
      glossary
    ),
    el(
      "section",
      { class: "panel" },
      el("h2", { text: "Sources" }),
      el("p", { class: "note", text: "Each claim in this level is backed by one of these pages. They open in a new tab." }),
      sources
    ),
    el(
      "div",
      { class: "actions" },
      nextLevel ? el("button", { type: "button", class: "primary", text: `Next: ${nextLevel.title}`, onclick: handlers.next }) : null,
      el("button", { type: "button", text: "Level select", onclick: handlers.select }),
      el("button", { type: "button", text: "Glossary", onclick: handlers.glossary })
    )
  );
}
