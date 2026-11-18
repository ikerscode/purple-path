import { el, clear } from "./dom.js";
import { applyInput } from "../engine/checks.js";

export const SIM_LABEL = "simulated — nothing here touches a real system";

function promptFor(level, session) {
  const cwd = session.terminal.cwd;
  const home = level.world.cwd;
  let shown = cwd;
  if (cwd === home) shown = "~";
  else if (cwd.startsWith(home + "/")) shown = "~" + cwd.slice(home.length);
  return `${session.terminal.user}@lab:${shown}$`;
}

// Renders the fake terminal. onChange(result) fires after every submitted line.
export function createTerminalView(level, session, onChange) {
  const history = [];
  let cursor = 0;

  const screen = el("div", { class: "term-screen", role: "log", "aria-live": "polite", "aria-label": "Terminal output", tabindex: "0" });
  const promptEl = el("span", { class: "term-prompt", "aria-hidden": "true" });
  const input = el("input", {
    class: "term-field",
    type: "text",
    autocomplete: "off",
    autocapitalize: "off",
    autocorrect: "off",
    spellcheck: "false",
    enterkeyhint: "send",
    "aria-label": "Terminal command",
  });
  const form = el("form", { class: "term-input", autocomplete: "off" }, promptEl, input);
  const label = el("p", { class: "sim-label" }, el("span", { class: "sim-dot", "aria-hidden": "true" }), SIM_LABEL);
  const root = el("section", { class: "terminal", "aria-label": "Simulated terminal" }, label, screen, form);

  function refreshPrompt() {
    promptEl.textContent = promptFor(level, session) + " ";
  }

  function print(text, cls) {
    const line = el("pre", { class: `term-out ${cls || ""}`.trim() }, text);
    screen.append(line);
    screen.scrollTop = screen.scrollHeight;
  }

  function echo(command) {
    screen.append(el("div", { class: "term-cmd" }, el("span", { class: "term-prompt-echo" }, promptFor(level, session) + " "), command));
  }

  function lock() {
    input.disabled = true;
    form.classList.add("is-locked");
  }

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const line = input.value;
    input.value = "";
    if (line.trim()) {
      history.push(line);
      cursor = history.length;
    }
    echo(line);
    const result = applyInput(level, session, line);
    if (result.clear) clear(screen);
    else if (result.output) print(result.output, result.terminated ? "term-fatal" : "");
    refreshPrompt();
    if (result.terminated) lock();
    screen.scrollTop = screen.scrollHeight;
    onChange(result);
  });

  input.addEventListener("keydown", (event) => {
    if (event.key === "ArrowUp") {
      if (!history.length) return;
      event.preventDefault();
      cursor = Math.max(0, cursor - 1);
      input.value = history[cursor];
      input.setSelectionRange(input.value.length, input.value.length);
    } else if (event.key === "ArrowDown") {
      if (!history.length) return;
      event.preventDefault();
      cursor = Math.min(history.length, cursor + 1);
      input.value = cursor === history.length ? "" : history[cursor];
    }
  });

  root.addEventListener("click", (event) => {
    if (event.target === input || window.getSelection().toString()) return;
    input.focus();
  });

  print("purple-path training terminal. Type help for the built-ins and hint if you are stuck.");
  refreshPrompt();
  if (session.terminated) lock();

  return { root, input, focus: () => input.focus(), lock };
}
