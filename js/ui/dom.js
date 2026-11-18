// Tiny DOM helper. Text always goes in as text nodes, never as markup.

export function el(tag, props = {}, ...kids) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key.startsWith("on") && typeof value === "function") node.addEventListener(key.slice(2), value);
    else if (value === true) node.setAttribute(key, "");
    else node.setAttribute(key, String(value));
  }
  append(node, kids);
  return node;
}

export function append(node, kids) {
  for (const kid of kids.flat(Infinity)) {
    if (kid === null || kid === undefined || kid === false) continue;
    node.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return node;
}

export function clear(node) {
  node.replaceChildren();
  return node;
}

export function focusHeading(root) {
  const h = root.querySelector("h1");
  if (!h) return;
  h.setAttribute("tabindex", "-1");
  h.focus({ preventScroll: false });
}

// Visually hidden live region for announcements.
export function announcer() {
  const node = el("div", { class: "visually-hidden", role: "status", "aria-live": "polite" });
  return {
    node,
    say(message) {
      node.textContent = "";
      setTimeout(() => { node.textContent = message; }, 30);
    },
  };
}

let uid = 0;
export function nextId(prefix) {
  uid += 1;
  return `${prefix}-${uid}`;
}
