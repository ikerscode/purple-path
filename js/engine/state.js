// Progress persistence. Every storage access is wrapped: the game works without storage.

const KEY = "purple-path:v1";

function getStorage() {
  try {
    return globalThis.localStorage || null;
  } catch {
    return null;
  }
}

export function emptyProgress() {
  return { version: 1, completed: [] };
}

export function loadProgress(storage = getStorage()) {
  try {
    if (!storage) return emptyProgress();
    const raw = storage.getItem(KEY);
    if (!raw) return emptyProgress();
    const data = JSON.parse(raw);
    if (!data || data.version !== 1 || !Array.isArray(data.completed)) return emptyProgress();
    return { version: 1, completed: data.completed.filter((x) => typeof x === "string") };
  } catch {
    return emptyProgress();
  }
}

export function saveProgress(progress, storage = getStorage()) {
  try {
    if (storage) storage.setItem(KEY, JSON.stringify(progress));
    return true;
  } catch {
    return false;
  }
}

export function markComplete(progress, levelId) {
  if (!progress.completed.includes(levelId)) progress.completed.push(levelId);
  return progress;
}

export function isComplete(progress, levelId) {
  return progress.completed.includes(levelId);
}

// Levels unlock in order: the first is always open; each other needs the one before it complete.
export function isUnlocked(progress, levels, index) {
  if (index <= 0) return true;
  return isComplete(progress, levels[index - 1].id);
}

export function resetProgress(storage = getStorage()) {
  try {
    if (storage) storage.removeItem(KEY);
    return true;
  } catch {
    return false;
  }
}
