export function makeDirty(read) {
  let saved = JSON.stringify(read());
  return {
    dirty: () => JSON.stringify(read()) !== saved,
    // Called after a successful save, or when the form is reloaded from the node
    reset: () => {
      saved = JSON.stringify(read());
    },
    saved: () => saved,
  };
}

export function dirtyGroup(parts) {
  return {
    dirty: () => Object.values(parts).some((p) => p.dirty()),
    names: () => Object.entries(parts).filter(([, p]) => p.dirty()).map(([name]) => name),
    reset: () => Object.values(parts).forEach((p) => p.reset()),
  };
}

export function dirtyText(names) {
  if (!names.length) return '';
  return names.length === 1 ? `Unsaved changes in ${names[0]}` : `Unsaved changes in ${names.slice(0, -1).join(', ')} and ${names.at(-1)}`;
}
