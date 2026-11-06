// The node's regex engine takes a leading (?i) flag, which JavaScript rejects, so it is dropped before the pattern is compiled here
export function stripLeadingFlags(source) {
  return String(source).replace(/^\(\?i\)/, '');
}

// Returns why the pattern cannot compile, or null
export function compileProblem(source) {
  try {
    new RegExp(stripLeadingFlags(source));
    return null;
  } catch (err) {
    return err.message.replace(/^Invalid regular expression: /, '');
  }
}
