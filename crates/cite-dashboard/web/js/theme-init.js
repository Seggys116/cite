// Runs before first paint so a stored theme choice does not flash the wrong palette
try {
  const stored = localStorage.getItem('cite.theme');
  if (stored === 'light' || stored === 'dark') document.documentElement.dataset.theme = stored;
} catch (err) {
  document.documentElement.removeAttribute('data-theme');
}
