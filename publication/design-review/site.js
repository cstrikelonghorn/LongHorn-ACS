'use strict';
// Local presentation only: no network requests, telemetry, cookies or storage.
for (const button of document.querySelectorAll('[data-copy]')) {
  button.addEventListener('click', async () => {
    const target = document.getElementById(button.dataset.copy);
    const status = button.closest('.checksum-panel').querySelector('.copy-status');
    if (!target) return;
    try {
      if (!navigator.clipboard?.writeText) throw new Error('Clipboard unavailable');
      await navigator.clipboard.writeText(target.textContent.trim());
      status.textContent = 'SHA-256 copied.';
    } catch {
      const range = document.createRange();
      range.selectNodeContents(target);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      status.textContent = 'Hash selected. Use your device’s Copy command.';
    }
  });
}
const input = document.getElementById('faq-search');
if (input) {
  document.querySelector('[data-search-box]').hidden = false;
  const groups = [...document.querySelectorAll('[data-faq-group]')];
  const items = [...document.querySelectorAll('[data-faq-group] details')];
  const initiallyOpen = items.map(item => item.open);
  input.addEventListener('input', () => {
    const query = input.value.trim().toLocaleLowerCase();
    let count = 0;
    items.forEach((item, index) => {
      const match = !query || item.textContent.toLocaleLowerCase().includes(query);
      item.hidden = !match;
      item.open = query ? match : initiallyOpen[index];
      if (match) count++;
    });
    for (const group of groups) group.hidden = ![...group.querySelectorAll('details')].some(item => !item.hidden);
    document.querySelector('.empty-search').hidden = count !== 0;
    document.getElementById('search-status').textContent = query ? `${count} matching question${count === 1 ? '' : 's'}.` : '';
  });
}
