/*
 * Daemon Wallet - content script (ISOLATED world)
 *
 * Bridges the in-page provider (inpage.js, MAIN world) to the background
 * service worker. It carries nothing of its own: page requests go up to
 * background, responses and pushed events come back down to the page.
 *
 *   inpage.js  --window.postMessage-->  content.js  --runtime.sendMessage-->  background
 *   inpage.js  <--window.postMessage--  content.js  <--response / DW_EVENT--  background
 */
(function () {
  const TO_CONTENT = 'daemon-wallet-content'; // page -> content
  const TO_PAGE = 'daemon-wallet-inpage'; // content -> page

  // Page -> background
  window.addEventListener('message', (ev) => {
    if (ev.source !== window) return;
    const d = ev.data;
    if (!d || d.target !== TO_CONTENT || d.kind !== 'request') return;

    chrome.runtime.sendMessage(
      { type: 'DW_RPC_REQUEST', payload: { id: d.id, method: d.method, params: d.params } },
      (resp) => {
        if (chrome.runtime.lastError) {
          window.postMessage(
            {
              target: TO_PAGE,
              kind: 'response',
              id: d.id,
              error: { code: -1, message: chrome.runtime.lastError.message },
            },
            '*',
          );
          return;
        }
        window.postMessage(
          {
            target: TO_PAGE,
            kind: 'response',
            id: d.id,
            result: resp ? resp.result : undefined,
            error: resp ? resp.error : undefined,
          },
          '*',
        );
      },
    );
  });

  // Background events -> page
  chrome.runtime.onMessage.addListener((msg) => {
    if (!msg || msg.type !== 'DW_EVENT') return;
    const p = msg.payload || {};
    window.postMessage(
      { target: TO_PAGE, kind: 'event', event: p.event, data: p.data },
      '*',
    );
  });
})();
