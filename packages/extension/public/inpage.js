/*
 * Daemon Wallet - in-page provider (MAIN world)
 *
 * Injects an EIP-1193 provider as window.ethereum. It holds no keys and no
 * secrets: request() posts to the content script and resolves when the answer
 * returns. Also announces itself via EIP-6963.
 */
(function () {
  if (window.ethereum && window.ethereum.isDaemonWallet) return;

  const TO_CONTENT = 'daemon-wallet-content'; // page -> content
  const TO_PAGE = 'daemon-wallet-inpage'; // content -> page

  let nextId = 1;
  const pending = new Map(); // id -> { resolve, reject, method }
  const listeners = new Map(); // event -> Set<fn>

  function emit(event, data) {
    const set = listeners.get(event);
    if (!set) return;
    for (const fn of set) {
      try {
        fn(data);
      } catch (e) {
        // A listener throwing must not break the provider.
        console.error('[daemon-wallet] listener error', e);
      }
    }
  }

  const provider = {
    isDaemonWallet: true,
    // Deliberately not claiming to be MetaMask.
    _accounts: [],
    _chainId: '0x1',

    request(args) {
      const method = args && args.method;
      const params = (args && args.params) || [];
      if (!method) {
        return Promise.reject(Object.assign(new Error('method is required'), { code: -32602 }));
      }
      return new Promise((resolve, reject) => {
        const id = 'dw-' + nextId++;
        pending.set(id, { resolve, reject, method });
        window.postMessage({ target: TO_CONTENT, kind: 'request', id, method, params }, '*');
      });
    },

    on(event, handler) {
      if (!listeners.has(event)) listeners.set(event, new Set());
      listeners.get(event).add(handler);
      return provider;
    },

    removeListener(event, handler) {
      const set = listeners.get(event);
      if (set) set.delete(handler);
      return provider;
    },

    // Legacy helpers some DApps still call.
    enable() {
      return provider.request({ method: 'eth_requestAccounts' });
    },
    get chainId() {
      return provider._chainId;
    },
    get selectedAddress() {
      return provider._accounts[0] || null;
    },
    get isConnected() {
      return () => provider._accounts.length > 0;
    },
  };

  function applyAccounts(accounts) {
    const next = Array.isArray(accounts) ? accounts : [];
    const changed = next.join(',') !== provider._accounts.join(',');
    provider._accounts = next;
    if (changed) {
      emit('accountsChanged', next);
      if (next.length) emit('connect', { chainId: provider._chainId });
      else emit('disconnect', { code: 4900, message: 'disconnected' });
    }
  }

  // Responses and events from the content script.
  window.addEventListener('message', (ev) => {
    if (ev.source !== window) return;
    const d = ev.data;
    if (!d || d.target !== TO_PAGE) return;

    if (d.kind === 'response') {
      const p = pending.get(d.id);
      if (!p) return;
      pending.delete(d.id);
      if (d.error) {
        const err = new Error(d.error.message || 'Request failed');
        err.code = d.error.code;
        p.reject(err);
        return;
      }
      if (p.method === 'eth_requestAccounts' || p.method === 'eth_accounts') {
        applyAccounts(d.result);
      } else if (p.method === 'eth_chainId' && typeof d.result === 'string') {
        provider._chainId = d.result;
      }
      p.resolve(d.result);
      return;
    }

    if (d.kind === 'event') {
      switch (d.event) {
        case 'accountsChanged':
          applyAccounts(d.data);
          break;
        case 'chainChanged':
          provider._chainId = d.data;
          emit('chainChanged', d.data);
          break;
        case 'connect':
          emit('connect', d.data);
          break;
        case 'disconnect':
          emit('disconnect', d.data);
          break;
        default:
          if (d.event) emit(d.event, d.data);
      }
    }
  });

  Object.defineProperty(window, 'ethereum', {
    value: provider,
    configurable: true,
    writable: false,
  });
  window.dispatchEvent(new Event('ethereum#initialized'));

  // --- EIP-6963 announcement ------------------------------------------------
  const icon =
    'data:image/svg+xml;base64,' +
    btoa(
      '<svg xmlns="http://www.w3.org/2000/svg" width="96" height="96" viewBox="0 0 96 96">' +
        '<rect width="96" height="96" rx="20" fill="#111827"/>' +
        '<text x="48" y="60" font-family="monospace" font-size="42" fill="#34d399" text-anchor="middle">DW</text>' +
        '</svg>',
    );

  const info = {
    uuid:
      (self.crypto && self.crypto.randomUUID && self.crypto.randomUUID()) ||
      'daemon-wallet-' + Date.now(),
    name: 'Daemon Wallet',
    icon,
    rdns: 'com.daemonwallet',
  };

  function announce() {
    window.dispatchEvent(
      new CustomEvent('eip6963:announceProvider', {
        detail: Object.freeze({ info, provider }),
      }),
    );
  }

  window.addEventListener('eip6963:requestProvider', announce);
  announce();
})();
