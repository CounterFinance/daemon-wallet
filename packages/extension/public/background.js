/*
 * Daemon Wallet - background service worker (MV3)
 *
 * Role: a DUMB PIPE. It owns the single chrome.runtime.connectNative port to
 * the native host, forwards DApp/popup requests to it, and routes responses
 * (matched by request id) and pushed events back to the right place.
 *
 * Plain classic script (no imports) so it needs no bundling and no
 * "type":"module" in the manifest.
 */

const NATIVE_HOST = 'com.daemonwallet.host';

/** The live native-messaging port, or null when disconnected. */
let port = null;
/** True only while `port` is believed usable. */
let portReady = false;

/** id -> { cb, req }  pending requests awaiting a native response. */
const pending = new Map();
/** tabIds whose content script has talked to us (event broadcast targets). */
const connectedTabs = new Set();

/*
 * Dev stub.
 *
 * No live daemon exists yet. When the native host is not installed, the port
 * opened by connectNative disconnects immediately with a lastError. We detect
 * that and answer requests from this in-memory echo instead, so the
 * page -> content -> background pipe can be proven end-to-end. Every stub
 * reply carries `stub: true` so nothing fake is mistaken for real wallet data.
 */
const stub = {
  active: false,
  locked: true,
  // Obvious placeholder address - never a real account.
  accounts: ['0xDEAD00000000000000000000000000000000BEEF'],
  chainId: '0x1',
};

function log(...args) {
  // eslint-ignore - plain console for a service worker
  console.log('[daemon-wallet:bg]', ...args);
}

function connect() {
  if (port) return;
  try {
    port = chrome.runtime.connectNative(NATIVE_HOST);
    portReady = true;
    stub.active = false;
    log('connected to native host', NATIVE_HOST);
  } catch (e) {
    port = null;
    portReady = false;
    enableStub('connectNative threw: ' + (e && e.message));
    return;
  }

  port.onMessage.addListener(onNativeMessage);

  port.onDisconnect.addListener(() => {
    const err = chrome.runtime.lastError;
    port = null;
    portReady = false;
    enableStub(err && err.message ? err.message : 'native host disconnected');
    // Never leave a caller hanging: flush anything in flight via the stub.
    const inflight = [...pending.entries()];
    pending.clear();
    for (const [, { cb, req }] of inflight) stubRespond(req, cb);
  });
}

function enableStub(reason) {
  if (!stub.active) log('native host unavailable, using dev stub:', reason);
  stub.active = true;
}

function onNativeMessage(message) {
  // A response carries the id of a request we are waiting on.
  if (message && message.id !== undefined && pending.has(message.id)) {
    const { cb } = pending.get(message.id);
    pending.delete(message.id);
    cb(message); // { id, result } | { id, error: { code, message } }
    return;
  }
  // Anything else is a pushed event (accountsChanged, chainChanged, ...).
  broadcastEvent(message);
}

function broadcastEvent(payload) {
  for (const tabId of connectedTabs) {
    chrome.tabs.sendMessage(tabId, { type: 'DW_EVENT', payload }, () => {
      // Swallow "no receiver" errors for tabs without our content script.
      void chrome.runtime.lastError;
    });
  }
}

function handleRpc(req, sendResponse) {
  if (!port) connect();

  if (port && portReady && !stub.active) {
    pending.set(req.id, { cb: sendResponse, req });
    try {
      port.postMessage(req);
    } catch (e) {
      pending.delete(req.id);
      enableStub('postMessage failed: ' + (e && e.message));
      stubRespond(req, sendResponse);
    }
    return;
  }

  stubRespond(req, sendResponse);
}

function stubRespond(req, cb) {
  stub.active = true;
  const { id, method, params } = req;
  const ok = (result) => cb({ id, result });

  switch (method) {
    case 'wallet_status':
      return ok({
        locked: stub.locked,
        accounts: stub.locked ? [] : stub.accounts,
        activeSessions: stub.locked ? 0 : 1,
        hasKeystore: true,
        stub: true,
      });

    case 'wallet_unlock':
      stub.locked = false;
      broadcastEvent({ event: 'accountsChanged', data: stub.accounts });
      return ok({ success: true, accounts: stub.accounts, stub: true });

    case 'eth_requestAccounts':
      stub.locked = false;
      broadcastEvent({ event: 'connect', data: { chainId: stub.chainId } });
      broadcastEvent({ event: 'accountsChanged', data: stub.accounts });
      return ok(stub.accounts);

    case 'eth_accounts':
      return ok(stub.locked ? [] : stub.accounts);

    case 'eth_chainId':
      return ok(stub.chainId);

    case 'personal_sign':
    case 'eth_sign':
      return ok('0x' + 'ab'.repeat(32)); // obvious placeholder signature

    case 'eth_signTypedData':
    case 'eth_signTypedData_v4':
      return ok('0x' + 'cd'.repeat(32));

    case 'eth_sendTransaction':
      return ok('0x' + 'ef'.repeat(32)); // obvious placeholder tx hash

    default:
      // Echo anything else so the pipe is still observably working.
      return ok({ echo: { method, params }, stub: true });
  }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || typeof msg !== 'object') return;

  if (msg.type === 'DW_RPC_REQUEST' && msg.payload) {
    if (sender.tab && sender.tab.id !== undefined) connectedTabs.add(sender.tab.id);
    // Stamp the TRUSTED requesting origin from the content-script sender. The page
    // cannot forge this; the daemon shows it in its approval prompt and ignores any
    // `origin` a hostile page tries to smuggle inside `params`.
    let trustedOrigin = sender.origin || '';
    if (!trustedOrigin && sender.tab && sender.tab.url) {
      try {
        trustedOrigin = new URL(sender.tab.url).origin;
      } catch (_) {
        trustedOrigin = '';
      }
    }
    const payload = { ...msg.payload, origin: trustedOrigin };
    handleRpc(payload, sendResponse);
    return true; // keep the channel open for the async reply
  }

  if (msg.type === 'DW_STATUS') {
    sendResponse({ nativeConnected: portReady && !stub.active, stub: stub.active });
    return true;
  }
});

chrome.tabs.onRemoved.addListener((tabId) => connectedTabs.delete(tabId));

// Try to connect eagerly; lazy reconnect also happens on each request.
connect();
