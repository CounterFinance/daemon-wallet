# Daemon Wallet: Chrome Extension (MV3)

The browser half of a KeePassXC-style Ethereum wallet. Private keys live in a
local native daemon; this extension is a **dumb pipe** between a web DApp and
that daemon over Chrome Native Messaging. Keys never enter the browser.

```
page (window.ethereum)  ⇄  inpage.js  ⇄  content.js  ⇄  background.js  ⇄  native host (daemon)
        MAIN world          MAIN           ISOLATED       service worker    com.daemonwallet.host
```

## Files

| File                  | Role                                                                 |
| --------------------- | -------------------------------------------------------------------- |
| `public/manifest.json`| MV3 manifest: `nativeMessaging` permission, background worker, two content scripts (ISOLATED bridge + MAIN-world provider), popup. |
| `public/background.js`| Owns the single `connectNative('com.daemonwallet.host')` port. Maps pending request ids → callers, routes responses back, broadcasts daemon events to tabs, handles disconnect/reconnect, and falls back to a dev stub when no host is installed. |
| `public/content.js`   | ISOLATED-world bridge. Forwards page requests to the worker and relays responses/events back via `window.postMessage`. |
| `public/inpage.js`    | MAIN-world EIP-1193 provider (`window.ethereum`): `request()`, `on/removeListener`, events (`accountsChanged`, `chainChanged`, `connect`, `disconnect`), plus EIP-6963 announcement. |
| `src/App.tsx`         | Popup: wallet status (locked/unlocked, accounts), a Connect button (`eth_requestAccounts`), and a reminder that approvals happen in the terminal. |

Wire framing (handled by the daemon, not the browser): 4-byte little-endian
length header + UTF-8 JSON. Request `{id, method, params}`; response
`{id, result}` or `{id, error:{code, message}}`.

## Build

```bash
cd packages/extension
npm install
npm run build        # tsc -b && vite build  →  dist/
```

`dist/` contains `manifest.json`, `background.js`, `content.js`, `inpage.js`,
the built popup (`index.html` + `assets/`), and `icons/`. It is loadable as-is.

## Load unpacked in Chrome

1. Open `chrome://extensions`.
2. Enable **Developer mode** (top right).
3. Click **Load unpacked** and select `packages/extension/dist`.
4. Note the extension ID Chrome assigns.

To talk to a real daemon, register the native host manifest for
`com.daemonwallet.host` with `"allowed_origins": ["chrome-extension://<ID>/"]`
(see `EXTENSION_INTEGRATION.md`). Until then, the dev stub below runs.

## Dev stub (no daemon required)

No live daemon exists yet. When the native host is not installed,
`connectNative` opens a port that disconnects immediately; `background.js`
detects this and answers requests from an in-memory echo instead, so the
**page → content → background** pipe is provable end-to-end. Every stub reply
carries `stub: true`, and the popup shows a **DEV STUB** badge, so nothing fake
is mistaken for real wallet data (the stub account is an obvious placeholder).

Try it:

- **Popup:** click the toolbar icon. The DEV STUB badge appears and status
  reads `Locked`. Click **Connect** → `eth_requestAccounts` resolves via the
  stub, status flips to `Unlocked`, and the placeholder account is listed.
- **Any page:** open DevTools console on any site and run:

  ```js
  await window.ethereum.request({ method: 'wallet_status' })
  // { locked: true, accounts: [], hasKeystore: true, stub: true }

  await window.ethereum.request({ method: 'eth_requestAccounts' })
  // ['0xDEAD00000000000000000000000000000000BEEF']

  window.ethereum.on('accountsChanged', console.log)
  ```

  Requests travel page → `inpage.js` → `content.js` → `background.js` and back.
  Watch the worker log in the extension's **service worker** DevTools
  (`chrome://extensions` → Daemon Wallet → *service worker*).

When a real native host is registered the stub stays dormant: live responses
and pushed events flow through unchanged.
