import { useCallback, useEffect, useState } from 'react'
import './App.css'

interface WalletStatus {
  locked: boolean
  accounts: string[]
  activeSessions?: number
  hasKeystore?: boolean
  stub?: boolean
}

interface RpcResponse {
  result?: unknown
  error?: { code: number; message: string }
}

/** Send a single JSON-RPC request to the background worker. */
function rpc<T = unknown>(method: string, params: unknown[] = []): Promise<T> {
  return new Promise((resolve, reject) => {
    const id = `popup-${Date.now()}-${Math.random().toString(16).slice(2)}`
    chrome.runtime.sendMessage(
      { type: 'DW_RPC_REQUEST', payload: { id, method, params } },
      (resp: RpcResponse | undefined) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message))
          return
        }
        if (resp?.error) {
          const err = new Error(resp.error.message)
          ;(err as Error & { code?: number }).code = resp.error.code
          reject(err)
          return
        }
        resolve(resp?.result as T)
      },
    )
  })
}

function shorten(addr: string): string {
  return addr.length > 12 ? `${addr.slice(0, 6)}…${addr.slice(-4)}` : addr
}

function App() {
  const [status, setStatus] = useState<WalletStatus | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const refresh = useCallback(async () => {
    setError(null)
    try {
      const s = await rpc<WalletStatus>('wallet_status')
      setStatus(s)
    } catch (e) {
      setError((e as Error).message)
      setStatus(null)
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  const connect = useCallback(async () => {
    setBusy(true)
    setError(null)
    try {
      await rpc<string[]>('eth_requestAccounts', [{ origin: 'popup' }])
      await refresh()
    } catch (e) {
      const code = (e as Error & { code?: number }).code
      setError(code === 4001 ? 'Request rejected in terminal.' : (e as Error).message)
    } finally {
      setBusy(false)
    }
  }, [refresh])

  const accounts = status?.accounts ?? []
  const connected = accounts.length > 0

  return (
    <main className="dw">
      <header className="dw-head">
        <span className="dw-mark">DW</span>
        <div>
          <h1>Daemon Wallet</h1>
          <p className="dw-sub">Keys stay in your local daemon</p>
        </div>
      </header>

      {status?.stub && (
        <div className="dw-badge dw-badge-warn">
          DEV STUB · native host not connected — responses are placeholders
        </div>
      )}

      <section className="dw-status">
        <div className="dw-row">
          <span>Status</span>
          {status ? (
            <strong className={status.locked ? 'dw-locked' : 'dw-unlocked'}>
              {status.locked ? 'Locked' : 'Unlocked'}
            </strong>
          ) : (
            <strong className="dw-muted">{error ? 'Unavailable' : '…'}</strong>
          )}
        </div>
        <div className="dw-row">
          <span>Accounts</span>
          <strong>{accounts.length}</strong>
        </div>
      </section>

      {connected && (
        <ul className="dw-accounts">
          {accounts.map((a) => (
            <li key={a}>
              <code title={a}>{shorten(a)}</code>
            </li>
          ))}
        </ul>
      )}

      {!connected && (
        <button className="dw-btn" onClick={connect} disabled={busy}>
          {busy ? 'Awaiting approval…' : 'Connect'}
        </button>
      )}

      {error && <p className="dw-error">{error}</p>}

      <p className="dw-note">
        Approvals happen in your terminal, where the daemon runs. Confirm or
        reject each request there — this popup never asks for your password.
      </p>

      <button className="dw-link" onClick={() => void refresh()}>
        Refresh
      </button>
    </main>
  )
}

export default App
