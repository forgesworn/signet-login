/**
 * The login modal — picker → method-specific UI → resolved session.
 *
 * Mirrors signet-verify's <dialog>-based pattern: native focus trap,
 * top-layer placement, theme-aware colours, no third-party UI deps.
 */

import type { LoginOptions, SignetSession, LoginMethod, SignetAuthEvent } from './types.js';
import { DEFAULTS } from './types.js';
import { hasNip07, createNip07Signer, createBunkerSigner, createBunkerSignerFromNostrConnect, buildNostrConnectUri, EphemeralSigner, createLocalSignerFromNsec, type BunkerSignerImpl, type LocalSigner } from './signers.js';
import { isAndroid, startAmberSignIn } from './amber.js';
import { waitForAuthResponse } from 'signet-verify';
import { schnorr } from '@noble/curves/secp256k1';
import { bytesToHex } from '@noble/hashes/utils';
import { startRedirect } from './redirect.js';
import QRCode from 'qrcode';

/**
 * Picker tokens.
 *
 *   - 'nip07'    — browser extension (Bark, Alby, nos2x, …)
 *   - 'redirect' — Sign in with Signet on this device (same-tab navigation)
 *   - 'qr'       — Sign in with Signet on another device (QR + relay delivery)
 *   - 'bunker'   — paste a NIP-46 bunker URI
 *
 * `redirect` and `qr` both terminate at signet-app, but the delivery channel
 * differs: redirect navigates the current tab, qr publishes a gift-wrapped
 * response over the relay so a phone can sign for a desktop session.
 */
type PickerChoice = 'nip07' | 'redirect' | 'qr' | 'bunker' | 'nostrconnect' | 'amber' | 'nsec' | 'cancel';

interface ModalRefs {
  dialog: HTMLDialogElement;
  style: HTMLStyleElement;
}

function escapeHtml(str: string): string {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function generateChallenge(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

function isDarkMode(theme: 'light' | 'dark' | 'auto'): boolean {
  if (theme === 'dark') return true;
  if (theme === 'light') return false;
  return typeof window !== 'undefined' && window.matchMedia('(prefers-color-scheme: dark)').matches;
}

function buildModalShell(theme: 'light' | 'dark' | 'auto'): ModalRefs {
  const style = document.createElement('style');
  style.textContent = '#signet-login-dialog::backdrop{background:rgba(0,0,0,0.7)}';
  document.head.appendChild(style);

  const dark = isDarkMode(theme);
  const bg = dark ? '#1a1a2e' : '#ffffff';
  const fg = dark ? '#e0e0e0' : '#1a1a2e';

  const dialog = document.createElement('dialog');
  dialog.id = 'signet-login-dialog';
  dialog.style.cssText = `border:none;border-radius:16px;padding:32px;max-width:380px;width:90%;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,0.3);background:${bg};color:${fg};font-family:system-ui,-apple-system,sans-serif;`;
  document.body.appendChild(dialog);
  dialog.showModal();

  return { dialog, style };
}

function tearDown(refs: ModalRefs): void {
  try { refs.dialog.close(); } catch { /* ignore */ }
  refs.dialog.remove();
  refs.style.remove();
}

function buttonStyle(dark: boolean, primary = false): string {
  if (primary) {
    return 'background:#2c3e8f;color:white;border:0;padding:12px 16px;border-radius:8px;cursor:pointer;font-size:0.95rem;width:100%;margin-bottom:8px;text-align:left;display:flex;align-items:center;gap:12px;';
  }
  const border = dark ? '#3a3a4e' : '#d0d0d0';
  const fg = dark ? '#e0e0e0' : '#1a1a2e';
  return `background:transparent;color:${fg};border:1px solid ${border};padding:12px 16px;border-radius:8px;cursor:pointer;font-size:0.95rem;width:100%;margin-bottom:8px;text-align:left;display:flex;align-items:center;gap:12px;`;
}

// ── Picker ────────────────────────────────────────────────────────────────────

function renderPicker(refs: ModalRefs, appName: string, theme: 'light' | 'dark' | 'auto'): Promise<PickerChoice> {
  const dark = isDarkMode(theme);
  const muted = dark ? '#888' : '#666';

  const showNip07 = hasNip07();
  const showAmber = isAndroid();

  refs.dialog.innerHTML = `
    <h2 style="margin:0 0 8px;font-size:1.3rem;">Sign in to ${escapeHtml(appName)}</h2>
    <p style="margin:0 0 24px;color:${muted};font-size:0.9rem;">Choose how you want to sign in. Your keys never leave your control.</p>
    <div style="display:flex;flex-direction:column;">
      ${showNip07 ? `<button data-choice="nip07" style="${buttonStyle(dark, true)}"><span style="font-size:1.2rem;">🌐</span><span><strong>Browser extension</strong><br><span style="font-size:0.8rem;opacity:0.8;">bark, Alby, nos2x</span></span></button>` : ''}
      ${showAmber ? `<button data-choice="amber" style="${buttonStyle(dark)}"><span style="font-size:1.2rem;">🤖</span><span><strong>Sign in with Amber</strong><br><span style="font-size:0.8rem;color:${muted};">Android signer (NIP-55)</span></span></button>` : ''}
      <button data-choice="redirect" style="${buttonStyle(dark)}"><span style="font-size:1.2rem;">🪪</span><span><strong>Sign in with Signet</strong><br><span style="font-size:0.8rem;color:${muted};">Open Signet on this device</span></span></button>
      <button data-choice="qr" style="${buttonStyle(dark)}"><span style="font-size:1.2rem;">📱</span><span><strong>Signet on another device</strong><br><span style="font-size:0.8rem;color:${muted};">Scan QR with your phone</span></span></button>
      <button data-choice="bunker" style="${buttonStyle(dark)}"><span style="font-size:1.2rem;">🔑</span><span><strong>Paste bunker URI</strong><br><span style="font-size:0.8rem;color:${muted};">For NIP-46 power users</span></span></button>
      <button data-choice="nostrconnect" style="${buttonStyle(dark)}"><span style="font-size:1.2rem;">📡</span><span><strong>Connect a Nostr signer</strong><br><span style="font-size:0.8rem;color:${muted};">Scan with nsec.app, Amber, Keychat…</span></span></button>
      <button data-choice="nsec" style="${buttonStyle(dark)}"><span style="font-size:1.2rem;">⚠️</span><span><strong>Paste private key</strong><br><span style="font-size:0.8rem;color:${muted};">In-memory only — risky, last resort</span></span></button>
    </div>
    <button data-choice="cancel" style="background:transparent;color:${dark ? '#e0e0e0' : '#1a1a2e'};border:1px solid ${dark ? '#3a3a4e' : '#d0d0d0'};border-radius:8px;padding:12px;cursor:pointer;font-size:0.95rem;width:100%;margin-top:12px;text-align:center;">Cancel</button>
  `;

  return new Promise<PickerChoice>(resolve => {
    refs.dialog.querySelectorAll<HTMLButtonElement>('button[data-choice]').forEach(btn => {
      btn.addEventListener('click', () => {
        const choice = btn.dataset.choice as PickerChoice;
        resolve(choice);
      });
    });
  });
}

// ── NIP-07 wait UI ────────────────────────────────────────────────────────────

interface Nip07Result {
  pubkey: string;
  authEvent: SignetAuthEvent;
}

/**
 * Render a "waiting for browser extension" UI with a working cancel button
 * and an elapsed-time ticker. NIP-07 calls (`getPublicKey`, `signEvent`) have
 * no native cancellation — bark / Alby / nsec.app etc. can take 4-30s to
 * respond on cold start (service worker spawn + relay handshake). Without
 * this UI the user sees the picker frozen and the picker's Cancel button is
 * already-resolved, so they appear stuck. Replacing the picker DOM with a
 * dedicated wait screen restores a real Cancel.
 */
async function runNip07Flow(
  refs: ModalRefs,
  opts: ResolvedOptions,
): Promise<Nip07Result | null> {
  const dark = isDarkMode(opts.theme);
  const muted = dark ? '#888' : '#666';
  const fg = dark ? '#e0e0e0' : '#1a1a2e';

  refs.dialog.innerHTML = `
    <h2 style="margin:0 0 8px;font-size:1.2rem;">Waiting for your extension</h2>
    <p style="margin:0 0 20px;color:${muted};font-size:0.85rem;">Approve the sign-in prompt in bark, Alby, nos2x, or whichever NIP-07 extension you use. Cold-start can take a few seconds.</p>
    <div style="display:flex;align-items:center;justify-content:center;gap:14px;margin:0 0 24px;color:${fg};">
      <div style="width:28px;height:28px;border:3px solid ${dark ? '#3a3a4e' : '#d0d0d0'};border-top-color:#5b6dff;border-radius:50%;animation:signet-login-spin 0.9s linear infinite;"></div>
      <span id="signet-login-nip07-elapsed" style="font-variant-numeric:tabular-nums;font-size:0.95rem;">Connecting…</span>
    </div>
    <div style="display:flex;gap:8px;justify-content:space-between;">
      <button data-action="back" style="${buttonStyle(dark)}width:auto;flex:0 0 auto;padding:8px 16px;">← Back</button>
      <button data-action="cancel" style="${buttonStyle(dark)}width:auto;flex:0 0 auto;padding:8px 16px;">Cancel</button>
    </div>
    <style>@keyframes signet-login-spin{to{transform:rotate(360deg)}}</style>
  `;

  const elapsedEl = refs.dialog.querySelector<HTMLElement>('#signet-login-nip07-elapsed');
  let elapsed = 0;
  const ticker = window.setInterval(() => {
    elapsed += 1;
    if (elapsedEl) elapsedEl.textContent = `Waiting for your signer (${elapsed}s)…`;
  }, 1000);

  // The cancel signal — resolves when the user clicks Cancel/Back. Used to
  // race the NIP-07 calls so the modal can dismiss promptly instead of
  // hanging on the unresolvable extension promise. (We can't truly abort
  // the NIP-07 promise since it has no abort signal, but we stop waiting
  // for it and let it resolve into the void.)
  const cancelled = new Promise<null>(resolve => {
    refs.dialog.querySelector<HTMLButtonElement>('[data-action="back"]')?.addEventListener('click', () => resolve(null));
    refs.dialog.querySelector<HTMLButtonElement>('[data-action="cancel"]')?.addEventListener('click', () => resolve(null));
  });

  try {
    // Race: either the extension comes through, or the user cancels.
    const signer = await Promise.race([createNip07Signer(), cancelled]);
    if (!signer) return null;

    const authEvent = await Promise.race([
      signer.signEvent({
        kind: 21236,
        content: '',
        tags: [
          ['challenge', opts.challenge],
          ['origin', opts.origin],
          ['app', opts.appName],
        ],
      }) as Promise<SignetAuthEvent>,
      cancelled,
    ]);
    if (!authEvent) {
      try { await signer.close(); } catch { /* ignore */ }
      return null;
    }
    return { pubkey: signer.pubkey, authEvent };
  } catch (err) {
    if (elapsedEl) {
      elapsedEl.textContent = `✗ ${err instanceof Error ? err.message : String(err)}`;
      elapsedEl.style.color = '#d04848';
    }
    // Keep the modal up so user sees the error; resolve null after a beat
    // so the cancel button can take them back.
    await Promise.race([new Promise(r => setTimeout(r, 2500)), cancelled]);
    return null;
  } finally {
    window.clearInterval(ticker);
  }
}

// ── Sign in with Signet (cross-device QR + same-device redirect) ──────────────

interface RedirectFlowResult {
  pubkey: string;
  authEvent: SignetAuthEvent;
  displayName?: string;
}

async function runRedirectFlow(
  refs: ModalRefs,
  opts: ResolvedOptions,
): Promise<RedirectFlowResult | null> {
  const dark = isDarkMode(opts.theme);
  const muted = dark ? '#888' : '#666';

  // Generate session keypair for cross-device gift-wrap
  const sessionPrivKey = schnorr.utils.randomPrivateKey();
  const sessionPubkey = bytesToHex(schnorr.getPublicKey(sessionPrivKey));

  const params = new URLSearchParams({
    auth: '1',
    challenge: opts.challenge,
    origin: opts.origin,
    name: opts.appName,
    callback: opts.redirectCallback ?? `${opts.origin}/`,
    t: String(Math.floor(Date.now() / 1000)),
    relay: opts.relayUrl,
    sessionPubkey,
  });
  const authUrl = `${opts.signetAppOrigin}/?${params.toString()}`;

  refs.dialog.innerHTML = `
    <h2 style="margin:0 0 8px;font-size:1.2rem;">Sign in with Signet</h2>
    <p style="margin:0 0 16px;color:${muted};font-size:0.85rem;">Open the link on your phone, or scan the QR if rendered.</p>
    <div style="background:${dark ? '#0f0f1f' : '#f5f5f8'};border-radius:8px;padding:16px;margin-bottom:16px;">
      <canvas id="signet-login-qr" width="200" height="200" style="display:block;width:200px;height:200px;margin:0 auto 12px;background:#ffffff;border-radius:6px;box-sizing:border-box;"></canvas>
      <a href="${escapeHtml(authUrl)}" target="_blank" rel="noopener" style="display:block;color:#5b6dff;font-size:0.75rem;word-break:break-all;text-decoration:none;">${escapeHtml(authUrl.slice(0, 80))}…</a>
    </div>
    <p id="signet-login-status" style="margin:0 0 12px;color:${muted};font-size:0.85rem;">Waiting for approval…</p>
    <div style="display:flex;gap:8px;justify-content:space-between;">
      <button data-action="back" style="${buttonStyle(dark)}width:auto;flex:0 0 auto;padding:8px 16px;">← Back</button>
      <button data-action="cancel" style="${buttonStyle(dark)}width:auto;flex:0 0 auto;padding:8px 16px;">Cancel</button>
    </div>
  `;

  // Render the auth URL into the QR canvas. Async, but the dialog has already
  // surfaced the visible link as a fallback so a slow encode doesn't block UX.
  // M error correction tolerates ~15% damage — comfortable for camera scans.
  const qrCanvas = refs.dialog.querySelector<HTMLCanvasElement>('#signet-login-qr');
  if (qrCanvas) {
    void QRCode.toCanvas(qrCanvas, authUrl, {
      width: 200,
      margin: 1,
      errorCorrectionLevel: 'M',
      color: { dark: '#0a0418', light: '#ffffff' },
    }).catch(() => {
      // Encoding failure (URL too long for QR L-Q levels, canvas inaccessible)
      // — the visible link below the canvas still gets the user across.
    });
  }

  return new Promise<RedirectFlowResult | null>(resolve => {
    let settled = false;
    const settle = (v: RedirectFlowResult | null): void => {
      if (settled) return;
      settled = true;
      resolve(v);
    };

    refs.dialog.querySelector<HTMLButtonElement>('[data-action="back"]')?.addEventListener('click', () => {
      settle(null);
    });
    refs.dialog.querySelector<HTMLButtonElement>('[data-action="cancel"]')?.addEventListener('click', () => {
      settle(null);
    });

    waitForAuthResponse({
      requestId: opts.challenge,
      relayUrl: opts.relayUrl,
      sessionPrivKey,
      expectedOrigin: opts.origin,
      timeout: opts.timeout,
    }).then(result => {
      const authEvent: SignetAuthEvent = {
        id: result.authEvent.id,
        pubkey: result.authEvent.pubkey,
        kind: 21236,
        created_at: result.authEvent.created_at,
        tags: result.authEvent.tags,
        content: result.authEvent.content,
        sig: result.authEvent.sig,
      };
      const out: RedirectFlowResult = { pubkey: result.pubkey, authEvent };
      if (result.displayName) out.displayName = result.displayName;
      settle(out);
    }).catch(err => {
      const status = refs.dialog.querySelector<HTMLElement>('#signet-login-status');
      if (status) {
        status.textContent = `✗ ${err instanceof Error ? err.message : String(err)}`;
        status.style.color = '#d04848';
      }
      // Don't auto-settle on error — let the user choose to go back/cancel.
    });
  });
}

// ── Paste bunker URI ──────────────────────────────────────────────────────────

async function runBunkerFlow(refs: ModalRefs, opts: ResolvedOptions): Promise<BunkerSignerImpl | null> {
  const dark = isDarkMode(opts.theme);
  const muted = dark ? '#888' : '#666';
  const inputBg = dark ? '#0f0f1f' : '#f5f5f8';
  const inputFg = dark ? '#e0e0e0' : '#1a1a2e';

  refs.dialog.innerHTML = `
    <h2 style="margin:0 0 8px;font-size:1.2rem;">Paste bunker URI</h2>
    <p style="margin:0 0 16px;color:${muted};font-size:0.85rem;">Connect to your NIP-46 bunker (Heartwood, nsecBunker, or any compatible signer).</p>
    <textarea id="signet-login-bunker-input" placeholder="bunker://..." rows="3" style="width:100%;background:${inputBg};color:${inputFg};border:1px solid ${dark ? '#3a3a4e' : '#d0d0d0'};border-radius:8px;padding:10px;font-size:0.85rem;font-family:ui-monospace,monospace;box-sizing:border-box;resize:vertical;margin-bottom:12px;"></textarea>
    <p id="signet-login-bunker-status" style="margin:0 0 12px;color:${muted};font-size:0.85rem;min-height:1.2em;"></p>
    <div style="display:flex;gap:8px;justify-content:space-between;">
      <button data-action="back" style="${buttonStyle(dark)}width:auto;flex:0 0 auto;padding:8px 16px;">← Back</button>
      <button data-action="connect" style="${buttonStyle(dark, true)}width:auto;flex:1;padding:8px 16px;text-align:center;">Connect</button>
    </div>
  `;

  return new Promise<BunkerSignerImpl | null>(resolve => {
    let settled = false;
    const settle = (v: BunkerSignerImpl | null): void => {
      if (settled) return;
      settled = true;
      resolve(v);
    };

    const input = refs.dialog.querySelector<HTMLTextAreaElement>('#signet-login-bunker-input');
    const status = refs.dialog.querySelector<HTMLElement>('#signet-login-bunker-status');
    const connectBtn = refs.dialog.querySelector<HTMLButtonElement>('[data-action="connect"]');

    refs.dialog.querySelector<HTMLButtonElement>('[data-action="back"]')?.addEventListener('click', () => {
      settle(null);
    });

    connectBtn?.addEventListener('click', async () => {
      const uri = input?.value.trim() ?? '';
      if (!uri) {
        if (status) status.textContent = 'Please paste a bunker URI.';
        return;
      }
      if (status) {
        status.textContent = 'Connecting…';
        status.style.color = '';
      }
      connectBtn.disabled = true;
      try {
        const signer = await createBunkerSigner({ uri });
        settle(signer);
      } catch (err) {
        if (status) {
          status.textContent = `✗ ${err instanceof Error ? err.message : String(err)}`;
          status.style.color = '#d04848';
        }
        connectBtn.disabled = false;
      }
    });
  });
}

// ── Connect a Nostr signer (NostrConnect URI, app-initiated NIP-46) ──────────

/**
 * App-initiated NIP-46. Mirror image of bunker URI: instead of the user
 * pasting a bunker URI from their signer, we generate a `nostrconnect://`
 * URI and the user scans it with their signer (nsec.app, Amber, Keychat…).
 * The signer connects to our chosen relay and signs ad-hoc from there.
 */
async function runNostrConnectFlow(refs: ModalRefs, opts: ResolvedOptions): Promise<BunkerSignerImpl | null> {
  const dark = isDarkMode(opts.theme);
  const muted = dark ? '#888' : '#666';

  const sk = schnorr.utils.randomPrivateKey();
  const clientPubkey = bytesToHex(schnorr.getPublicKey(sk));
  const secret = bytesToHex(schnorr.utils.randomPrivateKey()).slice(0, 32);

  const uri = buildNostrConnectUri({
    clientPubkeyHex: clientPubkey,
    relayUrl: opts.relayUrl,
    secret,
    perms: ['sign_event', 'nip44_encrypt', 'nip44_decrypt'],
    appName: opts.appName,
    appUrl: opts.origin,
  });

  refs.dialog.innerHTML = `
    <h2 style="margin:0 0 8px;font-size:1.2rem;">Connect a Nostr signer</h2>
    <p style="margin:0 0 16px;color:${muted};font-size:0.85rem;">Scan or paste this into your signer (nsec.app, Amber, Keychat…). The connection happens over your relay.</p>
    <div style="background:${dark ? '#0f0f1f' : '#f5f5f8'};border-radius:8px;padding:16px;margin-bottom:16px;">
      <canvas id="signet-login-nc-qr" width="200" height="200" style="display:block;width:200px;height:200px;margin:0 auto 12px;background:#ffffff;border-radius:6px;box-sizing:border-box;"></canvas>
      <button data-action="copy" style="${buttonStyle(dark)}width:auto;font-size:0.75rem;padding:6px 10px;margin:0 auto;display:block;">Copy URI</button>
    </div>
    <p id="signet-login-nc-status" style="margin:0 0 12px;color:${muted};font-size:0.85rem;">Waiting for signer to connect…</p>
    <div style="display:flex;gap:8px;justify-content:space-between;">
      <button data-action="back" style="${buttonStyle(dark)}width:auto;flex:0 0 auto;padding:8px 16px;">← Back</button>
      <button data-action="cancel" style="${buttonStyle(dark)}width:auto;flex:0 0 auto;padding:8px 16px;">Cancel</button>
    </div>
  `;

  const qrCanvas = refs.dialog.querySelector<HTMLCanvasElement>('#signet-login-nc-qr');
  if (qrCanvas) {
    void QRCode.toCanvas(qrCanvas, uri, {
      width: 200, margin: 1, errorCorrectionLevel: 'M',
      color: { dark: '#0a0418', light: '#ffffff' },
    }).catch(() => { /* link/copy fallback below */ });
  }

  const copyBtn = refs.dialog.querySelector<HTMLButtonElement>('[data-action="copy"]');
  copyBtn?.addEventListener('click', () => {
    void navigator.clipboard?.writeText(uri).then(() => {
      copyBtn.textContent = 'Copied ✓';
      window.setTimeout(() => { copyBtn.textContent = 'Copy URI'; }, 1500);
    });
  });

  const ac = new AbortController();
  const status = refs.dialog.querySelector<HTMLElement>('#signet-login-nc-status');

  return new Promise<BunkerSignerImpl | null>(resolve => {
    let settled = false;
    const settle = (v: BunkerSignerImpl | null): void => {
      if (settled) return;
      settled = true;
      resolve(v);
    };

    refs.dialog.querySelector<HTMLButtonElement>('[data-action="back"]')?.addEventListener('click', () => {
      ac.abort();
      settle(null);
    });
    refs.dialog.querySelector<HTMLButtonElement>('[data-action="cancel"]')?.addEventListener('click', () => {
      ac.abort();
      settle(null);
    });

    createBunkerSignerFromNostrConnect({ uri, clientSecretKey: sk, abortSignal: ac.signal })
      .then(signer => settle(signer))
      .catch(err => {
        if (settled) return;  // already cancelled
        if (status) {
          status.textContent = `✗ ${err instanceof Error ? err.message : String(err)}`;
          status.style.color = '#d04848';
        }
        // Don't auto-settle on error — user clicks Back/Cancel.
      });
  });
}

// ── Paste nsec (in-memory only) ───────────────────────────────────────────────

async function runNsecFlow(refs: ModalRefs, opts: ResolvedOptions): Promise<LocalSigner | null> {
  const dark = isDarkMode(opts.theme);
  const muted = dark ? '#888' : '#666';
  const inputBg = dark ? '#0f0f1f' : '#f5f5f8';
  const inputFg = dark ? '#e0e0e0' : '#1a1a2e';
  void opts;

  refs.dialog.innerHTML = `
    <h2 style="margin:0 0 8px;font-size:1.2rem;">Paste private key</h2>
    <p style="margin:0 0 12px;color:#d04848;font-size:0.85rem;font-weight:600;">⚠️ Last-resort method — only paste keys you can afford to lose.</p>
    <p style="margin:0 0 16px;color:${muted};font-size:0.8rem;line-height:1.4;">Held in memory for this session only. Cleared on page reload. Prefer a browser extension or bunker URI for any key with real value.</p>
    <textarea id="signet-login-nsec-input" placeholder="nsec1..." rows="2" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" style="width:100%;background:${inputBg};color:${inputFg};border:1px solid ${dark ? '#3a3a4e' : '#d0d0d0'};border-radius:8px;padding:10px;font-size:0.85rem;font-family:ui-monospace,monospace;box-sizing:border-box;resize:vertical;margin-bottom:12px;-webkit-text-security:disc;text-security:disc;"></textarea>
    <p id="signet-login-nsec-status" style="margin:0 0 12px;color:${muted};font-size:0.85rem;min-height:1.2em;"></p>
    <div style="display:flex;gap:8px;justify-content:space-between;">
      <button data-action="back" style="${buttonStyle(dark)}width:auto;flex:0 0 auto;padding:8px 16px;">← Back</button>
      <button data-action="connect" style="${buttonStyle(dark, true)}width:auto;flex:1;padding:8px 16px;text-align:center;">Sign in</button>
    </div>
  `;

  return new Promise<LocalSigner | null>(resolve => {
    let settled = false;
    const settle = (v: LocalSigner | null): void => {
      if (settled) return;
      settled = true;
      resolve(v);
    };

    const input = refs.dialog.querySelector<HTMLTextAreaElement>('#signet-login-nsec-input');
    const status = refs.dialog.querySelector<HTMLElement>('#signet-login-nsec-status');
    const connectBtn = refs.dialog.querySelector<HTMLButtonElement>('[data-action="connect"]');

    refs.dialog.querySelector<HTMLButtonElement>('[data-action="back"]')?.addEventListener('click', () => {
      if (input) input.value = '';
      settle(null);
    });

    connectBtn?.addEventListener('click', () => {
      const value = input?.value ?? '';
      if (!value.trim()) {
        if (status) status.textContent = 'Please paste an nsec.';
        return;
      }
      try {
        const signer = createLocalSignerFromNsec(value);
        // Wipe the textarea ASAP — the key is now in the signer.
        if (input) input.value = '';
        settle(signer);
      } catch (err) {
        if (status) {
          status.textContent = `✗ ${err instanceof Error ? err.message : String(err)}`;
          status.style.color = '#d04848';
        }
      }
    });
  });
}

// ── Orchestrator ──────────────────────────────────────────────────────────────

interface ResolvedOptions {
  appName: string;
  challenge: string;
  origin: string;
  preferredMethod?: LoginMethod;
  relayUrl: string;
  theme: 'light' | 'dark' | 'auto';
  timeout: number;
  signetAppOrigin: string;
  redirectCallback?: string;
}

function resolveOptions(opts: LoginOptions): ResolvedOptions {
  const challenge = opts.challenge ?? generateChallenge();
  if (!/^[0-9a-f]{64}$/i.test(challenge)) throw new Error('challenge-must-be-64-hex');
  const origin = typeof window !== 'undefined' ? window.location.origin : 'http://localhost';
  const timeout = Math.max(5_000, Math.min(opts.timeout ?? DEFAULTS.timeout, 600_000));
  const result: ResolvedOptions = {
    appName: opts.appName,
    challenge: challenge.toLowerCase(),
    origin,
    relayUrl: opts.relayUrl ?? DEFAULTS.relayUrl,
    theme: opts.theme ?? DEFAULTS.theme,
    timeout,
    signetAppOrigin: opts.signetAppOrigin ?? DEFAULTS.signetAppOrigin,
  };
  if (opts.preferredMethod !== undefined) result.preferredMethod = opts.preferredMethod;
  if (opts.redirectCallback !== undefined) result.redirectCallback = opts.redirectCallback;
  return result;
}

/**
 * Entry point — show the modal, route to the chosen method, return a session.
 *
 * Returns null when the user cancels or the flow times out.
 */
export async function showLoginModal(opts: LoginOptions): Promise<SignetSession | null> {
  if (!opts.appName || opts.appName.length === 0) throw new Error('appName-required');
  if (opts.appName.length > 64) throw new Error('appName-too-long');
  const resolved = resolveOptions(opts);
  const refs = buildModalShell(resolved.theme);

  // Escape and the Android / OS back button fire the dialog's native
  // `cancel` event. Unhandled, the dialog closes visually but the
  // in-flight flow promise never resolves — login() hangs forever and
  // the caller's UI is left stuck behind a dead modal. Racing every
  // flow await against this lets the modal exit cleanly.
  let userAborted = false;
  const aborted = new Promise<null>((resolve) => {
    refs.dialog.addEventListener('cancel', () => { userAborted = true; resolve(null); });
  });

  try {
    while (true) {
      const choice = resolved.preferredMethod
        ? (resolved.preferredMethod as PickerChoice)
        : await Promise.race([renderPicker(refs, resolved.appName, resolved.theme), aborted]);

      if (userAborted) return null;
      if (choice === null || choice === 'cancel') return null;

      if (choice === 'nip07') {
        const result = await Promise.race([runNip07Flow(refs, resolved), aborted]);
        if (userAborted) return null;
        if (!result) {
          if (resolved.preferredMethod) return null;
          continue;  // back to picker
        }
        // Re-create the signer object — runNip07Flow created one internally
        // but we need a usable handle to return. The extension is now warm
        // so this call resolves immediately.
        const signer = await createNip07Signer();
        return {
          pubkey: result.pubkey,
          method: 'nip07',
          signer,
          authEvent: result.authEvent,
        };
      }

      if (choice === 'redirect') {
        // Same-tab navigation. Reuses the same pending-state and callback
        // machinery as `Signet.login({ mode: 'redirect' })`, so this picker
        // path lands the user on signet-app and the consumer's next page
        // load picks up the round-trip via `Signet.handleRedirectCallback`.
        // The promise from `startRedirect` never resolves — the page is gone
        // before the await completes — so the dialog teardown in the finally
        // block is also a no-op for this branch.
        await startRedirect({
          appName: resolved.appName,
          challenge: resolved.challenge,
          origin: resolved.origin,
          signetAppOrigin: resolved.signetAppOrigin,
          ...(resolved.redirectCallback !== undefined ? { redirectCallback: resolved.redirectCallback } : {}),
        });
        return null;  // unreachable
      }

      if (choice === 'amber') {
        // Same-tab navigation to a `nostrsigner:` URL. Android dispatches
        // it to Amber; the page comes back via callbackUrl with the signed
        // event in `?event=`. Picked up on next boot by handleRedirectCallback.
        await startAmberSignIn({
          appName: resolved.appName,
          challenge: resolved.challenge,
          origin: resolved.origin,
          ...(resolved.redirectCallback !== undefined ? { redirectCallback: resolved.redirectCallback } : {}),
        });
        return null;  // unreachable
      }

      if (choice === 'qr') {
        const result = await Promise.race([runRedirectFlow(refs, resolved), aborted]);
        if (userAborted) return null;
        if (!result) {
          if (resolved.preferredMethod) return null;
          continue;
        }
        const ephemeral = new EphemeralSigner(result.pubkey, result.authEvent);
        const session: SignetSession = {
          pubkey: result.pubkey,
          method: 'redirect',
          signer: ephemeral,
          authEvent: result.authEvent,
        };
        if (result.displayName) session.displayName = result.displayName;
        return session;
      }

      if (choice === 'bunker') {
        const signer = await Promise.race([runBunkerFlow(refs, resolved), aborted]);
        if (userAborted) return null;
        if (!signer) {
          if (resolved.preferredMethod) return null;
          continue;
        }

        // Sign a kind-21236 auth event so we have a uniform proof shape
        const authEvent = await signer.signEvent({
          kind: 21236,
          content: '',
          tags: [
            ['challenge', resolved.challenge],
            ['origin', resolved.origin],
            ['app', resolved.appName],
          ],
        }) as SignetAuthEvent;

        return {
          pubkey: signer.pubkey,
          method: 'bunker',
          signer,
          authEvent,
        };
      }

      if (choice === 'nostrconnect') {
        const signer = await Promise.race([runNostrConnectFlow(refs, resolved), aborted]);
        if (userAborted) return null;
        if (!signer) {
          if (resolved.preferredMethod) return null;
          continue;
        }

        const authEvent = await signer.signEvent({
          kind: 21236,
          content: '',
          tags: [
            ['challenge', resolved.challenge],
            ['origin', resolved.origin],
            ['app', resolved.appName],
          ],
        }) as SignetAuthEvent;

        // Surfaces as 'bunker' since the session shape is identical to a
        // bunker URI session — same signer, same persistence path, same
        // capabilities. The picker choice routed us here; from this point
        // on the rest of the SDK doesn't care about the initiation direction.
        return {
          pubkey: signer.pubkey,
          method: 'bunker',
          signer,
          authEvent,
        };
      }

      if (choice === 'nsec') {
        const signer = await Promise.race([runNsecFlow(refs, resolved), aborted]);
        if (userAborted) return null;
        if (!signer) {
          if (resolved.preferredMethod) return null;
          continue;
        }

        const authEvent = await signer.signEvent({
          kind: 21236,
          content: '',
          tags: [
            ['challenge', resolved.challenge],
            ['origin', resolved.origin],
            ['app', resolved.appName],
          ],
        }) as SignetAuthEvent;

        return {
          pubkey: signer.pubkey,
          method: 'nsec',
          signer,
          authEvent,
        };
      }

      // Unknown choice — restart picker
    }
  } finally {
    tearDown(refs);
  }
}
