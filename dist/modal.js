/**
 * The login modal — picker → method-specific UI → resolved session.
 *
 * Mirrors signet-verify's <dialog>-based pattern: native focus trap,
 * top-layer placement, theme-aware colours, no third-party UI deps.
 */
import { DEFAULTS } from './types.js';
import { hasNip07, createNip07Signer, createBunkerSigner, createBunkerSignerFromNostrConnect, buildNostrConnectUri, EphemeralSigner, createLocalSignerFromNsec } from './signers.js';
import { isAndroid, startAmberSignIn } from './amber.js';
import { isMobile } from './platform.js';
import { loadOrCreatePersistentClientSkFromStorage } from './storage.js';
import { waitForAuthResponse } from 'signet-verify';
import { schnorr } from '@noble/curves/secp256k1';
import { bytesToHex } from '@noble/hashes/utils';
import QRCode from 'qrcode';
import jsQR from 'jsqr';
const QR_BUNKER_CONNECT_TIMEOUT_MS = 8000;
const DEFAULT_PICKER_METHODS = ['nip07', 'amber', 'local-signet', 'remote-signet', 'bunker', 'nostrconnect', 'nsec'];
const ALL_PICKER_METHODS = [...DEFAULT_PICKER_METHODS, 'redirect', 'qr'];
const DEFAULT_ADVANCED_METHODS = ['bunker', 'nostrconnect', 'nsec'];
const DEFAULT_NOSTR_CONNECT_PERMS = ['sign_event', 'nip44_encrypt', 'nip44_decrypt'];
const LARGE_QR_SIZE_PX = 360;
function escapeHtml(str) {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
function generateChallenge() {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}
function keepQrCanvasResponsive(canvas, sizePx = LARGE_QR_SIZE_PX) {
    // qrcode mutates canvas.style.width/height after rendering. Reset height so
    // max-width scaling on narrow phones preserves the square QR aspect ratio.
    canvas.style.width = `${sizePx}px`;
    canvas.style.height = 'auto';
    canvas.style.maxWidth = '100%';
}
function isDarkMode(theme) {
    if (theme === 'dark')
        return true;
    if (theme === 'light')
        return false;
    return typeof window !== 'undefined' && window.matchMedia('(prefers-color-scheme: dark)').matches;
}
function buildModalShell(theme) {
    const style = document.createElement('style');
    style.textContent = '#signet-login-dialog::backdrop{background:rgba(0,0,0,0.7)}';
    document.head.appendChild(style);
    const dark = isDarkMode(theme);
    const bg = dark ? '#1a1a2e' : '#ffffff';
    const fg = dark ? '#e0e0e0' : '#1a1a2e';
    const dialog = document.createElement('dialog');
    dialog.id = 'signet-login-dialog';
    dialog.style.cssText = `border:none;border-radius:16px;padding:32px;max-width:460px;width:90%;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,0.3);background:${bg};color:${fg};font-family:system-ui,-apple-system,sans-serif;`;
    document.body.appendChild(dialog);
    dialog.showModal();
    // Gamepad navigation. A booth/kiosk drives this modal with a gamepad, whose
    // host game dispatches *synthetic* Arrow / Enter / Escape KeyboardEvents on
    // `window` (isTrusted=false). Native <dialog> only moves focus with Tab, and
    // synthetic Enter/Escape don't trigger native button activation or the
    // dialog's cancel — so bridge them here. Real keyboard events (isTrusted)
    // keep their native behaviour; we only fully drive the synthetic ones. Works
    // across every screen because it queries the live buttons each keypress.
    const visibleButtons = () => Array.from(dialog.querySelectorAll('button'))
        .filter((b) => {
        if (b.disabled || !b.isConnected)
            return false;
        const css = window.getComputedStyle(b);
        return css.display !== 'none' && css.visibility !== 'hidden';
    });
    const focusedButton = () => document.activeElement instanceof HTMLButtonElement && dialog.contains(document.activeElement)
        ? document.activeElement
        : null;
    // Tracked cursor. We click THIS index on Enter rather than
    // document.activeElement, because a host page's own menu-nav (still mounted
    // behind the dialog) can clear/move DOM focus between keypresses — which made
    // "A = select the highlighted item" click the wrong (first) button. Tracking
    // the index ourselves makes selection reliable regardless of the host.
    let selIndex = 0;
    const showSel = () => {
        const btns = visibleButtons();
        if (btns.length === 0)
            return;
        selIndex = Math.min(Math.max(selIndex, 0), btns.length - 1);
        btns[selIndex].focus();
    };
    const keyNav = (e) => {
        if (!dialog.isConnected || !dialog.open)
            return;
        const tgt = e.target;
        if (tgt && (tgt.tagName === 'INPUT' || tgt.tagName === 'TEXTAREA') && e.isTrusted)
            return; // real typing owns its keys
        const btns = visibleButtons();
        if (btns.length === 0)
            return;
        const key = e.key || e.code;
        const code = e.code || e.key;
        const dir = key === 'ArrowDown' || code === 'ArrowDown' || key === 'ArrowRight' || code === 'ArrowRight' ? 1
            : key === 'ArrowUp' || code === 'ArrowUp' || key === 'ArrowLeft' || code === 'ArrowLeft' ? -1 : 0;
        if (dir) {
            // The modal owns nav while open — stop the host page's listeners from
            // also grabbing the key and stealing focus.
            e.preventDefault();
            e.stopImmediatePropagation();
            // Re-sync to live DOM focus if the host moved it, else step our index.
            const fb = focusedButton();
            const fi = fb ? btns.indexOf(fb) : -1;
            selIndex = ((fi >= 0 ? fi : selIndex) + dir + btns.length) % btns.length;
            btns[selIndex].focus();
            return;
        }
        // Real keyboard (isTrusted): let native Enter/Escape stand AND keep
        // propagating so the focused button's native activation fires. We only
        // fully drive the SYNTHETIC events a gamepad host dispatches on window.
        if (e.isTrusted)
            return;
        if (e.key === 'Enter' || e.key === ' ' || e.code === 'Space' || e.code === 'Enter') {
            e.preventDefault();
            e.stopImmediatePropagation();
            btns[Math.min(Math.max(selIndex, 0), btns.length - 1)].click(); // tracked cursor, not activeElement
        }
        else if (e.key === 'Escape' || e.code === 'Escape') {
            e.preventDefault();
            e.stopImmediatePropagation();
            // Prefer Back (sub-screen → picker); fall back to Cancel.
            (dialog.querySelector('[data-action="back"]')
                ?? dialog.querySelector('[data-action="cancel"],[data-choice="cancel"]'))?.click();
        }
    };
    // Capture phase: run BEFORE the host page's bubble-phase window keydown
    // handlers, so stopImmediatePropagation above actually pre-empts them.
    window.addEventListener('keydown', keyNav, true);
    // Reset the cursor to the first button when a new SCREEN swaps in. childList
    // (no subtree) so frequent status-text updates inside a screen don't reset it.
    const mo = new MutationObserver(() => { selIndex = 0; showSel(); });
    mo.observe(dialog, { childList: true });
    showSel();
    return {
        dialog,
        style,
        cleanupNav: () => { window.removeEventListener('keydown', keyNav, true); mo.disconnect(); },
    };
}
function tearDown(refs) {
    refs.cleanupNav?.();
    try {
        refs.dialog.close();
    }
    catch { /* ignore */ }
    refs.dialog.remove();
    refs.style.remove();
}
function buttonStyle(dark, primary = false) {
    if (primary) {
        return 'background:#2c3e8f;color:white;border:0;padding:12px 16px;border-radius:8px;cursor:pointer;font-size:0.95rem;width:100%;margin-bottom:8px;text-align:left;display:flex;align-items:center;gap:12px;';
    }
    const border = dark ? '#3a3a4e' : '#d0d0d0';
    const fg = dark ? '#e0e0e0' : '#1a1a2e';
    return `background:transparent;color:${fg};border:1px solid ${border};padding:12px 16px;border-radius:8px;cursor:pointer;font-size:0.95rem;width:100%;margin-bottom:8px;text-align:left;display:flex;align-items:center;gap:12px;`;
}
function canUseCameraQrScanner() {
    return typeof navigator !== 'undefined'
        && !!navigator.mediaDevices
        && typeof navigator.mediaDevices.getUserMedia === 'function'
        && typeof document !== 'undefined';
}
function isAcceptedPairingQr(value, acceptedPrefixes) {
    const lower = value.trim().toLowerCase();
    return acceptedPrefixes.some(prefix => lower.startsWith(prefix));
}
async function startCameraQrScanner(input) {
    const { container, status, acceptedPrefixes, onValue } = input;
    if (!canUseCameraQrScanner())
        throw new Error('camera-unavailable');
    let stopped = false;
    let frame = 0;
    let stream = null;
    const video = document.createElement('video');
    const canvas = document.createElement('canvas');
    const stopBtn = document.createElement('button');
    video.muted = true;
    video.playsInline = true;
    video.style.cssText = 'display:block;width:100%;max-height:240px;object-fit:cover;border-radius:8px;background:#000;margin:0 0 8px;';
    canvas.style.display = 'none';
    stopBtn.type = 'button';
    stopBtn.dataset.action = 'stop-scan';
    stopBtn.textContent = 'Stop scan';
    stopBtn.style.cssText = 'display:block;margin:0 auto 8px;background:transparent;border:1px solid currentColor;border-radius:8px;padding:8px 12px;cursor:pointer;color:inherit;';
    const stop = () => {
        if (stopped)
            return;
        stopped = true;
        if (frame)
            cancelAnimationFrame(frame);
        if (stream) {
            for (const track of stream.getTracks())
                track.stop();
        }
        container.hidden = true;
        container.replaceChildren();
    };
    stopBtn.addEventListener('click', () => {
        stop();
        if (status) {
            status.textContent = 'QR scan stopped.';
            status.style.color = '';
        }
    });
    container.hidden = false;
    container.replaceChildren(video, canvas, stopBtn);
    if (status) {
        status.textContent = 'Point your camera at a QR code...';
        status.style.color = '';
    }
    try {
        stream = await navigator.mediaDevices.getUserMedia({
            audio: false,
            video: { facingMode: { ideal: 'environment' } },
        });
        video.srcObject = stream;
        await video.play();
    }
    catch (err) {
        stop();
        throw err;
    }
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    if (!ctx) {
        stop();
        throw new Error('canvas-unavailable');
    }
    const tick = () => {
        if (stopped)
            return;
        if (video.readyState >= HTMLMediaElement.HAVE_CURRENT_DATA && video.videoWidth > 0 && video.videoHeight > 0) {
            canvas.width = video.videoWidth;
            canvas.height = video.videoHeight;
            ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
            const image = ctx.getImageData(0, 0, canvas.width, canvas.height);
            const code = jsQR(image.data, image.width, image.height, { inversionAttempts: 'attemptBoth' });
            const scanned = code?.data?.trim();
            if (scanned) {
                if (isAcceptedPairingQr(scanned, acceptedPrefixes)) {
                    onValue(scanned);
                    if (status) {
                        status.textContent = 'QR code scanned.';
                        status.style.color = '';
                    }
                    stop();
                    return;
                }
                if (status) {
                    status.textContent = 'That QR is not a supported pairing URI.';
                    status.style.color = '#d04848';
                }
            }
        }
        frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return { stop };
}
// ── Picker ────────────────────────────────────────────────────────────────────
// Titles below are the desktop/unknown presentation. On a phone, the remote
// option is reworded to "Use another device" (see resolveMethodMeta).
const METHOD_META = {
    nip07: { icon: '🌐', title: 'Browser extension', hint: 'bark, Alby, nos2x' },
    amber: { icon: '🤖', title: 'Sign in with Amber', hint: 'Android signer (NIP-55)' },
    'local-signet': { icon: '🪪', title: 'Use this device', hint: 'Open Signet here' },
    'remote-signet': { icon: '📱', title: 'Use your phone', hint: 'Scan with Signet' },
    redirect: { icon: '🪪', title: 'Use this device', hint: 'Open Signet here' },
    qr: { icon: '📱', title: 'Use your phone', hint: 'Scan with Signet' },
    bunker: { icon: '🔑', title: 'Paste bunker URI', hint: 'For NIP-46 power users' },
    nostrconnect: { icon: '📡', title: 'Connect a Nostr signer', hint: 'Scan with nsec.app, Amber, Keychat...' },
    nsec: { icon: '⚠️', title: 'Paste private key', hint: 'In-memory only - risky, last resort' },
};
/**
 * Resolve a method's display metadata for the current platform. On a phone the
 * remote-Signet option points at "another device" rather than "your phone",
 * since the phone is the device the user is already holding.
 */
function resolveMethodMeta(method, mobile) {
    const base = METHOD_META[method];
    if (mobile && pickerMethodKey(method) === 'remote-signet') {
        return { ...base, title: 'Use another device' };
    }
    return base;
}
/**
 * Lead the picker with the signer on the *other* device: phone → "this device"
 * (local) first, desktop/unknown → "your phone" (remote) first. Swaps only the
 * local/remote Signet pair, leaving every other method in place.
 */
function orderSignetPairForPlatform(methods, mobile) {
    const localIdx = methods.findIndex(method => pickerMethodKey(method) === 'local-signet');
    const remoteIdx = methods.findIndex(method => pickerMethodKey(method) === 'remote-signet');
    if (localIdx === -1 || remoteIdx === -1)
        return methods;
    const alreadyOrdered = mobile ? localIdx < remoteIdx : remoteIdx < localIdx;
    if (alreadyOrdered)
        return methods;
    const next = methods.slice();
    [next[localIdx], next[remoteIdx]] = [next[remoteIdx], next[localIdx]];
    return next;
}
function pickerMethodKey(method) {
    if (method === 'local-signet' || method === 'redirect')
        return 'local-signet';
    if (method === 'remote-signet' || method === 'qr')
        return 'remote-signet';
    return method;
}
function routePickerChoice(choice) {
    if (choice === 'local-signet')
        return 'redirect';
    if (choice === 'remote-signet')
        return 'qr';
    return choice;
}
function isMethodAvailable(method) {
    if (method === 'nip07')
        return hasNip07();
    if (method === 'amber')
        return isAndroid();
    return true;
}
function methodButtonHtml(method, dark, muted, primary, mobile) {
    const meta = resolveMethodMeta(method, mobile);
    return `<button data-choice="${method}" style="${buttonStyle(dark, primary)}"><span style="font-size:1.2rem;">${meta.icon}</span><span><strong>${meta.title}</strong><br><span style="font-size:0.8rem;color:${primary ? 'rgba(255,255,255,0.8)' : muted};">${meta.hint}</span></span></button>`;
}
function renderPicker(refs, opts) {
    const dark = isDarkMode(opts.theme);
    const muted = dark ? '#888' : '#666';
    const mobile = opts.mobile;
    return new Promise(resolve => {
        let advancedOpen = false;
        const availableMethods = opts.methods.filter(isMethodAvailable);
        const advancedSet = new Set(opts.advancedMethods.map(pickerMethodKey));
        const primaryMethods = availableMethods.filter(method => !advancedSet.has(pickerMethodKey(method)));
        const advancedMethods = availableMethods.filter(method => advancedSet.has(pickerMethodKey(method)));
        const attachChoiceHandlers = () => {
            refs.dialog.querySelectorAll('button[data-choice]').forEach(btn => {
                btn.addEventListener('click', () => {
                    const choice = btn.dataset.choice;
                    resolve(choice);
                });
            });
            refs.dialog.querySelector('[data-action="advanced"]')?.addEventListener('click', () => {
                advancedOpen = true;
                paint();
            });
        };
        const paint = () => {
            const showAdvanced = advancedOpen || primaryMethods.length === 0;
            const primaryHtml = primaryMethods.map((method, index) => methodButtonHtml(method, dark, muted, index === 0, mobile)).join('');
            const advancedHtml = showAdvanced
                ? advancedMethods.map((method, index) => methodButtonHtml(method, dark, muted, primaryMethods.length === 0 && index === 0, mobile)).join('')
                : '';
            const advancedToggle = advancedMethods.length > 0 && !showAdvanced
                ? `<button data-action="advanced" style="${buttonStyle(dark)}justify-content:center;text-align:center;">Advanced</button>`
                : '';
            const empty = availableMethods.length === 0
                ? `<p style="margin:0 0 12px;color:${muted};font-size:0.85rem;">No configured sign-in methods are available on this device.</p>`
                : '';
            refs.dialog.innerHTML = `
        <h2 style="margin:0 0 8px;font-size:1.3rem;">Sign in to ${escapeHtml(opts.appName)}</h2>
        <p style="margin:0 0 24px;color:${muted};font-size:0.9rem;">Choose how you want to sign in. Your keys never leave your control.</p>
        <div style="display:flex;flex-direction:column;">
          ${empty}
          ${primaryHtml}
          ${advancedToggle}
          ${advancedHtml}
        </div>
        <button data-choice="cancel" style="background:transparent;color:${dark ? '#e0e0e0' : '#1a1a2e'};border:1px solid ${dark ? '#3a3a4e' : '#d0d0d0'};border-radius:8px;padding:12px;cursor:pointer;font-size:0.95rem;width:100%;margin-top:12px;text-align:center;">Cancel</button>
      `;
            attachChoiceHandlers();
        };
        paint();
    });
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
async function runNip07Flow(refs, opts) {
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
    const elapsedEl = refs.dialog.querySelector('#signet-login-nip07-elapsed');
    let elapsed = 0;
    const ticker = window.setInterval(() => {
        elapsed += 1;
        if (elapsedEl)
            elapsedEl.textContent = `Waiting for your signer (${elapsed}s)…`;
    }, 1000);
    // The cancel signal — resolves when the user clicks Cancel/Back. Used to
    // race the NIP-07 calls so the modal can dismiss promptly instead of
    // hanging on the unresolvable extension promise. (We can't truly abort
    // the NIP-07 promise since it has no abort signal, but we stop waiting
    // for it and let it resolve into the void.)
    const cancelled = new Promise(resolve => {
        refs.dialog.querySelector('[data-action="back"]')?.addEventListener('click', () => resolve(null));
        refs.dialog.querySelector('[data-action="cancel"]')?.addEventListener('click', () => resolve(null));
    });
    try {
        // Race: either the extension comes through, or the user cancels.
        const signer = await Promise.race([createNip07Signer(), cancelled]);
        if (!signer)
            return null;
        const authEvent = await Promise.race([
            signer.signEvent({
                kind: 21236,
                content: '',
                tags: [
                    ['challenge', opts.challenge],
                    ['origin', opts.origin],
                    ['app', opts.appName],
                ],
            }),
            cancelled,
        ]);
        if (!authEvent) {
            try {
                await signer.close();
            }
            catch { /* ignore */ }
            return null;
        }
        return { pubkey: signer.pubkey, authEvent };
    }
    catch (err) {
        if (elapsedEl) {
            elapsedEl.textContent = `✗ ${err instanceof Error ? err.message : String(err)}`;
            elapsedEl.style.color = '#d04848';
        }
        // Keep the modal up so user sees the error; resolve null after a beat
        // so the cancel button can take them back.
        await Promise.race([new Promise(r => setTimeout(r, 2500)), cancelled]);
        return null;
    }
    finally {
        window.clearInterval(ticker);
    }
}
async function runRedirectFlow(refs, opts, flowOpts = {}) {
    const dark = isDarkMode(opts.theme);
    const muted = dark ? '#888' : '#666';
    const sameDevice = flowOpts.sameDevice === true;
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
    <h2 style="margin:0 0 8px;font-size:1.2rem;">${sameDevice ? 'Open My Signet' : 'Sign in with Signet'}</h2>
    <p style="margin:0 0 16px;color:${muted};font-size:0.85rem;">${sameDevice ? 'Approve in My Signet and keep that tab open so it can sign for this app.' : 'Open the link on your phone, or scan the QR if rendered.'}</p>
    <div style="background:${dark ? '#0f0f1f' : '#f5f5f8'};border-radius:8px;padding:16px;margin-bottom:16px;">
      <canvas id="signet-login-qr" width="${LARGE_QR_SIZE_PX}" height="${LARGE_QR_SIZE_PX}" style="display:block;width:${LARGE_QR_SIZE_PX}px;height:auto;max-width:100%;margin:0 auto 12px;background:#ffffff;border-radius:6px;box-sizing:border-box;"></canvas>
      <a id="signet-login-open-signet" href="${escapeHtml(authUrl)}" target="_blank" rel="noopener" style="${sameDevice ? buttonStyle(dark, true) + 'justify-content:center;text-align:center;text-decoration:none;' : 'display:block;color:#5b6dff;font-size:0.75rem;word-break:break-all;text-decoration:none;'}">${sameDevice ? 'Open My Signet' : `${escapeHtml(authUrl.slice(0, 80))}…`}</a>
    </div>
    <p id="signet-login-status" style="margin:0 0 12px;color:${muted};font-size:0.85rem;">${sameDevice ? 'Waiting for My Signet approval…' : 'Waiting for approval…'}</p>
    <div style="display:flex;gap:8px;justify-content:space-between;">
      <button data-action="back" style="${buttonStyle(dark)}width:auto;flex:0 0 auto;padding:8px 16px;">← Back</button>
      <button data-action="cancel" style="${buttonStyle(dark)}width:auto;flex:0 0 auto;padding:8px 16px;">Cancel</button>
    </div>
  `;
    // Render the auth URL into the QR canvas. Async, but the dialog has already
    // surfaced the visible link as a fallback so a slow encode doesn't block UX.
    // 360px + H error correction (~30% damage tolerance) so a phone can lock on
    // from across a booth, at an angle, through screen glare. The auth URL is
    // short (origin + relay + session pubkey), so H's denser modules stay large
    // enough to scan at this size.
    const qrCanvas = refs.dialog.querySelector('#signet-login-qr');
    if (qrCanvas) {
        void QRCode.toCanvas(qrCanvas, authUrl, {
            width: LARGE_QR_SIZE_PX,
            margin: 1,
            errorCorrectionLevel: 'H',
            color: { dark: '#0a0418', light: '#ffffff' },
        }).then(() => { keepQrCanvasResponsive(qrCanvas); }).catch(() => {
            // Encoding failure (URL too long for QR L-Q levels, canvas inaccessible)
            // — the visible link below the canvas still gets the user across.
        });
    }
    if (sameDevice && typeof window !== 'undefined') {
        try {
            window.open(authUrl, '_blank', 'noopener,noreferrer');
        }
        catch {
            // Popup blocked or unavailable — the explicit link remains visible.
        }
    }
    return new Promise(resolve => {
        let settled = false;
        const settle = (v) => {
            if (settled)
                return;
            settled = true;
            resolve(v);
        };
        refs.dialog.querySelector('[data-action="back"]')?.addEventListener('click', () => {
            settle(null);
        });
        refs.dialog.querySelector('[data-action="cancel"]')?.addEventListener('click', () => {
            settle(null);
        });
        waitForAuthResponse({
            requestId: opts.challenge,
            relayUrl: opts.relayUrl,
            sessionPrivKey,
            expectedOrigin: opts.origin,
            timeout: opts.timeout,
        }).then(rawResult => {
            const result = rawResult;
            const authEvent = {
                id: result.authEvent.id,
                pubkey: result.authEvent.pubkey,
                kind: 21236,
                created_at: result.authEvent.created_at,
                tags: result.authEvent.tags,
                content: result.authEvent.content,
                sig: result.authEvent.sig,
            };
            const out = { pubkey: result.pubkey, authEvent };
            if (result.displayName)
                out.displayName = result.displayName;
            if (result.bunkerUri)
                out.bunkerUri = result.bunkerUri;
            settle(out);
        }).catch(err => {
            const status = refs.dialog.querySelector('#signet-login-status');
            if (status) {
                status.textContent = `✗ ${err instanceof Error ? err.message : String(err)}`;
                status.style.color = '#d04848';
            }
            // Don't auto-settle on error — let the user choose to go back/cancel.
        });
    });
}
async function buildSessionFromRedirectFlowResult(refs, result, opts, _aborted) {
    // Default: auth-only ephemeral signer (identity proof, no live signing).
    let signer = new EphemeralSigner(result.pubkey, result.authEvent);
    let method = 'redirect';
    // Cross-device / same-device bunker passthrough: when the signer device hands
    // back a `bunker://` URI (its own NIP-46 server, or an upstream hardware
    // bunker), connect before resolving the flow. Consumers such as Pallasite
    // reject auth-only at their auth boundary; returning a cold
    // DeferredBunkerSigner makes them classify the session as non-signing before
    // the relay handshake can finish.
    if (result.bunkerUri) {
        const clientSecretKey = await loadOrCreatePersistentClientSkFromStorage(opts.storage);
        const expected = result.pubkey;
        const status = refs.dialog.querySelector('#signet-login-status');
        if (status)
            status.textContent = 'Connecting signer...';
        try {
            const bunkerSigner = await createBunkerSigner({
                uri: result.bunkerUri,
                clientSecretKey,
                timeoutMs: QR_BUNKER_CONNECT_TIMEOUT_MS,
            });
            if (bunkerSigner.pubkey.toLowerCase() !== expected.toLowerCase()) {
                // Bunker came back as a different key than the identity we proved.
                // Discard it and keep the auth-only identity (result.pubkey) rather than
                // signing as the wrong key — the consumer can prompt for a proper signer
                // if it needs one.
                console.warn('[signet-login] Signet relay upgrade: bunker pubkey mismatch — continuing identity-only', { connected: bunkerSigner.pubkey, expected });
                void bunkerSigner.close().catch(() => { });
            }
            else {
                signer = bunkerSigner;
                method = 'bunker';
            }
        }
        catch (err) {
            // Bunker connect failed or timed out — signer offline, or a stale handoff
            // URI (the common cross-device failure: the producer re-handed a dead
            // connect string). Do NOT fail the whole sign-in: fall back to the
            // auth-only identity we already hold (the kind-21236 authEvent proves
            // result.pubkey). The consumer decides whether identity-only is enough —
            // one that needs a live signer can prompt for an upgrade rather than being
            // handed null and stranding the user at "couldn't sign in".
            console.warn('[signet-login] Signet relay upgrade: createBunkerSigner failed — continuing identity-only (auth-only).', err);
        }
    }
    else {
        console.warn('[signet-login] Signet relay login carried no bunkerUri — auth-only ephemeral (cannot sign). The signer device must have its NIP-46 server enabled to hand back a bunker:// URI.');
    }
    const session = {
        pubkey: result.pubkey,
        method,
        signer,
        authEvent: result.authEvent,
    };
    if (result.displayName)
        session.displayName = result.displayName;
    return session;
}
// ── Paste bunker URI ──────────────────────────────────────────────────────────
async function runBunkerFlow(refs, opts) {
    const dark = isDarkMode(opts.theme);
    const muted = dark ? '#888' : '#666';
    const inputBg = dark ? '#0f0f1f' : '#f5f5f8';
    const inputFg = dark ? '#e0e0e0' : '#1a1a2e';
    const scanButton = canUseCameraQrScanner()
        ? `<button data-action="scan" style="${buttonStyle(dark)}width:auto;flex:0 0 auto;padding:8px 16px;">Scan QR</button>`
        : '';
    refs.dialog.innerHTML = `
    <h2 style="margin:0 0 8px;font-size:1.2rem;">Paste bunker URI</h2>
    <p style="margin:0 0 16px;color:${muted};font-size:0.85rem;">Connect to your NIP-46 bunker (Heartwood, nsecBunker, Amber, or any compatible signer).</p>
    <textarea id="signet-login-bunker-input" placeholder="bunker://..." rows="3" style="width:100%;background:${inputBg};color:${inputFg};border:1px solid ${dark ? '#3a3a4e' : '#d0d0d0'};border-radius:8px;padding:10px;font-size:0.85rem;font-family:ui-monospace,monospace;box-sizing:border-box;resize:vertical;margin-bottom:12px;"></textarea>
    <div id="signet-login-bunker-scan" hidden style="margin:0 0 12px;"></div>
    <p id="signet-login-bunker-status" style="margin:0 0 12px;color:${muted};font-size:0.85rem;min-height:1.2em;"></p>
    <div style="display:flex;gap:8px;justify-content:space-between;">
      <button data-action="back" style="${buttonStyle(dark)}width:auto;flex:0 0 auto;padding:8px 16px;">← Back</button>
      ${scanButton}
      <button data-action="connect" style="${buttonStyle(dark, true)}width:auto;flex:1;padding:8px 16px;text-align:center;">Connect</button>
    </div>
  `;
    return new Promise(resolve => {
        let settled = false;
        let scanGeneration = 0;
        const settle = (v) => {
            if (settled)
                return;
            settled = true;
            scanGeneration++;
            scanner?.stop();
            resolve(v);
        };
        const input = refs.dialog.querySelector('#signet-login-bunker-input');
        const status = refs.dialog.querySelector('#signet-login-bunker-status');
        const scanContainer = refs.dialog.querySelector('#signet-login-bunker-scan');
        const connectBtn = refs.dialog.querySelector('[data-action="connect"]');
        const scanBtn = refs.dialog.querySelector('[data-action="scan"]');
        let scanner = null;
        refs.dialog.querySelector('[data-action="back"]')?.addEventListener('click', () => {
            scanner?.stop();
            settle(null);
        });
        scanBtn?.addEventListener('click', () => {
            if (!input || !scanContainer)
                return;
            scanner?.stop();
            scanner = null;
            const generation = ++scanGeneration;
            void startCameraQrScanner({
                container: scanContainer,
                status,
                acceptedPrefixes: ['bunker://'],
                onValue: value => {
                    input.value = value;
                    input.focus();
                },
            }).then(handle => {
                if (settled || generation !== scanGeneration) {
                    handle.stop();
                    return;
                }
                scanner = handle;
            }).catch(err => {
                if (settled || generation !== scanGeneration)
                    return;
                if (status) {
                    status.textContent = `✗ ${err instanceof Error ? err.message : String(err)}`;
                    status.style.color = '#d04848';
                }
            });
        });
        connectBtn?.addEventListener('click', async () => {
            const uri = input?.value.trim() ?? '';
            if (!uri) {
                if (status)
                    status.textContent = 'Please paste a bunker URI.';
                return;
            }
            if (status) {
                status.textContent = 'Connecting…';
                status.style.color = '';
            }
            connectBtn.disabled = true;
            try {
                const signer = await createBunkerSigner({
                    uri,
                    clientSecretKey: await loadOrCreatePersistentClientSkFromStorage(opts.storage),
                });
                settle(signer);
            }
            catch (err) {
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
function nostrConnectStatusText(status) {
    switch (status.type) {
        case 'uri-created':
            return 'NostrConnect URI ready. Scan or copy it into your signer.';
        case 'relay-connecting':
            return 'Connecting to NostrConnect relay...';
        case 'relay-connected':
            return `Connected to relay${status.relay ? ` ${status.relay}` : ''}. Waiting for signer approval...`;
        case 'signer-seen':
            return 'Signer seen. Verifying approval...';
        case 'request-sent':
            return status.method === 'connect'
                ? 'Signer approved. Confirming connection...'
                : `Sent ${status.method ?? 'NIP-46'} request to signer...`;
        case 'response-received':
            return status.phase === 'pairing'
                ? 'Approval received. Preparing signer...'
                : `Signer responded${status.method ? ` to ${status.method}` : ''}.`;
        case 'timeout':
            return status.message ? `Timed out: ${status.message}` : 'Timed out waiting for signer.';
        case 'error':
            return status.message ? `Error: ${status.message}` : 'NostrConnect failed.';
    }
}
/**
 * App-initiated NIP-46. Mirror image of bunker URI: instead of the user
 * pasting a bunker URI from their signer, we generate a `nostrconnect://`
 * URI and the user scans it with their signer (nsec.app, Amber, Keychat…).
 * The signer connects to our chosen relay and signs ad-hoc from there.
 */
async function runNostrConnectFlow(refs, opts) {
    const dark = isDarkMode(opts.theme);
    const muted = dark ? '#888' : '#666';
    // Persistent client key so the advertised client pubkey is stable across
    // logins (bunkers auto-approve a bound client pubkey). The connect `secret`
    // stays fresh per handshake — it's a one-time challenge, not an identity.
    const sk = await loadOrCreatePersistentClientSkFromStorage(opts.storage);
    const clientPubkey = bytesToHex(schnorr.getPublicKey(sk));
    const secret = bytesToHex(schnorr.utils.randomPrivateKey()).slice(0, 32);
    const uri = buildNostrConnectUri({
        clientPubkeyHex: clientPubkey,
        relayUrls: opts.relayUrls,
        secret,
        perms: opts.nostrConnectPerms,
        appName: opts.appName,
        appUrl: opts.origin,
    });
    refs.dialog.innerHTML = `
    <h2 style="margin:0 0 8px;font-size:1.2rem;">Connect a Nostr signer</h2>
    <p style="margin:0 0 16px;color:${muted};font-size:0.85rem;">Scan this with your signer (nsec.app, Amber, Keychat...), or copy/paste the URI below. The connection happens over your configured relay${opts.relayUrls.length > 1 ? 's' : ''}.</p>
    <div style="background:${dark ? '#0f0f1f' : '#f5f5f8'};border-radius:8px;padding:16px;margin-bottom:16px;">
      <canvas id="signet-login-nc-qr" width="${LARGE_QR_SIZE_PX}" height="${LARGE_QR_SIZE_PX}" style="display:block;width:${LARGE_QR_SIZE_PX}px;height:auto;max-width:100%;margin:0 auto 12px;background:#ffffff;border-radius:6px;box-sizing:border-box;"></canvas>
      <textarea id="signet-login-nc-uri" readonly rows="4" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" aria-label="NostrConnect URI" style="width:100%;background:${dark ? '#050510' : '#ffffff'};color:${dark ? '#e7e7f0' : '#141427'};border:1px solid ${dark ? '#34344d' : '#d8dae3'};border-radius:6px;padding:8px;font-size:0.7rem;line-height:1.35;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;box-sizing:border-box;resize:vertical;margin:0 0 10px;overflow-wrap:anywhere;">${escapeHtml(uri)}</textarea>
      <button data-action="copy" style="${buttonStyle(dark)}width:auto;font-size:0.75rem;padding:6px 10px;margin:0 auto;display:block;">Copy URI</button>
    </div>
    <p id="signet-login-nc-status" style="margin:0 0 12px;color:${muted};font-size:0.85rem;">Waiting for signer to connect…</p>
    <div style="display:flex;gap:8px;justify-content:space-between;">
      <button data-action="back" style="${buttonStyle(dark)}width:auto;flex:0 0 auto;padding:8px 16px;">← Back</button>
      <button data-action="cancel" style="${buttonStyle(dark)}width:auto;flex:0 0 auto;padding:8px 16px;">Cancel</button>
    </div>
  `;
    const qrCanvas = refs.dialog.querySelector('#signet-login-nc-qr');
    if (qrCanvas) {
        void QRCode.toCanvas(qrCanvas, uri, {
            width: LARGE_QR_SIZE_PX, margin: 2, errorCorrectionLevel: 'L',
            color: { dark: '#0a0418', light: '#ffffff' },
        }).then(() => { keepQrCanvasResponsive(qrCanvas); }).catch(() => { });
    }
    const status = refs.dialog.querySelector('#signet-login-nc-status');
    const uriText = refs.dialog.querySelector('#signet-login-nc-uri');
    const selectUriText = () => {
        if (!uriText)
            return;
        uriText.focus();
        uriText.select();
        uriText.setSelectionRange(0, uriText.value.length);
    };
    uriText?.addEventListener('focus', selectUriText);
    uriText?.addEventListener('click', selectUriText);
    const copyBtn = refs.dialog.querySelector('[data-action="copy"]');
    copyBtn?.addEventListener('click', () => {
        void (async () => {
            try {
                if (navigator.clipboard?.writeText) {
                    await navigator.clipboard.writeText(uri);
                }
                else {
                    selectUriText();
                    if (typeof document.execCommand !== 'function' || !document.execCommand('copy')) {
                        throw new Error('clipboard-unavailable');
                    }
                }
                copyBtn.textContent = 'Copied ✓';
                window.setTimeout(() => { copyBtn.textContent = 'Copy URI'; }, 1500);
            }
            catch {
                selectUriText();
                copyBtn.textContent = 'URI selected';
                if (status) {
                    status.textContent = 'URI selected. Copy it manually if needed.';
                    status.style.color = '';
                }
                window.setTimeout(() => { copyBtn.textContent = 'Copy URI'; }, 2000);
            }
        })();
    });
    const ac = new AbortController();
    return new Promise(resolve => {
        let settled = false;
        const settle = (v) => {
            if (settled)
                return;
            settled = true;
            resolve(v);
        };
        refs.dialog.querySelector('[data-action="back"]')?.addEventListener('click', () => {
            ac.abort();
            settle(null);
        });
        refs.dialog.querySelector('[data-action="cancel"]')?.addEventListener('click', () => {
            ac.abort();
            settle(null);
        });
        const handleStatus = (event) => {
            const text = nostrConnectStatusText(event);
            if (status && text) {
                status.textContent = text;
                status.style.color = event.type === 'error' || event.type === 'timeout' ? '#d04848' : muted;
            }
            opts.onNostrConnectStatus?.(event);
        };
        createBunkerSignerFromNostrConnect({
            uri,
            clientSecretKey: sk,
            abortSignal: ac.signal,
            timeoutMs: opts.timeout,
            onStatus: handleStatus,
        })
            .then(signer => settle(signer))
            .catch(err => {
            if (settled)
                return; // already cancelled
            if (status) {
                status.textContent = `✗ ${err instanceof Error ? err.message : String(err)}`;
                status.style.color = '#d04848';
            }
            // Don't auto-settle on error — user clicks Back/Cancel.
        });
    });
}
// ── Paste nsec (in-memory only) ───────────────────────────────────────────────
async function runNsecFlow(refs, opts) {
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
    return new Promise(resolve => {
        let settled = false;
        const settle = (v) => {
            if (settled)
                return;
            settled = true;
            resolve(v);
        };
        const input = refs.dialog.querySelector('#signet-login-nsec-input');
        const status = refs.dialog.querySelector('#signet-login-nsec-status');
        const connectBtn = refs.dialog.querySelector('[data-action="connect"]');
        refs.dialog.querySelector('[data-action="back"]')?.addEventListener('click', () => {
            if (input)
                input.value = '';
            settle(null);
        });
        connectBtn?.addEventListener('click', () => {
            const value = input?.value ?? '';
            if (!value.trim()) {
                if (status)
                    status.textContent = 'Please paste an nsec.';
                return;
            }
            try {
                const signer = createLocalSignerFromNsec(value);
                // Wipe the textarea ASAP — the key is now in the signer.
                if (input)
                    input.value = '';
                settle(signer);
            }
            catch (err) {
                if (status) {
                    status.textContent = `✗ ${err instanceof Error ? err.message : String(err)}`;
                    status.style.color = '#d04848';
                }
            }
        });
    });
}
function uniquePickerMethods(input, fallback) {
    const source = input ?? fallback;
    const allowed = new Set(ALL_PICKER_METHODS);
    const seen = new Set();
    const out = [];
    for (const method of source) {
        if (!allowed.has(method))
            continue;
        const key = pickerMethodKey(method);
        if (seen.has(key))
            continue;
        seen.add(key);
        out.push(method);
    }
    return input === undefined && out.length === 0 ? [...fallback] : out;
}
function resolveMethodConfig(opts, mobile) {
    let methods = uniquePickerMethods(opts.methods, DEFAULT_PICKER_METHODS);
    // Only the default list adapts to the platform; an explicit `methods` order is
    // the consumer's deliberate choice and is honoured as given.
    if (opts.methods === undefined)
        methods = orderSignetPairForPlatform(methods, mobile);
    const methodKeys = new Set(methods.map(pickerMethodKey));
    const advancedMethods = uniquePickerMethods(opts.advancedMethods, DEFAULT_ADVANCED_METHODS)
        .filter(method => methodKeys.has(pickerMethodKey(method)));
    return { methods, advancedMethods };
}
function resolveRelayUrls(opts) {
    const relayUrls = opts.relayUrls ?? (opts.relayUrl ? [opts.relayUrl] : [DEFAULTS.relayUrl]);
    const cleanRelayUrls = relayUrls.map(relay => relay.trim()).filter(Boolean);
    return cleanRelayUrls.length > 0 ? cleanRelayUrls : [DEFAULTS.relayUrl];
}
function resolvePrimaryRelayUrl(opts, relayUrls) {
    const relayUrl = opts.relayUrl?.trim();
    return relayUrl || relayUrls[0] || DEFAULTS.relayUrl;
}
function resolveOptions(opts) {
    const challenge = opts.challenge ?? generateChallenge();
    if (!/^[0-9a-f]{64}$/i.test(challenge))
        throw new Error('challenge-must-be-64-hex');
    const origin = typeof window !== 'undefined' ? window.location.origin : 'http://localhost';
    const timeout = Math.max(5000, Math.min(opts.timeout ?? DEFAULTS.timeout, 600000));
    const relayUrls = resolveRelayUrls(opts);
    const relayUrl = resolvePrimaryRelayUrl(opts, relayUrls);
    const mobile = isMobile();
    const methodConfig = resolveMethodConfig(opts, mobile);
    const result = {
        appName: opts.appName,
        challenge: challenge.toLowerCase(),
        origin,
        mobile,
        methods: methodConfig.methods,
        advancedMethods: methodConfig.advancedMethods,
        relayUrl,
        relayUrls,
        nostrConnectPerms: opts.nostrConnectPerms ?? DEFAULT_NOSTR_CONNECT_PERMS,
        theme: opts.theme ?? DEFAULTS.theme,
        timeout,
        signetAppOrigin: opts.signetAppOrigin ?? DEFAULTS.signetAppOrigin,
    };
    if (opts.preferredMethod !== undefined)
        result.preferredMethod = opts.preferredMethod;
    if (opts.redirectCallback !== undefined)
        result.redirectCallback = opts.redirectCallback;
    if (opts.storage !== undefined)
        result.storage = opts.storage;
    if (opts.onNostrConnectStatus !== undefined)
        result.onNostrConnectStatus = opts.onNostrConnectStatus;
    return result;
}
let modalQueue = Promise.resolve();
/**
 * Entry point — show the modal, route to the chosen method, return a session.
 *
 * Returns null when the user cancels or the flow times out.
 */
export async function showLoginModal(opts) {
    const previous = modalQueue;
    let release;
    modalQueue = new Promise(resolve => { release = resolve; });
    await previous;
    try {
        return await runLoginModal(opts);
    }
    finally {
        release();
    }
}
async function runLoginModal(opts) {
    if (!opts.appName || opts.appName.length === 0)
        throw new Error('appName-required');
    if (opts.appName.length > 64)
        throw new Error('appName-too-long');
    const resolved = resolveOptions(opts);
    const refs = buildModalShell(resolved.theme);
    // Escape and the Android / OS back button fire the dialog's native
    // `cancel` event. Unhandled, the dialog closes visually but the
    // in-flight flow promise never resolves — login() hangs forever and
    // the caller's UI is left stuck behind a dead modal. Racing every
    // flow await against this lets the modal exit cleanly.
    let userAborted = false;
    const aborted = new Promise((resolve) => {
        refs.dialog.addEventListener('cancel', () => { userAborted = true; resolve(null); });
    });
    try {
        while (true) {
            const choice = resolved.preferredMethod
                ? resolved.preferredMethod
                : await Promise.race([renderPicker(refs, resolved), aborted]);
            const routeChoice = choice === null ? null : routePickerChoice(choice);
            if (userAborted)
                return null;
            if (routeChoice === null || routeChoice === 'cancel')
                return null;
            if (routeChoice === 'nip07') {
                const result = await Promise.race([runNip07Flow(refs, resolved), aborted]);
                if (userAborted)
                    return null;
                if (!result) {
                    if (resolved.preferredMethod)
                        return null;
                    continue; // back to picker
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
            if (routeChoice === 'redirect') {
                // Same-device Signet in the modal must keep this app tab alive and keep
                // the My Signet tab alive as the ongoing bunker. Use the relay-backed
                // auth response path here; explicit `login({ mode: 'redirect' })`
                // remains the same-tab redirect API for mobile/single-device callers.
                const result = await Promise.race([runRedirectFlow(refs, resolved, { sameDevice: true }), aborted]);
                if (userAborted)
                    return null;
                if (!result) {
                    if (resolved.preferredMethod)
                        return null;
                    continue;
                }
                const session = await buildSessionFromRedirectFlowResult(refs, result, resolved, aborted);
                if (userAborted)
                    return null;
                if (!session) {
                    if (resolved.preferredMethod)
                        return null;
                    continue;
                }
                return session;
            }
            if (routeChoice === 'amber') {
                // Same-tab navigation to a `nostrsigner:` URL. Android dispatches
                // it to Amber; the page comes back via callbackUrl with the signed
                // event in `?event=`. Picked up on next boot by handleRedirectCallback.
                await startAmberSignIn({
                    appName: resolved.appName,
                    challenge: resolved.challenge,
                    origin: resolved.origin,
                    ...(resolved.redirectCallback !== undefined ? { redirectCallback: resolved.redirectCallback } : {}),
                    ...(resolved.storage !== undefined ? { storage: resolved.storage } : {}),
                });
                return null; // unreachable
            }
            if (routeChoice === 'qr') {
                const result = await Promise.race([runRedirectFlow(refs, resolved), aborted]);
                if (userAborted)
                    return null;
                if (!result) {
                    if (resolved.preferredMethod)
                        return null;
                    continue;
                }
                const session = await buildSessionFromRedirectFlowResult(refs, result, resolved, aborted);
                if (userAborted)
                    return null;
                if (!session) {
                    if (resolved.preferredMethod)
                        return null;
                    continue;
                }
                return session;
            }
            if (routeChoice === 'bunker') {
                const signer = await Promise.race([runBunkerFlow(refs, resolved), aborted]);
                if (userAborted)
                    return null;
                if (!signer) {
                    if (resolved.preferredMethod)
                        return null;
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
                });
                return {
                    pubkey: signer.pubkey,
                    method: 'bunker',
                    signer,
                    authEvent,
                };
            }
            if (routeChoice === 'nostrconnect') {
                const signer = await Promise.race([runNostrConnectFlow(refs, resolved), aborted]);
                if (userAborted)
                    return null;
                if (!signer) {
                    if (resolved.preferredMethod)
                        return null;
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
                });
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
            if (routeChoice === 'nsec') {
                const signer = await Promise.race([runNsecFlow(refs, resolved), aborted]);
                if (userAborted)
                    return null;
                if (!signer) {
                    if (resolved.preferredMethod)
                        return null;
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
                });
                return {
                    pubkey: signer.pubkey,
                    method: 'nsec',
                    signer,
                    authEvent,
                };
            }
            // Unknown choice — restart picker
        }
    }
    finally {
        tearDown(refs);
    }
}
