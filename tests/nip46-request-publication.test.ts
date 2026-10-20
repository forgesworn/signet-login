import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { publishNip46DecryptRequest } from '../src/nip46-request-publication.js';
import type { NostrEvent } from '../src/types.js';

// Deterministic socket lifecycle fixture. This is no external-relay proof.
class Socket {
  static sockets: Socket[] = [];
  static failClose = false;
  onopen?: () => void;
  onerror?: () => void;
  onclose?: () => void;
  onmessage?: (event: { data: string }) => void;
  frames: string[] = [];
  closes = 0;
  constructor(readonly url: string) { Socket.sockets.push(this); }
  send(data: string) { this.frames.push(data); }
  close() { this.closes++; if (Socket.failClose) throw Error('Unfinished handshake'); }
  open() { this.onopen?.(); }
  ack(id: string, accepted = true) { this.onmessage?.({ data: JSON.stringify(['OK', id, accepted, '']) }); }
}
const Base = Socket as unknown as typeof WebSocket;
const event: NostrEvent = { kind: 24133, pubkey: 'a'.repeat(64), id: 'b'.repeat(64), sig: 'c'.repeat(128), created_at: 1, tags: [['p', 'd'.repeat(64)]], content: 'Already signed encrypted RPC' };
beforeEach(() => { Socket.sockets = []; Socket.failClose = false; });
afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });

it('refuses revoked permission before constructing a socket and never falls back to a global carrier', async () => {
  await expect(publishNip46DecryptRequest(event, ['wss://relay.example'], () => false, 100, Base)).rejects.toThrow('no-longer-current');
  await expect(publishNip46DecryptRequest(event, ['wss://relay.example'], () => true, 100, undefined as unknown as typeof WebSocket)).rejects.toThrow('websocket-unavailable');
  expect(Socket.sockets).toHaveLength(0);
});

for (const reason of ['view', 'request-settlement', 'guard-error'] as const) it(`a late OPEN cannot write after ${reason}`, async () => {
  let live = true;
  const pending = publishNip46DecryptRequest(event, ['wss://relay.example'], () => { if (reason === 'guard-error' && !live) throw Error('Revoked'); return live; }, 100, Base);
  const refused = expect(pending).rejects.toThrow('no-longer-current');
  live = false; Socket.sockets[0].open(); await refused;
  expect(Socket.sockets[0].frames).toEqual([]); expect(Socket.sockets[0].closes).toBeGreaterThan(0);
});

it('captures its selected constructor/send and sends the original signed event only once', async () => {
  const pending = publishNip46DecryptRequest(event, ['wss://relay.example'], () => true, 100, Base);
  vi.spyOn(Socket.prototype, 'send').mockImplementation(() => { throw Error('Replaced after capture'); });
  const socket = Socket.sockets[0]; socket.open(); socket.open();
  expect(socket.frames).toEqual([JSON.stringify(['EVENT', event])]);
  socket.ack(event.id); await pending; expect(socket.closes).toBeGreaterThan(0);
});

it('closes slower peers after a positive acknowledgement and fences a later handshake', async () => {
  const pending = publishNip46DecryptRequest(event, ['wss://one.example', 'wss://two.example'], () => true, 100, Base);
  const [first, second] = Socket.sockets; first.open(); first.ack(event.id); await pending; second.open();
  expect(first.frames).toHaveLength(1); expect(second.frames).toEqual([]); expect(second.closes).toBeGreaterThan(0);
});

it('does not resurrect a refused socket while another relay is still pending or retry either relay', async () => {
  const pending = publishNip46DecryptRequest(event, ['wss://one.example', 'wss://two.example'], () => true, 100, Base);
  const refused = expect(pending).rejects.toThrow('publication-failed');
  const [first, second] = Socket.sockets; first.open(); first.ack(event.id, false); first.open(); second.open(); second.ack(event.id, false);
  await refused; expect(first.frames).toHaveLength(1); expect(second.frames).toHaveLength(1); expect(Socket.sockets).toHaveLength(2);
});

it('bounds a stalled handshake and refuses late OPEN even if closing the handshake throws', async () => {
  vi.useFakeTimers(); Socket.failClose = true;
  const pending = publishNip46DecryptRequest(event, ['wss://relay.example'], () => true, 50, Base);
  const refused = expect(pending).rejects.toThrow('publication-timeout');
  await vi.advanceTimersByTimeAsync(50); await refused;
  Socket.sockets[0].open(); expect(Socket.sockets[0].frames).toEqual([]); expect(vi.getTimerCount()).toBe(0);
});

it('ignores wrong-id or malformed acknowledgements instead of treating them as acceptance', async () => {
  vi.useFakeTimers();
  const pending = publishNip46DecryptRequest(event, ['wss://relay.example'], () => true, 50, Base);
  const refused = expect(pending).rejects.toThrow('publication-timeout');
  const socket = Socket.sockets[0]; socket.open(); socket.ack('Wrong event'); socket.onmessage?.({ data: 'not json' });
  await vi.advanceTimersByTimeAsync(50); await refused; expect(vi.getTimerCount()).toBe(0);
});
