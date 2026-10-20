import { NostrConnect } from 'nostr-tools/kinds';
/** Publish one already-signed decrypt request. This owns only its EVENT
 * sockets, never the shared response subscription or signer connection.
 * No queue, reconnect or retry may outlive this request's permission. */
export function publishNip46DecryptRequest(event, relays, current, timeoutMs, Base) {
    const live = () => { try {
        return current() === true;
    }
    catch {
        return false;
    } };
    if (!live())
        return Promise.reject(new Error('nip46-decrypt-no-longer-current'));
    if (!Base || typeof Base.prototype.send !== 'function')
        return Promise.reject(new Error('nip46-decrypt-websocket-unavailable'));
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || relays.length < 1 || relays.length > 16)
        return Promise.reject(new Error('nip46-decrypt-invalid-carrier'));
    const targets = [...new Set(relays)];
    const frame = JSON.stringify(['EVENT', event]);
    if (event.kind !== NostrConnect || frame.length > 1024 * 1024 || new TextEncoder().encode(frame).byteLength > 1024 * 1024)
        return Promise.reject(new Error('nip46-decrypt-invalid-request'));
    const send = Base.prototype.send;
    const invoke = Reflect.apply;
    return new Promise((resolve, reject) => {
        let active = true, remaining = targets.length;
        const sockets = new Set();
        let timer, poll;
        const close = (socket) => { try {
            socket.close();
        }
        catch { /* Late OPEN still checks active/current before send. */ } };
        const finish = (error) => {
            if (!active)
                return;
            active = false;
            clearTimeout(timer);
            clearInterval(poll);
            for (const socket of sockets)
                close(socket);
            if (error)
                reject(error);
            else
                resolve();
        };
        const permitted = () => active && live();
        timer = setTimeout(() => finish(new Error('nip46-decrypt-publication-timeout')), timeoutMs);
        poll = setInterval(() => { if (!live())
            finish(new Error('nip46-decrypt-no-longer-current')); }, 25);
        for (const relay of targets) {
            // No await between the fresh decision and starting this socket.
            if (!permitted()) {
                finish(new Error('nip46-decrypt-no-longer-current'));
                break;
            }
            let socket;
            try {
                socket = new Base(relay);
                sockets.add(socket);
            }
            catch {
                if (--remaining === 0)
                    finish(new Error('nip46-decrypt-publication-failed'));
                continue;
            }
            let sent = false, failed = false;
            const refuse = () => {
                if (failed || !active)
                    return;
                failed = true;
                close(socket);
                if (--remaining === 0)
                    finish(new Error('nip46-decrypt-publication-failed'));
            };
            // Keep the error observer until the socket closes, including an
            // abandoned Node ws handshake. No detached rejection is created.
            socket.onerror = () => refuse();
            socket.onclose = () => refuse();
            socket.onopen = () => {
                if (sent)
                    return;
                if (failed || !active) {
                    close(socket);
                    return;
                }
                sent = true;
                if (!permitted()) {
                    close(socket);
                    finish(new Error('nip46-decrypt-no-longer-current'));
                    return;
                }
                try {
                    // The captured native send is invoked synchronously in this
                    // decision. A pool's deferred send callback cannot bypass it.
                    invoke(send, socket, [frame]);
                }
                catch {
                    refuse();
                }
            };
            socket.onmessage = message => {
                if (failed)
                    return;
                if (!permitted()) {
                    finish(new Error('nip46-decrypt-no-longer-current'));
                    return;
                }
                if (typeof message.data !== 'string' || message.data.length > 64 * 1024)
                    return;
                try {
                    const reply = JSON.parse(message.data);
                    if (!Array.isArray(reply) || reply.length !== 4 || reply[0] !== 'OK' || reply[1] !== event.id || typeof reply[3] !== 'string')
                        return;
                    if (reply[2] === true)
                        finish();
                    else if (reply[2] === false)
                        refuse();
                }
                catch { /* Unrelated/malformed acknowledgements prove nothing. */ }
            };
        }
    });
}
