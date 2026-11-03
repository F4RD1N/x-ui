/* Fill missing credentials only after an explicit native mode change. */
(() => {
    const clone = value => JSON.parse(JSON.stringify(value));
    const dormant = new WeakMap();
    const shadowModes = new WeakMap();
    const random = length => {
        if (!globalThis.crypto?.getRandomValues) throw new Error('Secure credential generation is unavailable in this browser.');
        return globalThis.crypto.getRandomValues(new Uint8Array(length));
    };
    const hex = bytes => Array.from(bytes, value => value.toString(16).padStart(2, '0')).join('');
    const base64 = length => btoa(Array.from(random(length), value => String.fromCharCode(value)).join(''));
    const uuid = () => {
        const bytes = random(16);
        bytes[6] = (bytes[6] & 15) | 64;
        bytes[8] = (bytes[8] & 63) | 128;
        const value = hex(bytes);
        return `${value.slice(0, 8)}-${value.slice(8, 12)}-${value.slice(12, 16)}-${value.slice(16, 20)}-${value.slice(20)}`;
    };
    const present = value => Array.isArray(value) ? value.some(item => String(item).trim()) : typeof value === 'string' && value.trim() !== '';
    const serverName = (data, options) => data.clientExport?.serverName || options.serverName || (typeof location !== 'undefined' && location.hostname) || 'vpn.internal';
    const ss2022Sizes = {'2022-blake3-aes-128-gcm': 16, '2022-blake3-aes-256-gcm': 32, '2022-blake3-chacha20-poly1305': 32};
    const aeadMethods = ['aes-128-gcm', 'aes-256-gcm', 'chacha20-poly1305', 'xchacha20-poly1305', 'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305', 'aead_aes_128_gcm', 'aead_aes_256_gcm', 'aead_chacha20_poly1305', 'aead_xchacha20_poly1305'];

    function completeShadowInner(inner) {
        const settings = inner?.settings;
        if (!settings || typeof settings !== 'object') return false;
        if (inner.protocol === 'socks') return settings.auth === 'password' && settings.udp !== true && Array.isArray(settings.accounts) && settings.accounts.every(account => present(account.user) && present(account.pass));
        if (inner.protocol === 'vless') return settings.decryption === 'none' && Array.isArray(settings.clients) && settings.clients.every(account => /^[0-9a-f-]{36}$/i.test(account.id || '') && !account.flow);
        if (inner.protocol !== 'shadowsocks' || !Array.isArray(settings.clients) || (settings.network && settings.network !== 'tcp')) return false;
        const method = String(settings.method || settings.clients[0]?.method || '').toLowerCase();
        if (ss2022Sizes[method]) return present(settings.password) && settings.clients.every(account => present(account.password));
        return aeadMethods.includes(method) && settings.clients.every(account => present(account.password) && aeadMethods.includes(String(account.method || method).toLowerCase()));
    }

    // Called before the form changes inner.protocol. Dormant modes remain only
    // in memory and are never added to the runtime or subscription JSON.
    Inbound.NativeSettings.prototype.rememberModeDefaults = function () {
        if (this.protocol !== 'shadowtls') return;
        let state = shadowModes.get(this);
        if (!state) { state = {modes: new Map(), from: ''}; shadowModes.set(this, state); }
        state.from = this.data.inner?.protocol || '';
        if (completeShadowInner(this.data.inner)) {
            state.modes.set(state.from, {inner: clone(this.data.inner), users: new Map(this.clients.map(client => [client, client.data.innerUsername]))});
        }
    };

    function fillShadow(settings, data, clients) {
        const protocol = data.inner?.protocol;
        if (!['socks', 'vless', 'shadowsocks'].includes(protocol)) throw new Error('Choose an authenticated inner proxy.');
        const mode = shadowModes.get(settings);
        const changed = mode?.from && mode.from !== protocol;
        const saved = changed ? mode.modes.get(protocol) : null;
        if (saved) data.inner = clone(saved.inner);
        else if (changed) {
            if (protocol === 'socks') data.inner = {protocol, settings: {auth: 'password', udp: false, accounts: []}};
            else if (protocol === 'vless') data.inner = {protocol, settings: {decryption: 'none', clients: []}};
            else data.inner = {protocol, settings: {network: 'tcp', method: '2022-blake3-aes-256-gcm', password: base64(32), clients: []}};
        }
        if (!completeShadowInner(data.inner)) throw new Error('Complete or clear the partial inner credentials before changing this mode.');
        const inner = data.inner.settings;
        const list = protocol === 'socks' ? inner.accounts : inner.clients;
        for (const entry of clients) {
            if (!entry.client.email) throw new Error('A client email is required.');
            if (protocol === 'socks') {
                const remembered = saved?.users.get(entry.client) || (!changed && entry.data.innerUsername);
                let matches = list.filter(account => account.user === (remembered || entry.client.email));
                if (matches.length > 1) throw new Error('Inner usernames must be unique.');
                if (!matches.length) {
                    const account = {user: entry.client.email, pass: uuid()};
                    if (list.some(existing => existing.user === account.user)) throw new Error('The inner username is already assigned.');
                    list.push(account); matches = [account];
                }
                entry.data.innerUsername = matches[0].user;
            } else {
                const matches = list.filter(account => account.email === entry.client.email);
                if (matches.length > 1) throw new Error('Inner client emails must be unique.');
                if (!matches.length) {
                    const account = {email: entry.client.email, level: 0};
                    if (protocol === 'vless') account.id = uuid();
                    else {
                        const method = String(inner.method || inner.clients[0]?.method || '').toLowerCase();
                        account.password = base64(ss2022Sizes[method] || 32);
                        if (!ss2022Sizes[method]) account.method = method;
                        else if (inner.uuidIdentityKeys === true) account.uuidIdentityKeys = false;
                    }
                    list.push(account);
                }
            }
        }
        if (new Set(clients.map(entry => entry.client.email)).size !== clients.length) throw new Error('Client emails must be unique.');
        const identities = list.map(account => protocol === 'socks' ? account.user : protocol === 'vless' ? account.id : account.password);
        if (new Set(identities).size !== identities.length) throw new Error('Inner client credentials must be unique.');
        if (data.version === 2 && !present(data.password)) data.password = uuid();
        if ((data.version || 3) === 3) {
            for (const entry of clients) if (!present(entry.data.password)) entry.data.password = uuid();
        }
        return {inner: clone(data.inner), users: new Map(clients.map(entry => [entry.client, entry.data.innerUsername]))};
    }

    function needsWork(settings) {
        const data = settings.data;
        if (settings.protocol === 'orbit') {
            if (['ws', 'wss'].includes(data.transport) && (!data.host || !data.path)) return true;
            if (data.transport === 'wss' && present(data.outerTls?.certificate) !== present(data.outerTls?.key)) return true;
            return data.security === 'reality' && (data.transport !== 'tcp' || !present(data.reality?.privateKey) || !data.reality?.serverNames?.length || !data.reality?.shortIds?.length || !data.reality?.dest);
        }
        if (settings.protocol === 'dnstt') {
            const inner = data.inner?.protocol || 'vless';
            if (!['socks', 'vless'].includes(inner)) return true;
            return settings.clients.some(client => inner === 'socks'
                ? Object.hasOwn(client.data, 'id') || !client.data.username || !client.data.password
                : Object.hasOwn(client.data, 'username') || Object.hasOwn(client.data, 'password') || !client.data.id);
        }
        if (settings.protocol === 'shadowtls') {
            const inner = data.inner;
            const mode = shadowModes.get(settings);
            if (mode?.from && mode.from !== inner?.protocol) return true;
            if (!completeShadowInner(inner)) return true;
            if (data.version === 2 && !present(data.password)) return true;
            if ((data.version || 3) === 3 && settings.clients.some(client => !present(client.data.password))) return true;
            return settings.clients.some(client => inner.protocol === 'socks'
                ? !inner.settings.accounts.some(account => account.user === client.data.innerUsername)
                : !inner.settings.clients.some(account => account.email === client.email));
        }
        if (settings.protocol === 'openvpn' && data.clientProof?.required === true) {
            const proofs = settings.clients.map(client => client.data.clientProof);
            return proofs.some(proof => !proof || typeof proof.keyId !== 'string' || !proof.keyId.trim() || typeof proof.key !== 'string' || !/^[0-9a-f]{64}$/i.test(proof.key)) || new Set(proofs.map(proof => proof.keyId)).size !== proofs.length;
        }
        return false;
    }

    Inbound.NativeSettings.prototype.fillMissingModeDefaults = async function (options = {}) {
        if (this.generating) return false;
        if (!needsWork(this)) {
            this.generationError = '';
            return true;
        }
        this.generating = true;
        this.generationError = '';
        this.generationNotice = '';
        const before = JSON.stringify(this.toJson());
        const protocol = this.protocol;
        const data = clone(this.data);
        const clients = this.clients.map(client => ({client, data: clone(client.data), cache: {...(dormant.get(client) || {})}}));
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 15000);
        try {
            let nextShadow;
            if (protocol === 'orbit') {
                if (data.transport === 'wss') {
                    const hasCert = present(data.outerTls?.certificate), hasKey = present(data.outerTls?.key);
                    if (hasCert !== hasKey) throw new Error('Provide both the WSS certificate and private key.');
                    // The current Orbit client uses system CA trust. Generated
                    // self-signed outer certificates would make WSS unusable.
                    if (!data.host) data.host = serverName(data, options);
                    if (!data.path) data.path = '/core';
                } else if (data.transport === 'ws') {
                    if (!data.host) data.host = serverName(data, options);
                    if (!data.path) data.path = '/core';
                }
                if (data.security === 'reality') {
                    if (data.transport !== 'tcp') throw new Error('Reality requires TCP.');
                    data.reality = {...(data.reality || {})};
                    if (!present(data.reality.privateKey)) {
                        const generated = await Inbound.NativeSettings.requestCredentials({kind: 'orbit-reality'}, controller.signal);
                        if (!/^[A-Za-z0-9_-]{43}$/.test(generated.privateKey || '') || !/^[A-Za-z0-9_-]{43}$/.test(generated.publicKey || '') || !/^[0-9a-f]{16}$/i.test(generated.shortId || '')) throw new Error('The server returned invalid Reality keys.');
                        data.reality.privateKey = generated.privateKey;
                        if (!Array.isArray(data.reality.shortIds) || !data.reality.shortIds.length) data.reality.shortIds = [generated.shortId];
                    } else if (!Array.isArray(data.reality.shortIds) || !data.reality.shortIds.length) data.reality.shortIds = [hex(random(8))];
                    if (!Array.isArray(data.reality.serverNames) || !data.reality.serverNames.length) data.reality.serverNames = ['www.microsoft.com'];
                    if (!data.reality.dest) data.reality.dest = 'www.microsoft.com:443';
                }
            } else if (protocol === 'dnstt') {
                const inner = data.inner?.protocol || 'vless';
                if (!['vless', 'socks'].includes(inner)) throw new Error('Choose VLESS or SOCKS for the inner protocol.');
                for (const entry of clients) {
                    const account = entry.data;
                    if (inner === 'socks') {
                        if (account.id) entry.cache.id = account.id;
                        if (!account.username) account.username = entry.cache.username || entry.client.email;
                        if (!account.password) account.password = entry.cache.password || uuid();
                        if (!account.username) throw new Error('A client email is required.');
                        delete account.id;
                    } else {
                        if (account.username) entry.cache.username = account.username;
                        if (account.password) entry.cache.password = account.password;
                        if (!account.id) account.id = entry.cache.id || uuid();
                        delete account.username;
                        delete account.password;
                    }
                }
                const identities = clients.map(entry => inner === 'socks' ? entry.data.username : entry.data.id);
                if (new Set(identities).size !== identities.length) throw new Error('Client identities must be unique.');
            } else if (protocol === 'shadowtls') {
                nextShadow = fillShadow(this, data, clients);
            } else if (protocol === 'openvpn' && data.clientProof?.required === true) {
                // Validate all existing material before requesting anything.
                for (const entry of clients) {
                    const proof = entry.data.clientProof;
                    if (proof !== undefined && (proof === null || typeof proof !== 'object' || Array.isArray(proof))) throw new Error('Client proof must contain a key ID and key.');
                    if ((proof?.keyId !== undefined && typeof proof.keyId !== 'string') || (proof?.key !== undefined && typeof proof.key !== 'string')) throw new Error('Client proof key ID and key must be text.');
                    const hasID = present(proof?.keyId), hasKey = present(proof?.key);
                    if (hasID !== hasKey) throw new Error('Complete or clear the partial client proof first.');
                    if (hasKey && !/^[0-9a-f]{64}$/i.test(proof.key)) throw new Error('Client proof key must contain 64 hex characters.');
                }
                for (const entry of clients) {
                    if (present(entry.data.clientProof?.key)) continue;
                    const generated = await Inbound.NativeSettings.requestCredentials({kind: 'openvpn-proof'}, controller.signal);
                    if (!present(generated.keyId) || !/^[0-9a-f]{64}$/i.test(generated.key || '')) throw new Error('The server returned an invalid client proof key.');
                    entry.data.clientProof = {...(entry.data.clientProof || {}), keyId: generated.keyId, key: generated.key};
                }
                const ids = clients.map(entry => entry.data.clientProof.keyId);
                if (new Set(ids).size !== ids.length) throw new Error('Client proof key IDs must be unique.');
            }
            if (controller.signal.aborted) throw new Error('Credential generation timed out. Try again.');
            if (this.protocol !== protocol || JSON.stringify(this.toJson()) !== before) throw new Error('Settings changed during generation. Try again.');
            this.data = data;
            for (const entry of clients) {
                entry.client.data = entry.data;
                if (protocol === 'dnstt') {
                    dormant.set(entry.client, entry.cache);
                    entry.client.innerProtocol = data.inner?.protocol || 'vless';
                }
            }
            if (nextShadow) {
                let state = shadowModes.get(this);
                if (!state) { state = {modes: new Map(), from: ''}; shadowModes.set(this, state); }
                state.from = data.inner.protocol;
                state.modes.set(state.from, nextShadow);
                this.rememberClientBindings?.();
            }
            return true;
        } catch (error) {
            this.generationError = error.name === 'AbortError' ? 'Credential generation timed out. Try again.' : error.message;
            return false;
        } finally {
            clearTimeout(timeout);
            this.generating = false;
        }
    };
})();
