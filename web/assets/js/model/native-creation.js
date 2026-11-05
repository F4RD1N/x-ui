/* Creation helpers extend native forms without changing existing protocol models. */
(() => {
    const clone = value => JSON.parse(JSON.stringify(value));
    const bytes = size => {
        if (!globalThis.crypto?.getRandomValues) throw new Error('Secure credential generation is unavailable in this browser.');
        return globalThis.crypto.getRandomValues(new Uint8Array(size));
    };
    const uuid = () => {
        const value = bytes(16);
        value[6] = (value[6] & 15) | 64;
        value[8] = (value[8] & 63) | 128;
        const hex = Array.from(value, item => item.toString(16).padStart(2, '0')).join('');
        return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
    };
    const base64 = size => btoa(Array.from(bytes(size), item => String.fromCharCode(item)).join(''));
    const pem = (value, label) => typeof value === 'string' && value.includes(`-----BEGIN ${label}-----`) && value.includes(`-----END ${label}-----`);
    const certificate = data => Array.isArray(data.tls?.certificate) ? data.tls.certificate.join('\n') : data.tls?.certificate || '';
    const aeadMethods = ['aes-128-gcm', 'aes-256-gcm', 'chacha20-poly1305', 'xchacha20-poly1305', 'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305', 'aead_aes_128_gcm', 'aead_aes_256_gcm', 'aead_chacha20_poly1305', 'aead_xchacha20_poly1305'];
    const ss2022Sizes = {'2022-blake3-aes-128-gcm': 16, '2022-blake3-aes-256-gcm': 32, '2022-blake3-chacha20-poly1305': 32};
    const generatedInner = new WeakMap();
    const rememberedInner = new WeakMap();
    const accountIdentity = (protocol, account) => protocol === 'vless' ? account.id : protocol === 'socks' ? account.user : account.password;
    const sharedShadowSettings = data => {
        const settings = data.inner?.settings;
        return (data.version || 3) === 3 && data.inner?.protocol === 'shadowsocks' && settings
            && (!Object.prototype.hasOwnProperty.call(settings, 'clients') || (!ss2022Sizes[settings.method] && (settings.clients === null || (Array.isArray(settings.clients) && !settings.clients.length))));
    };

    function appendShadowAccount(data, client) {
        const inner = data.inner;
        if (!inner || !inner.settings || typeof inner.settings !== 'object') throw new Error('Configure an authenticated inner proxy first.');
        const settings = inner.settings;
        if (inner.protocol === 'socks') {
            if (settings.auth !== 'password' || settings.udp === true || !Array.isArray(settings.accounts)) throw new Error('Inner SOCKS requires password accounts and UDP disabled.');
            if (settings.accounts.some(account => account.user === client.email)) throw new Error('The inner username already exists.');
            settings.accounts.push({user: client.email, pass: uuid()});
            client.data.innerUsername = client.email;
        } else if (inner.protocol === 'vless') {
            if (settings.decryption !== 'none' || !Array.isArray(settings.clients)) throw new Error('Configure inner VLESS clients first.');
            if (settings.clients.some(account => account.email === client.email)) throw new Error('The inner client email already exists.');
            const id = uuid();
            if (settings.clients.some(account => account.id === id)) throw new Error('Generated inner UUID already exists. Try again.');
            settings.clients.push({id, email: client.email, level: 0});
        } else if (inner.protocol === 'shadowsocks') {
            if (sharedShadowSettings(data)) {
                if ((!ss2022Sizes[settings.method] && !aeadMethods.includes(String(settings.method).toLowerCase())) || !settings.password) throw new Error('Configure authenticated shared Shadowsocks credentials first.');
                // A new outer identity shares the existing inner PSK. Adding an
                // empty clients list here would turn SS2022 into deny-all mode.
                return;
            }
            if (!Array.isArray(settings.clients) || !settings.clients.length) throw new Error('Import per-client Shadowsocks credentials before adding a client.');
            if (settings.clients.some(account => account.email === client.email)) throw new Error('The inner client email already exists.');
            const method = String(settings.method || settings.clients[0].method || '').toLowerCase();
            if (method === '2022-blake3-chacha20-poly1305') throw new Error('Inner multi-user SS2022 requires an AES-GCM method.');
            const size = ss2022Sizes[method];
            if (!size && !aeadMethods.includes(method)) throw new Error('Choose an authenticated Shadowsocks cipher first.');
            const password = base64(size || 32);
            if (settings.clients.some(account => account.password === password)) throw new Error('Generated inner key already exists. Try again.');
            const account = {email: client.email, password, level: 0};
            if (!size) account.method = method;
            else if (settings.uuidIdentityKeys === true) account.uuidIdentityKeys = false;
            settings.clients.push(account);
        } else throw new Error('Choose an authenticated inner proxy first.');
    }

    // Complete credentials off-form, then append once. Failed, stale or repeated
    // requests leave the current clients and server material untouched.
    Inbound.NativeSettings.prototype.addGeneratedClient = async function () {
        if (this.generating) return null;
        this.generating = true;
        this.generationError = '';
        this.generationNotice = '';
        const before = JSON.stringify(this.toJson());
        const protocol = this.protocol;
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 15000);
        try {
            let client;
            for (let attempt = 0; attempt < 8; attempt++) {
                const candidate = this.newClient();
                if (candidate.email && candidate.subId && !this.clients.some(existing => existing.email === candidate.email || existing.subId === candidate.subId)) {
                    client = candidate;
                    break;
                }
            }
            if (!client) throw new Error('Could not create a unique client identity. Try again.');
            const data = clone(this.data);
            switch (protocol) {
                case 'anytls': client.data.password = uuid(); break;
                case 'mieru': client.data.username = uuid(); client.data.password = uuid(); break;
                case 'dnstt':
                    if (data.inner?.protocol === 'socks') {
                        client.data.username = client.email;
                        client.data.password = uuid();
                    } else client.data.id = uuid();
                    break;
                case 'shadowtls':
                    if ((data.version || 3) === 3) client.data.password = uuid();
                    else delete client.data.password;
                    appendShadowAccount(data, client);
                    break;
                case 'orbit': {
                    const request = {kind: 'orbit'};
                    if (data.security === 'reality') request.realityPrivateKey = data.reality?.privateKey || '';
                    else request.certificate = certificate(data);
                    if (!request.certificate && !request.realityPrivateKey) throw new Error('Configure the server certificate or Reality key first.');
                    const result = await Inbound.NativeSettings.requestCredentials(request, controller.signal);
                    if (!/^vck1_[A-Za-z0-9_-]{86}$/.test(result.key || '')) throw new Error('The server returned an invalid client key.');
                    client.data.key = result.key;
                    break;
                }
                case 'openvpn': {
                    if (!data.certificates?.ca || !data.clientExport?.issuerPrivateKey) throw new Error('Import the CA certificate and issuer private key to issue another client.');
                    const request = {
                        kind: 'openvpn-client', email: client.email,
                        caCertificate: data.certificates.ca, issuerPrivateKey: data.clientExport.issuerPrivateKey,
                        serverKey: data.certificates.tlsCryptV2 || '', clientProofRequired: data.clientProof?.required === true,
                    };
                    const result = await Inbound.NativeSettings.requestCredentials(request, controller.signal);
                    const issued = result?.client;
                    if (!issued || typeof issued.commonName !== 'string' || !issued.commonName || !pem(issued.certificate, 'CERTIFICATE') || !(pem(issued.privateKey, 'PRIVATE KEY') || pem(issued.privateKey, 'RSA PRIVATE KEY') || pem(issued.privateKey, 'EC PRIVATE KEY'))) throw new Error('The server returned incomplete client credentials.');
                    if (request.serverKey && !pem(issued.tlsCryptV2, 'OpenVPN tls-crypt-v2 client key')) throw new Error('The server did not return a wrapped client key.');
                    if (request.clientProofRequired && (!issued.clientProof?.keyId || !/^[0-9a-f]{64}$/i.test(issued.clientProof?.key || ''))) throw new Error('The server did not return a valid client proof key.');
                    // The form owns identity/accounting metadata. Only issued
                    // credential fields are accepted from this response.
                    for (const key of ['commonName', 'certificate', 'privateKey', 'tlsCryptV2', 'clientProof']) {
                        if (issued[key] !== undefined) client.data[key] = clone(issued[key]);
                    }
                    break;
                }
                default: throw new Error('Unsupported native protocol.');
            }
            if (controller.signal.aborted) throw new Error('Client generation timed out. Try again.');
            if (this.protocol !== protocol || JSON.stringify(this.toJson()) !== before) throw new Error('Settings changed during generation. Try again.');
            const errors = client.validationErrors;
            if (errors.length) throw new Error(errors.join('; '));
            const credential = Inbound.nativeCredentialId(protocol, client);
            if (credential && this.clients.some(existing => Inbound.nativeCredentialId(protocol, existing) === credential)) throw new Error('Generated credentials already exist. Try again.');
            if (protocol === 'shadowtls') this.data = data;
            this.clients.push(client);
            if (protocol === 'shadowtls') {
                const inner = data.inner;
                const list = inner.protocol === 'socks' ? inner.settings.accounts : inner.settings.clients;
                if (Array.isArray(list) && list.length) {
                    const binding = {protocol: inner.protocol, account: clone(list[list.length - 1])};
                    generatedInner.set(client, binding);
                    rememberedInner.set(client, binding);
                }
            }
            return client;
        } catch (error) {
            this.generationError = error.name === 'AbortError' ? 'Client generation timed out. Try again.' : error.message;
            return null;
        } finally {
            clearTimeout(timeout);
            this.generating = false;
        }
    };

    Inbound.NativeSettings.prototype.rememberClientBindings = function () {
        if (this.protocol !== 'shadowtls') return;
        const inner = this.data.inner;
        const list = inner?.protocol === 'socks' ? inner.settings?.accounts : inner?.settings?.clients;
        if (!Array.isArray(list)) return;
        for (const client of this.clients) {
            const matches = list.filter(account => inner.protocol === 'socks' ? account.user === client.data.innerUsername : account.email === client.email);
            if (matches.length === 1) rememberedInner.set(client, {protocol: inner.protocol, account: clone(matches[0])});
        }
    };

    // Email edits change panel identity, not cryptographic credentials. Match
    // only previously remembered accounts by their unchanged secret/UUID.
    Inbound.NativeSettings.prototype.syncGeneratedClientBindings = function () {
        if (this.protocol !== 'shadowtls') return true;
        const data = clone(this.data), inner = data.inner;
        const list = inner?.protocol === 'socks' ? inner.settings?.accounts : inner?.settings?.clients;
        if (sharedShadowSettings(data)) return true;
        if (!Array.isArray(list)) throw new Error('Configure the inner client accounts first.');
        const emails = this.clients.map(client => client.email);
        if (new Set(emails).size !== emails.length) throw new Error('Client emails must be unique.');
        const updates = [];
        for (const client of this.clients) {
            const saved = rememberedInner.get(client);
            if (!saved) continue;
            if (saved.protocol !== inner.protocol) throw new Error('The inner protocol changed. Reopen the form before changing client identities.');
            const identity = accountIdentity(saved.protocol, saved.account);
            const matches = list.filter(account => accountIdentity(saved.protocol, account) === identity);
            if (!identity || matches.length !== 1) throw new Error('The inner credential binding changed. Reopen the form before saving.');
            const account = matches[0];
            if (inner.protocol === 'socks') {
                if (client.data.innerUsername !== account.user) throw new Error('The inner username changed. Reopen the form before saving.');
                continue;
            }
            if (account.email !== saved.account.email && account.email !== client.email) throw new Error('The inner email binding changed. Reopen the form before saving.');
            if (list.some(other => other !== account && other.email === client.email)) throw new Error('The inner client email already exists.');
            account.email = client.email;
            updates.push({client, binding: {protocol: inner.protocol, account: clone(account)}});
        }
        this.data = data;
        for (const {client, binding} of updates) {
            rememberedInner.set(client, binding);
            if (generatedInner.has(client)) generatedInner.set(client, binding);
        }
        return true;
    };

    // The existing addClient route accepts only this generated account subset;
    // server keys, transport and other users must not be included in its merge.
    Inbound.NativeSettings.prototype.generatedClientInner = function (client) {
        const created = generatedInner.get(client);
        if (this.protocol !== 'shadowtls' || !this.clients.includes(client) || !created) return null;
        if (this.data.inner?.protocol !== created.protocol) throw new Error('The inner protocol changed. Create the client again.');
        const account = clone(created.account);
        if (created.protocol === 'socks') {
            if (client.data.innerUsername !== account.user) throw new Error('The generated inner username changed. Create the client again.');
            return {protocol: created.protocol, settings: {accounts: [account]}};
        }
        account.email = client.email;
        return {protocol: created.protocol, settings: {clients: [account]}};
    };
})();
