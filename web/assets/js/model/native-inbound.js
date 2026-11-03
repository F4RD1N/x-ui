/* Native protocol form models. Loaded after inbound.js; existing protocol models stay independent. */
(() => {
    const clone = value => JSON.parse(JSON.stringify(value));
    const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
    const uuid = value => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value || '');
    const nativeTelegramId = value => {
        if (value === undefined || value === null || (typeof value === 'string' && value.trim() === '')) return 0;
        if (typeof value === 'string') {
            const text = value.trim();
            if (!/^[+-]?\d+$/.test(text)) throw new Error('Telegram ID must be a whole number.');
            value = Number(text);
        }
        if (typeof value !== 'number' || !Number.isSafeInteger(value)) throw new Error('Telegram ID must be a safe whole number.');
        return value;
    };
    const field = (path, label, type = 'text', extra = {}) => ({path, label, type, ...extra});
    const number = (path, label, min, max) => field(path, label, 'number', {min, max});
    const select = (path, label, options) => field(path, label, 'select', {options});
    const protocols = {
        anytls: {
            defaults: () => ({handshakeTimeout: 10, maxStreams: 128}),
            fields: [number('handshakeTimeout', 'Handshake timeout (seconds)', 0, 300), number('maxStreams', 'Maximum streams', 0, 1024)],
            help: 'AnyTLS uses the TCP listener and TLS certificate below. UUID hash compatibility changes authentication format; enable it only for matching clients.',
        },
        mieru: {
            defaults: () => ({transport: 'tcp', handshakeTimeout: 10}),
            fields: [select('transport', 'Transport', ['tcp', 'udp']), number('handshakeTimeout', 'Handshake timeout (seconds)', 0, 300)],
            help: 'Mieru owns its TCP or UDP transport. UUID metadata compatibility is optional per client.',
        },
        dnstt: {
            defaults: () => ({domain: '', privateKey: '', inner: {protocol: 'vless'}, mtu: 1232, handshakeTimeout: 30, maxSessions: 256, maxStreams: 128}),
            fields: [field('domain', 'Tunnel name'), field('privateKey', 'Private key (64 hex)', 'password'), select('inner.protocol', 'Inner protocol', ['vless', 'socks']), number('mtu', 'DNS payload MTU', 512, 4096), number('handshakeTimeout', 'Handshake timeout (seconds)', 0, 300), number('maxSessions', 'Maximum sessions', 1, 4096), number('maxStreams', 'Maximum streams', 1, 1024)],
            help: 'Delegate this domain to the server DNS listener. VLESS is the default authenticated inner proxy. SOCKS inner mode carries TCP only. Keep the private key unchanged when editing or restoring.',
        },
        openvpn: {
            defaults: () => ({network: 'udp', certificates: {ca: '', cert: '', key: ''}, crypto: {dataCiphers: ['AES-256-GCM', 'AES-128-GCM', 'CHACHA20-POLY1305'], authHash: 'SHA256'}, tunnel: {ipv4: '10.88.0.0/24', dns: [], mtu: 1400}, clientProof: {required: false}, limits: {maxSessions: 128, maxSessionsPerIP: 16, maxFlowsPerSession: 256, handshakeSeconds: 15, idleSeconds: 120}, renegotiationSeconds: 3600}),
            fields: [select('network', 'Transport', ['udp', 'tcp']), field('certificates.ca', 'CA certificate PEM', 'textarea'), field('certificates.cert', 'Server certificate PEM', 'textarea'), field('certificates.key', 'Server private key PEM', 'textarea'), field('certificates.tlsAuth', 'Optional tls-auth key', 'textarea'), select('certificates.keyDirection', 'tls-auth key direction', ['', 0, 1]), field('certificates.tlsCrypt', 'Optional tls-crypt key', 'textarea'), field('certificates.tlsCryptV2', 'Optional tls-crypt-v2 server key', 'textarea'), field('crypto.dataCiphers', 'Data ciphers (one per line)', 'lines'), field('crypto.authHash', 'Authentication hash'), field('tunnel.ipv4', 'IPv4 tunnel subnet'), field('tunnel.ipv6', 'Optional IPv6 subnet'), field('tunnel.dns', 'DNS servers (one per line)', 'lines'), number('tunnel.mtu', 'Tunnel MTU', 1280, 8000), field('clientProof.required', 'Require client proof for every client', 'boolean'), number('limits.maxSessions', 'Maximum sessions', 0, 4096), number('limits.maxSessionsPerIP', 'Sessions per source IP', 0, 4096), number('limits.maxFlowsPerSession', 'Flows per session', 0, 4096), number('limits.handshakeSeconds', 'Handshake timeout (seconds)', 0, 120), number('limits.idleSeconds', 'Idle timeout (seconds)', 0, 86400), number('renegotiationSeconds', 'Renegotiation interval (seconds)', 0, 86400)],
            help: 'OpenVPN handles its own TLS and TCP/UDP transport. Each client common name must match its issued certificate. Optional client proof requires a matching client key; it does not replace certificate validation. Configure at most one TLS control-channel key format.',
        },
        shadowtls: {
            defaults: () => ({version: 3, strict: true, handshake: {address: '', port: 443}, handshakeTimeout: 10, inner: {protocol: 'socks', settings: {auth: 'password', accounts: [{user: '', pass: ''}], udp: false}}}),
            fields: [select('version', 'ShadowTLS version', [1, 2, 3]), field('strict', 'Strict verification (v3)', 'boolean'), field('password', 'Shared outer password (v2)', 'password', {show: data => data.version === 2}), field('handshake.address', 'Handshake TLS target'), number('handshake.port', 'Handshake target port', 1, 65535), number('handshakeTimeout', 'Handshake timeout (seconds)', 0, 300), select('inner.protocol', 'Authenticated inner proxy', ['socks', 'vless', 'shadowsocks']), field('inner.settings', 'Inner proxy settings JSON', 'json')],
            help: 'ShadowTLS is a TCP carrier. An authenticated inner SOCKS, VLESS or encrypted Shadowsocks proxy is required. VLESS Vision is not supported inside this carrier. v1 has no outer password; v2 uses one shared password; v3 uses the outer client passwords. For v1/v2 the client list stores subscription identities bound to inner accounts; account changes restart the inner listener.',
        },
        orbit: {
            defaults: () => ({transport: 'tcp', tls: {certificate: [], key: []}, host: '', path: '/core', security: '', handshakeTimeout: 15, maxSessions: 1000, maxFlows: 128, udpIdleTimeout: 60}),
            fields: [select('transport', 'Transport', ['tcp', 'quic', 'ws', 'wss']), select('security', 'TCP security', ['', 'reality']), field('tls.certificate', 'Pinned inner certificate PEM', 'lines', {show: data => data.security !== 'reality'}), field('tls.key', 'Inner private key PEM', 'lines', {show: data => data.security !== 'reality'}), field('outerTls.certificate', 'Outer WSS certificate PEM', 'lines', {show: data => data.transport === 'wss'}), field('outerTls.key', 'Outer WSS private key PEM', 'lines', {show: data => data.transport === 'wss'}), field('host', 'WebSocket host', 'text', {show: data => ['ws', 'wss'].includes(data.transport)}), field('path', 'WebSocket path', 'text', {show: data => ['ws', 'wss'].includes(data.transport)}), field('reality.privateKey', 'Reality private key', 'password', {show: data => data.security === 'reality'}), field('reality.serverNames', 'Reality server names (one per line)', 'lines', {show: data => data.security === 'reality'}), field('reality.shortIds', 'Reality short IDs (one per line)', 'lines', {show: data => data.security === 'reality'}), field('reality.dest', 'Reality destination host:port', 'text', {show: data => data.security === 'reality'}), number('handshakeTimeout', 'Handshake timeout (seconds)', 0, 90), number('maxSessions', 'Maximum sessions', 0, 10000), number('maxFlows', 'Maximum flows', 0, 4096), number('udpIdleTimeout', 'UDP idle timeout (seconds)', 0, 3600)],
            help: 'Orbit uses its own transport and TLS. Each vck1 client key must contain the pin of the configured inner certificate. WSS requires a separate outer TLS certificate. Reality is available with TCP only.',
        },
    };
    const getPath = (data, path) => path.split('.').reduce((value, part) => value?.[part], data);
    const setPath = (data, path, value) => {
        const parts = path.split('.');
        let target = data;
        parts.slice(0, -1).forEach(part => { if (!object(target[part])) target[part] = {}; target = target[part]; });
        if (value === undefined) delete target[parts[parts.length - 1]];
        else target[parts[parts.length - 1]] = value;
    };
    const readValue = (data, descriptor) => {
        const value = getPath(data, descriptor.path);
        if (descriptor.type === 'lines') return Array.isArray(value) ? value.join('\n') : value || '';
        if (descriptor.type === 'json') return value === undefined ? (descriptor.array ? '[]' : '{}') : JSON.stringify(value, null, 2);
        return value === undefined ? '' : value;
    };
    const writeValue = (data, descriptor, raw) => {
        let value = raw;
        if (descriptor.type === 'number') {
            if (raw === null || raw === '') value = undefined;
            else if (!Number.isFinite(Number(raw))) throw new Error(`${descriptor.label} must be a number`);
            else value = Number(raw);
        } else if (descriptor.type === 'lines') value = String(raw).split(/\r?\n/).filter(line => line.length);
        else if (descriptor.type === 'json') { value = JSON.parse(raw); if (descriptor.array ? !Array.isArray(value) : !object(value)) throw new Error(`${descriptor.label} must be ${descriptor.array ? 'an array' : 'an object'}`); }
        else if (descriptor.type === 'boolean') value = raw === true;
        else if (raw === '') value = undefined;
        setPath(data, descriptor.path, value);
    };
    const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
    const mergeUntouched = (before, current, generated) => {
        if (same(before, current)) return generated === undefined ? undefined : clone(generated);
        if (object(before) && object(current) && object(generated)) {
            const result = clone(generated);
            new Set([...Object.keys(before), ...Object.keys(current)]).forEach(key => {
                if (!Object.prototype.hasOwnProperty.call(current, key)) delete result[key];
                else {
                    const value = mergeUntouched(before[key], current[key], generated[key]);
                    if (value === undefined) delete result[key];
                    else result[key] = value;
                }
            });
            return result;
        }
        return current === undefined ? undefined : clone(current);
    };
    const clientDefaults = (protocol, inner) => {
        switch (protocol) {
            case 'anytls': return {password: RandomUtil.randomUUID(), level: 0};
            case 'mieru': return {username: RandomUtil.randomUUID(), password: RandomUtil.randomUUID(), level: 0};
            case 'dnstt': return inner === 'socks' ? {username: RandomUtil.randomLowerAndNum(16), password: RandomUtil.randomUUID(), level: 0} : {id: RandomUtil.randomUUID(), level: 0};
            case 'openvpn': return {commonName: '', level: 0};
            case 'shadowtls': return {password: RandomUtil.randomUUID(), level: 0};
            case 'orbit': return {key: '', level: 0};
        }
    };
    Inbound.nativeCredentialId = (protocol, client) => {
        const data = client instanceof Inbound.NativeClient ? client.data : client;
        if (!data) return '';
        switch (protocol) {
            case 'anytls': return (data.password || '') + (uuid(data.password) && data.uuidHashMiddle === true ? ':uuid-middle' : '');
            case 'shadowtls': return data.password || '';
            case 'mieru': return data.username || '';
            case 'dnstt': return data.id || data.username || '';
            case 'openvpn': return data.commonName || '';
            case 'orbit': return data.key || '';
            default: return data.id || '';
        }
    };
    // Native CRUD routes use a stable email token, never credentials in URLs.
    Inbound.nativeClientId = (protocol, client) => {
        const email = client?.email || '';
        const bytes = new TextEncoder().encode(email);
        const encoded = btoa(Array.from(bytes, byte => String.fromCharCode(byte)).join(''));
        return 'email:' + encoded.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    };
    Inbound.subscriptionNeedsJSON = (inbounds, subId) => {
        if (!subId) return false;
        return (inbounds || []).some(inbound => {
            if (!Inbound.NativeSettings.supports(inbound.protocol)) return false;
            try {
                const settings = typeof inbound.settings === 'string' ? JSON.parse(inbound.settings) : inbound.settings;
                return Array.isArray(settings?.clients) && settings.clients.some(client => client?.subId === subId);
            } catch (_) { return false; }
        });
    };
    Inbound.compatibilityErrors = (protocol, clients, method) => {
        const flag = {vmess: 'rawUuidAuth', trojan: 'uuidHashPrefix', shadowsocks: 'uuidIdentityKeys'}[protocol];
        if (!flag) return [];
        const errors = [];
        (clients || []).forEach((client, index) => {
            if (client[flag] !== undefined && typeof client[flag] !== 'boolean') errors.push(`Client ${index + 1}: ${flag} must be true or false`);
            if (flag === 'uuidIdentityKeys' && client[flag] === true && !['2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305'].includes(method)) errors.push('UUID identity key import requires an SS2022 method');
        });
        return errors;
    };
    Inbound.NativeClient = class extends Inbound.ClientBase {
        constructor(protocol, json, inner = 'vless', shadowVersion = 3) {
            super(...Inbound.ClientBase.commonArgsFromJson(json || {}));
            this.protocol = protocol;
            this.shadowVersion = shadowVersion || 3;
            this.innerProtocol = inner || 'vless';
            this.data = clone(json === undefined ? clientDefaults(protocol, inner) : json);
            this.fieldError = '';
        }
        get fields() {
            const fields = [number('level', 'Policy level', 0, 4294967295)];
            switch (this.protocol) {
                case 'anytls': fields.unshift(field('password', 'Password', 'password'), field('uuidHashMiddle', 'UUID hash authentication compatibility', 'boolean')); break;
                case 'mieru': fields.unshift(field('username', 'Username'), field('password', 'Password', 'password'), field('uuidMetadataTrailer', 'UUID metadata compatibility', 'boolean')); break;
                case 'dnstt':
                    if (this.innerProtocol === 'socks') fields.unshift(field('username', 'SOCKS username'), field('password', 'SOCKS password', 'password'));
                    else fields.unshift(field('id', 'VLESS UUID'));
                    break;
                case 'openvpn': fields.unshift(field('commonName', 'Certificate common name'), field('username', 'Optional username'), field('password', 'Optional password', 'password'), field('clientProof.keyId', 'Optional client proof key ID'), field('clientProof.key', 'Optional client proof key (64 hex)', 'password'), field('certificate', 'Client certificate', 'textarea'), field('privateKey', 'Client private key', 'textarea'), field('tlsCryptV2', 'Client tls-crypt-v2 key', 'textarea')); break;
                case 'shadowtls':
                    if (this.innerProtocol === 'socks') fields.unshift(field('innerUsername', 'Inner SOCKS username'));
                    if (this.shadowVersion === 3) fields.unshift(field('password', 'Outer password (v3)', 'password'), field('requireUuidSessionId', 'Require UUID session ID compatibility', 'boolean'));
                    break;
                case 'orbit': fields.unshift(field('key', 'Client key (vck1)', 'password'), number('expiresAt', 'Optional expiry (Unix seconds)', 0, Number.MAX_SAFE_INTEGER)); break;
            }
            return fields;
        }
        get delayedStart() { return this.expiryTime < 0; }
        set delayedStart(enabled) { this.expiryTime = enabled ? -86400000 : 0; }
        get delayedExpireDays() { return this.expiryTime < 0 ? this.expiryTime / -86400000 : 0; }
        set delayedExpireDays(days) { this.expiryTime = -Math.max(0, Number(days) || 0) * 86400000; }
        fieldValue(descriptor) { return readValue(this.data, descriptor); }
        setField(descriptor, raw) {
            try { const data = clone(this.data); writeValue(data, descriptor, raw); this.data = data; this.fieldError = ''; }
            catch (error) { this.fieldError = error.message; }
        }
        get validationErrors() {
            const errors = this.fieldError ? [this.fieldError] : [];
            try { nativeTelegramId(this.tgId); } catch (error) { errors.push(error.message); }
            const data = this.data;
            if (typeof this.email !== 'string' || !this.email.trim()) errors.push('A unique client email is required');
            this.fields.forEach(descriptor => {
                const value = getPath(data, descriptor.path);
                if (value !== undefined && descriptor.type === 'boolean' && typeof value !== 'boolean') errors.push(`${descriptor.label} must be true or false`);
            });
            const require = (key, label) => { if (typeof data[key] !== 'string' || !data[key]) errors.push(`${label} is required`); };
            if (['anytls', 'mieru'].includes(this.protocol) || (this.protocol === 'shadowtls' && this.shadowVersion === 3)) require('password', 'Password');
            if (this.protocol === 'mieru') { require('username', 'Username'); if (data.uuidMetadataTrailer && !uuid(data.username)) errors.push('UUID metadata compatibility requires a UUID username'); }
            if (this.protocol === 'shadowtls' && this.shadowVersion === 3 && data.requireUuidSessionId && !uuid(data.password)) errors.push('UUID session ID compatibility requires a UUID password');
            if (this.protocol === 'dnstt') {
                if (this.innerProtocol === 'socks') { require('username', 'SOCKS username'); require('password', 'SOCKS password'); }
                else if (!uuid(data.id) || /^0{8}-0{4}-0{4}-0{4}-0{12}$/.test(data.id)) errors.push('A nonzero VLESS UUID is required');
            }
            if (this.protocol === 'openvpn') {
                require('commonName', 'Certificate common name');
                if (!!data.username !== !!data.password) errors.push('OpenVPN username and password must be supplied together');
                if (data.clientProof && (data.clientProof.keyId || data.clientProof.key)) {
                    if (!data.clientProof.keyId) errors.push('Client proof key ID is required');
                    if (!/^[0-9a-f]{64}$/i.test(data.clientProof.key || '')) errors.push('Client proof key must contain 64 hex characters');
                }
            }
            if (this.protocol === 'orbit' && !/^vck1_[A-Za-z0-9_-]{86}$/.test(data.key || '')) errors.push('A valid 91-character vck1 client key is required');
            if (data.level !== undefined && (!Number.isInteger(data.level) || data.level < 0 || data.level > 4294967295)) errors.push('Policy level must be an unsigned 32-bit integer');
            return errors;
        }
        toJson() {
            const data = clone(this.data);
            if (this.protocol === 'openvpn' && object(data.clientProof) && !Object.keys(data.clientProof).length) delete data.clientProof;
            let tgId;
            try { tgId = nativeTelegramId(this.tgId); }
            catch (_) {
                // Keep invalid input visible to validation without breaking
                // Vue's JSON preview. A string cannot pass the server's int64
                // decoder if a caller bypasses the form's save guard.
                tgId = typeof this.tgId === 'string' ? this.tgId : String(this.tgId);
            }
            return {...data, ...this._clientBaseToJson(), tgId};
        }
    };
    Inbound.NativeSettings = class extends Inbound.Settings {
        static supports(protocol) { return Object.prototype.hasOwnProperty.call(protocols, protocol); }
        static isOrbitDNSHost(value) {
            return typeof value === 'string' && value.length > 0 && value.length <= 253 && /[a-z]/i.test(value)
                && value.split('.').every(label => label.length > 0 && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label));
        }
        static numericServerAddress(value) {
            if (typeof value !== 'string') return '';
            const text = value.trim().replace(/^\[([^\]]+)\]$/, '$1');
            if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(text) && text.split('.').every(part => Number(part) <= 255 && (part.length === 1 || part[0] !== '0'))) return text;
            if (text.includes(':')) {
                try { return new URL(`http://[${text}]/`).hostname.slice(1, -1); } catch (_) { /* Invalid IPv6 is not an identity. */ }
            }
            return '';
        }
        static canonicalServerIdentity(value) {
            if (typeof value !== 'string') return '';
            const text = value.trim().replace(/\.$/, '');
            return Inbound.NativeSettings.numericServerAddress(text) || text.toLowerCase();
        }
        static async requestCredentials(request, signal) {
            const prefix = typeof basePath === 'string' ? basePath : '/';
            const response = await fetch(prefix.replace(/\/?$/, '/') + 'panel/api/server/native/credentials', {
                method: 'POST', credentials: 'same-origin', cache: 'no-store', signal,
                headers: {'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest'},
                body: JSON.stringify(request),
            });
            if (!response.ok) throw new Error('Could not generate settings. Check your panel session.');
            const result = await response.json();
            if (!result?.success || !object(result.obj)) throw new Error(result?.msg || 'Could not generate settings.');
            return result.obj;
        }
        static mergeGeneratedProfile(protocol, generated, before, current) {
            if (generated.protocol !== protocol || !object(generated.settings) || !Array.isArray(generated.settings.clients) || generated.settings.clients.length !== 1) throw new Error('The generated settings were incomplete. Try again.');
            if (current.settings.clients?.length !== 1) throw new Error('Client credentials changed. Your entries were kept.');
            const protectedPaths = ['privateKey', 'tls', 'outerTls', 'certificates', 'reality.privateKey', 'reality.shortIds', 'inner', 'clientExport.ca', 'clientExport.issuerPrivateKey'];
            if (protectedPaths.some(path => !same(getPath(before.settings, path), getPath(current.settings, path)))) throw new Error('Connection credentials changed. Your entries were kept.');
            const beforeClient = before.settings.clients[0], currentClient = current.settings.clients[0];
            if (['id', 'username', 'password', 'key', 'commonName', 'certificate', 'privateKey', 'tlsCryptV2', 'clientProof', 'innerUsername'].some(key => !same(beforeClient[key], currentClient[key]))) throw new Error('Client credentials changed. Your entries were kept.');
            if (protocol === 'anytls' && !same(before.streamSettings?.tlsSettings?.certificates, current.streamSettings?.tlsSettings?.certificates)) throw new Error('Certificates changed. Your entries were kept.');
            const beforeSettings = {...before.settings}, currentSettings = {...current.settings};
            delete beforeSettings.clients;
            delete currentSettings.clients;
            if (beforeSettings.clientExport === undefined && object(currentSettings.clientExport)) beforeSettings.clientExport = {};
            const settings = mergeUntouched(beforeSettings, currentSettings, generated.settings);
            // Only the form supplies deployment values. Generated trust and
            // account material may be added alongside those explicit choices.
            for (const path of ['domain', 'handshake.address', 'handshake.port', 'host', 'clientExport.serverName', 'clientExport.address', 'clientExport.resolvers', 'tunnel.dns', 'reality.serverNames', 'reality.dest']) {
                const value = getPath(currentSettings, path);
                if (value !== undefined) setPath(settings, path, clone(value));
                else if (getPath(settings, path) !== undefined) setPath(settings, path, undefined);
            }
            if (['anytls', 'orbit'].includes(protocol) && currentSettings.clientExport?.serverName) settings.clientExport.serverName = Inbound.NativeSettings.canonicalServerIdentity(currentSettings.clientExport.serverName);
            if (protocol === 'orbit' && currentSettings.clientExport?.address) settings.clientExport.address = Inbound.NativeSettings.canonicalServerIdentity(currentSettings.clientExport.address);
            settings.clients = [mergeUntouched(beforeClient, currentClient, generated.settings.clients[0])];
            const oldEmail = generated.settings.clients[0].email, newEmail = currentClient.email;
            settings.clients[0].email = newEmail;
            settings.clients[0].subId = currentClient.subId;
            if (protocol === 'shadowtls' && oldEmail !== newEmail) {
                (settings.inner?.settings?.clients || []).forEach(client => { if (client.email === oldEmail) client.email = newEmail; });
            }
            return {...current, settings, streamSettings: generated.streamSettings ? mergeUntouched(before.streamSettings, current.streamSettings, generated.streamSettings) : current.streamSettings};
        }
        constructor(protocol, json) {
            super(protocol);
            if (!Inbound.NativeSettings.supports(protocol)) throw new Error('Unknown native inbound protocol');
            if (json !== undefined && !object(json)) throw new Error('Native inbound settings must be an object');
            const data = clone(json === undefined ? protocols[protocol].defaults() : json);
            if (data.clients !== undefined && !Array.isArray(data.clients)) throw new Error('Native inbound clients must be an array');
            this.clients = (data.clients || (json === undefined ? [clientDefaults(protocol, data.inner?.protocol)] : [])).map(client => {
                if (!object(client)) throw new Error('Each native inbound client must be an object');
                return new Inbound.NativeClient(protocol, client, data.inner?.protocol, data.version);
            });
            delete data.clients;
            this.data = data;
            this.advancedError = '';
            this.invalidAdvancedJSON = null;
            this.fieldError = '';
            this.generating = false;
            this.generationError = '';
            this.generationNotice = '';
            this.generatedPublicKey = '';
            this.needsProfile = json === undefined;
            this.profileAttempted = false;
            this.profileSnapshot = '';
            this.modeDefaultsPending = false;
            this.modeDefaultsFailed = false;
        }
        get help() {
            const text = protocols[this.protocol].help;
            return this.protocol === 'orbit' && this.data.transport === 'quic' ? text + ' Warning: this QUIC compatibility mode exposes bearer credentials to a passive network observer. Use TCP, WS, WSS or TCP Reality for TLS-protected credentials.' : text;
        }
        get canBulkCreate() { return ['anytls', 'mieru', 'dnstt'].includes(this.protocol); }
        get profileRequiresIdentity() { return ['anytls', 'orbit'].includes(this.protocol); }
        get profileIdentityError() {
            if (!this.needsProfile) return '';
            if (this.protocol === 'anytls') {
                const name = typeof this.data.clientExport?.serverName === 'string' ? this.data.clientExport.serverName.trim().replace(/\.$/, '') : '';
                if (!Inbound.NativeSettings.isOrbitDNSHost(name) && !Inbound.NativeSettings.numericServerAddress(name)) return 'Enter a client server name or IP before generating credentials.';
            }
            if (this.protocol === 'orbit') {
                const address = Inbound.NativeSettings.numericServerAddress(this.data.clientExport?.address);
                if (!address || ['0.0.0.0', '::'].includes(address)) return 'Enter a numeric client server address before generating credentials.';
            }
            return '';
        }
        get fields() {
            const fields = protocols[this.protocol].fields.filter(descriptor => !descriptor.show || descriptor.show(this.data));
            if (['anytls', 'openvpn'].includes(this.protocol)) fields.push(field('clientExport.serverName', 'Client server name'), field('clientExport.ca', 'Client CA certificate', 'textarea'));
            if (this.protocol === 'orbit' && ['ws', 'wss'].includes(this.data.transport)) fields.push(field('clientExport.serverName', 'Client server name'));
            if (this.protocol === 'orbit') fields.push(field('clientExport.address', 'Client server address'));
            if (this.protocol === 'openvpn') fields.push(field('clientExport.issuerPrivateKey', 'CA signing key', 'textarea'));
            if (this.protocol === 'dnstt') fields.push(field('clientExport.resolvers', 'DNS resolvers JSON', 'json', {array: true}));
            return fields;
        }
        newClient() { return new Inbound.NativeClient(this.protocol, undefined, this.data.inner?.protocol, this.data.version); }
        cloneForNewInbound() {
            const copy = new Inbound.NativeSettings(this.protocol, this.toJson());
            const emails = new Map();
            copy.clients.forEach(client => {
                const oldEmail = client.email;
                client.email = RandomUtil.randomLowerAndNum(12);
                client.subId = RandomUtil.randomLowerAndNum(16);
                client.created_at = undefined;
                client.updated_at = undefined;
                emails.set(oldEmail, client.email);
            });
            if (copy.protocol === 'shadowtls' && ['vless', 'shadowsocks'].includes(copy.data.inner?.protocol)) {
                (copy.data.inner.settings?.clients || []).forEach(client => { if (emails.has(client.email)) client.email = emails.get(client.email); });
                if (emails.has(copy.data.inner.settings?.email)) copy.data.inner.settings.email = emails.get(copy.data.inner.settings.email);
            }
            return copy;
        }
        fieldValue(descriptor) { return readValue(this.data, descriptor); }
        setField(descriptor, raw) {
            try {
                const data = clone(this.data);
                writeValue(data, descriptor, raw);
                const modeChange = ['transport', 'security', 'inner.protocol', 'version', 'clientProof.required'].includes(descriptor.path);
                if (modeChange && this.rememberModeDefaults) this.rememberModeDefaults();
                this.data = data;
                if (descriptor.path === 'privateKey') this.generatedPublicKey = '';
                this.clients.forEach(client => {client.shadowVersion = data.version || 3; client.innerProtocol = data.inner?.protocol || 'vless';});
                this.fieldError = '';
                if (modeChange && !this.needsProfile) this.modeDefaultsPending = true;
            }
            catch (error) { this.fieldError = error.message; }
        }
        async generateCredentials(kind, client = null) {
            if (this.generating) return false;
            this.generating = true;
            this.generationError = '';
            this.generationNotice = '';
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 15000);
            try {
                const request = {kind};
                if (['orbit', 'openvpn-proof', 'openvpn-tls-crypt-v2'].includes(kind) && (!client || !this.clients.includes(client))) throw new Error('Select a client before generating its credentials.');
                if (kind === 'orbit') {
                    if (this.data.security === 'reality') request.realityPrivateKey = this.data.reality?.privateKey || '';
                    else request.certificate = Array.isArray(this.data.tls?.certificate) ? this.data.tls.certificate.join('\n') : this.data.tls?.certificate || '';
                    if (!request.certificate && !request.realityPrivateKey) throw new Error('Import the Orbit certificate or Reality private key first.');
                }
                if (kind === 'openvpn-tls-crypt-v2') {
                    request.serverKey = this.data.certificates?.tlsCryptV2 || '';
                    if (!request.serverKey) throw new Error('Generate or import the TLS-crypt-v2 server key first.');
                }
                if (kind === 'openvpn-tls-crypt-v2-server' && (this.data.certificates?.tlsAuth || this.data.certificates?.tlsCrypt)) throw new Error('Clear tls-auth and tls-crypt before choosing TLS-crypt-v2.');
                // The existing Axios interceptor form-encodes every request; this endpoint requires strict JSON.
                const generated = await Inbound.NativeSettings.requestCredentials(request, controller.signal);
                if (client && !this.clients.includes(client)) throw new Error('The selected client was removed before generation completed.');
                if (kind === 'orbit') {
                    const certificate = Array.isArray(this.data.tls?.certificate) ? this.data.tls.certificate.join('\n') : this.data.tls?.certificate || '';
                    if ((request.certificate && certificate !== request.certificate) || (request.realityPrivateKey && this.data.reality?.privateKey !== request.realityPrivateKey)) throw new Error('The Orbit certificate or Reality key changed during generation. Generate again for the current identity.');
                }
                if (kind === 'openvpn-tls-crypt-v2' && this.data.certificates?.tlsCryptV2 !== request.serverKey) throw new Error('The server wrapping key changed during generation. Generate again for the current key.');
                const data = clone(this.data);
                const clientData = client ? clone(client.data) : null;
                switch (kind) {
                    case 'dnstt':
                        if (!/^[0-9a-f]{64}$/i.test(generated.privateKey || '') || !/^[0-9a-f]{64}$/i.test(generated.publicKey || '')) throw new Error('Server returned an invalid DNSTT key pair.');
                        data.privateKey = generated.privateKey;
                        this.generatedPublicKey = generated.publicKey;
                        break;
                    case 'orbit':
                        if (!/^vck1_[A-Za-z0-9_-]{86}$/.test(generated.key || '')) throw new Error('Server returned an invalid Orbit client key.');
                        clientData.key = generated.key;
                        break;
                    case 'openvpn-proof':
                        if (!generated.keyId || !/^[0-9a-f]{64}$/i.test(generated.key || '')) throw new Error('Server returned an invalid proof key.');
                        clientData.clientProof = {keyId: generated.keyId, key: generated.key};
                        break;
                    case 'openvpn-tls-crypt-v2':
                        if (typeof generated.clientKey !== 'string' || !generated.clientKey.includes('-----BEGIN ')) throw new Error('Server returned an invalid client wrapping key.');
                        clientData.tlsCryptV2 = generated.clientKey;
                        break;
                    case 'openvpn-tls-crypt-v2-server':
                        if (typeof generated.serverKey !== 'string' || !generated.serverKey.includes('-----BEGIN ')) throw new Error('Server returned an invalid server wrapping key.');
                        setPath(data, 'certificates.tlsCryptV2', generated.serverKey);
                        break;
                    default: throw new Error('Unsupported credential type.');
                }
                this.data = data;
                if (client) client.data = clientData;
                this.generationNotice = 'New credentials are ready. Save to apply.';
                return true;
            } catch (error) {
                this.generationError = error.name === 'AbortError' ? 'Credential generation timed out; existing keys were preserved.' : error.message || 'Credential generation failed.';
                return false;
            } finally { clearTimeout(timeout); this.generating = false; }
        }
        get advancedJSON() { return this.invalidAdvancedJSON === null ? JSON.stringify(this.toJson(), null, 2) : this.invalidAdvancedJSON; }
        set advancedJSON(raw) {
            try {
                const parsed = JSON.parse(raw);
                const settings = new Inbound.NativeSettings(this.protocol, parsed);
                if (this.data.privateKey !== settings.data.privateKey) this.generatedPublicKey = '';
                this.data = settings.data;
                this.clients = settings.clients;
                this.invalidAdvancedJSON = null;
                this.advancedError = '';
                this.fieldError = '';
            } catch (error) { this.invalidAdvancedJSON = raw; this.advancedError = error.message; }
        }
        get validationErrors() { return this.validateSettings(false); }
        get generatedProfileErrors() { return this.validateSettings(true); }
        validateSettings(allowMissingDeployment) {
            const errors = [this.advancedError, this.fieldError].filter(Boolean);
            const data = this.data;
            if (this.needsProfile && this.profileIdentityError) errors.push(this.profileIdentityError);
            if (!this.clients.length && !(this.protocol === 'shadowtls' && (data.version || 3) !== 3)) errors.push('At least one client is required');
            this.clients.forEach((client, index) => client.validationErrors.forEach(error => errors.push(`Client ${index + 1}: ${error}`)));
            const ids = (this.protocol === 'shadowtls' && (data.version || 3) !== 3 ? [] : this.clients.map(client => Inbound.nativeCredentialId(this.protocol, client))).filter(Boolean);
            if (new Set(ids).size !== ids.length) errors.push('Client identities must be unique');
            const emails = this.clients.map(client => client.email?.toLowerCase()).filter(Boolean);
            if (new Set(emails).size !== emails.length) errors.push('Client emails must be unique');
            this.fields.forEach(descriptor => {
                const value = getPath(data, descriptor.path);
                if (value === undefined) return;
                if (descriptor.type === 'number' && (!Number.isInteger(value) || (value !== 0 && (value < descriptor.min || value > descriptor.max)))) errors.push(`${descriptor.label} must be an integer from ${descriptor.min} to ${descriptor.max}`);
                if (descriptor.type === 'select' && !descriptor.options.includes(value) && !(value === '' && ['transport', 'network', 'inner.protocol'].includes(descriptor.path))) errors.push(`${descriptor.label} has an unsupported value`);
                if (descriptor.type === 'boolean' && typeof value !== 'boolean') errors.push(`${descriptor.label} must be true or false`);
            });
            if (this.protocol === 'dnstt') {
                const domain = typeof data.domain === 'string' ? data.domain.replace(/\.$/, '') : '';
                if (!(allowMissingDeployment && (data.domain === undefined || data.domain === '')) && !Inbound.NativeSettings.isOrbitDNSHost(domain)) errors.push('A valid DNS tunnel name is required');
                if (!/^[0-9a-f]{64}$/i.test(data.privateKey || '')) errors.push('DNSTT private key must contain 64 hex characters');
                const socks = data.inner?.protocol === 'socks';
                if (this.clients.some(client => socks ? !client.data.username : !client.data.id)) errors.push('Client credentials must match the selected inner protocol');
                if (socks && this.clients.some(client => (client.totalGB > 0 || client.limitIp > 0) && client.data.username !== client.email)) errors.push('DNSTT SOCKS username must match client email when traffic or IP limits are enabled');
            }
            if (this.protocol === 'openvpn') {
                ['ca', 'cert', 'key'].forEach(key => { if (typeof data.certificates?.[key] !== 'string' || !data.certificates[key].includes('-----BEGIN ')) errors.push(`OpenVPN ${key} PEM is required`); });
                if (['tlsAuth', 'tlsCrypt', 'tlsCryptV2'].filter(key => data.certificates?.[key]).length > 1) errors.push('Choose only one TLS control-channel key format');
                if (data.clientProof?.required && this.clients.some(client => !client.data.clientProof?.keyId || !client.data.clientProof?.key)) errors.push('Every client must have a client proof key when proof is required');
            }
            if (this.protocol === 'shadowtls') {
                const target = data.handshake?.address;
                if (!(allowMissingDeployment && (target === undefined || target === '')) && (typeof target !== 'string' || target !== target.trim() || (!Inbound.NativeSettings.isOrbitDNSHost(target.replace(/\.$/, '')) && !Inbound.NativeSettings.numericServerAddress(target)))) errors.push('A valid TLS handshake target is required');
                if (data.version === 2 && !data.password) errors.push('ShadowTLS v2 requires a shared password');
                if ((data.version || 3) !== 3 && data.inner?.protocol === 'socks' && this.clients.some(client => (client.totalGB > 0 || client.limitIp > 0) && client.data.innerUsername !== client.email)) errors.push('ShadowTLS v1/v2 inner SOCKS username must match client email when traffic or IP limits are enabled');
                const inner = data.inner;
                if (!inner || !['socks', 'vless', 'shadowsocks'].includes(inner.protocol)) errors.push('An authenticated SOCKS, VLESS or encrypted Shadowsocks inner proxy is required');
                else if (inner.protocol === 'socks' && (inner.settings?.auth !== 'password' || !inner.settings?.accounts?.length || inner.settings.accounts.some(account => !account.user || !account.pass) || inner.settings.udp === true)) errors.push('Inner SOCKS requires password accounts and UDP disabled');
                else if (inner.protocol === 'vless' && (inner.settings?.decryption !== 'none' || !inner.settings?.clients?.length || inner.settings.clients.some(client => !uuid(client.id) || client.flow))) errors.push('Inner VLESS requires UUID clients, decryption none, and no Vision flow');
                else if (inner.protocol === 'shadowsocks') {
                    const settings = inner.settings || {};
                    const modern = ['aes-128-gcm', 'aes-256-gcm', 'chacha20-poly1305', 'xchacha20-poly1305', 'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305', 'aead_aes_128_gcm', 'aead_aes_256_gcm', 'aead_chacha20_poly1305', 'aead_xchacha20_poly1305'];
                    const ss2022 = ['2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305'];
                    if (settings.network && settings.network !== 'tcp') errors.push('Inner Shadowsocks currently supports TCP only');
                    if (ss2022.includes(settings.method)) {
                        if (!settings.password || (settings.clients || []).some(client => !client.password)) errors.push('Inner SS2022 requires a base64 server key and each selected user key');
                    } else if (!settings.clients?.length || settings.clients.some(client => !modern.includes(String(client.method || settings.method).toLowerCase()) || !client.password)) errors.push('Inner Shadowsocks requires authenticated AEAD clients; plain and legacy ciphers are unsupported');
                }
            }
            if (this.protocol === 'orbit') {
                if (data.security === 'reality') {
                    if (data.transport !== 'tcp') errors.push('Orbit Reality requires TCP');
                    if (!data.reality?.privateKey || !data.reality?.serverNames?.length || !data.reality?.dest) errors.push('Orbit Reality private key, server names and destination are required');
                } else if (!data.tls?.certificate?.length || !data.tls?.key?.length) errors.push('Orbit inner certificate and key are required');
                if (['ws', 'wss'].includes(data.transport) && !Inbound.NativeSettings.isOrbitDNSHost(data.host)) errors.push('Orbit WebSocket host must be a DNS name without a port');
                if (data.transport === 'wss' && (!data.outerTls?.certificate?.length || !data.outerTls?.key?.length)) errors.push('Orbit WSS outer certificate and key are required');
            }
            return errors;
        }
        toJson() {
            const data = {...clone(this.data), clients: this.clients.map(client => client.toJson())};
            if (this.protocol === 'orbit') {
                // Keep inactive identities in the form for reversible mode
                // changes, but never send incompatible runtime fields.
                if (data.security === 'reality') delete data.tls;
                else delete data.reality;
                if (!['ws', 'wss'].includes(data.transport)) {
                    delete data.host;
                    delete data.path;
                    delete data.outerTls;
                    if (data.clientExport) delete data.clientExport.serverName;
                } else if (data.transport !== 'wss') delete data.outerTls;
            }
            return data;
        }
    };
})();
