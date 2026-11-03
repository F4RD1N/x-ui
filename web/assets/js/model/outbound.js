const Protocols = {
    Freedom: "freedom",
    Blackhole: "blackhole",
    DNS: "dns",
    VMess: "vmess",
    VLESS: "vless",
    Trojan: "trojan",
    Shadowsocks: "shadowsocks",
    Socks: "socks",
    HTTP: "http",
    Wireguard: "wireguard",
    Hysteria: "hysteria",
    Orbit: "orbit",
    DNSTT: "dnstt",
    OpenVPN: "openvpn",
    AnyTLS: "anytls",
    ShadowTLS: "shadowtls",
    Mieru: "mieru"
};

const SSMethods = {
    AES_256_GCM: 'aes-256-gcm',
    AES_128_GCM: 'aes-128-gcm',
    CHACHA20_POLY1305: 'chacha20-poly1305',
    CHACHA20_IETF_POLY1305: 'chacha20-ietf-poly1305',
    XCHACHA20_POLY1305: 'xchacha20-poly1305',
    XCHACHA20_IETF_POLY1305: 'xchacha20-ietf-poly1305',
    BLAKE3_AES_128_GCM: '2022-blake3-aes-128-gcm',
    BLAKE3_AES_256_GCM: '2022-blake3-aes-256-gcm',
    BLAKE3_CHACHA20_POLY1305: '2022-blake3-chacha20-poly1305',
};

const TLS_FLOW_CONTROL = {
    VISION: "xtls-rprx-vision",
    VISION_UDP443: "xtls-rprx-vision-udp443",
};

const UTLS_FINGERPRINT = {
    UTLS_CHROME: "chrome",
    UTLS_FIREFOX: "firefox",
    UTLS_SAFARI: "safari",
    UTLS_IOS: "ios",
    UTLS_android: "android",
    UTLS_EDGE: "edge",
    UTLS_360: "360",
    UTLS_QQ: "qq",
    UTLS_RANDOM: "random",
    UTLS_RANDOMIZED: "randomized",
    UTLS_RONDOMIZEDNOALPN: "randomizednoalpn",
    UTLS_UNSAFE: "unsafe",
};

const ALPN_OPTION = {
    H3: "h3",
    H2: "h2",
    HTTP1: "http/1.1",
};

const OutboundDomainStrategies = [
    "AsIs",
    "UseIP",
    "UseIPv4",
    "UseIPv6",
    "UseIPv6v4",
    "UseIPv4v6",
    "ForceIP",
    "ForceIPv6v4",
    "ForceIPv6",
    "ForceIPv4v6",
    "ForceIPv4"
];

const WireguardDomainStrategy = [
    "ForceIP",
    "ForceIPv4",
    "ForceIPv4v6",
    "ForceIPv6",
    "ForceIPv6v4"
];

const USERS_SECURITY = {
    AES_128_GCM: "aes-128-gcm",
    CHACHA20_POLY1305: "chacha20-poly1305",
    AUTO: "auto",
    NONE: "none",
    ZERO: "zero",
};

const MODE_OPTION = {
    AUTO: "auto",
    PACKET_UP: "packet-up",
    STREAM_UP: "stream-up",
    STREAM_ONE: "stream-one",
};

const Address_Port_Strategy = {
    NONE: "none",
    SrvPortOnly: "srvportonly",
    SrvAddressOnly: "srvaddressonly",
    SrvPortAndAddress: "srvportandaddress",
    TxtPortOnly: "txtportonly",
    TxtAddressOnly: "txtaddressonly",
    TxtPortAndAddress: "txtportandaddress"
};

Object.freeze(Protocols);
Object.freeze(SSMethods);
Object.freeze(TLS_FLOW_CONTROL);
Object.freeze(UTLS_FINGERPRINT);
Object.freeze(ALPN_OPTION);
Object.freeze(OutboundDomainStrategies);
Object.freeze(WireguardDomainStrategy);
Object.freeze(USERS_SECURITY);
Object.freeze(MODE_OPTION);
Object.freeze(Address_Port_Strategy);

class CommonClass {

    static toJsonArray(arr) {
        return arr.map(obj => obj.toJson());
    }

    static fromJson() {
        return new CommonClass();
    }

    toJson() {
        return this;
    }

    toString(format = true) {
        return format ? JSON.stringify(this.toJson(), null, 2) : JSON.stringify(this.toJson());
    }
}

class TcpStreamSettings extends CommonClass {
    constructor(type = 'none', host, path) {
        super();
        this.type = type;
        this.host = host;
        this.path = path;
    }

    static fromJson(json = {}) {
        let header = json.header;
        if (!header) return new TcpStreamSettings();
        if (header.type == 'http' && header.request) {
            return new TcpStreamSettings(
                header.type,
                header.request.headers.Host.join(','),
                header.request.path.join(','),
            );
        }
        return new TcpStreamSettings(header.type, '', '');
    }

    toJson() {
        return {
            header: {
                type: this.type,
                request: this.type === 'http' ? {
                    headers: {
                        Host: ObjectUtil.isEmpty(this.host) ? [] : this.host.split(',')
                    },
                    path: ObjectUtil.isEmpty(this.path) ? ["/"] : this.path.split(',')
                } : undefined,
            }
        };
    }
}

class KcpStreamSettings extends CommonClass {
    constructor(
        mtu = 1350,
        tti = 20,
        uplinkCapacity = 5,
        downlinkCapacity = 20,
        cwndMultiplier = 0,
        maxSendingWindow = 0,
    ) {
        super();
        this.mtu = mtu;
        this.tti = tti;
        this.upCap = uplinkCapacity;
        this.downCap = downlinkCapacity;
        this.cwndMultiplier = cwndMultiplier;
        this.maxSendingWindow = maxSendingWindow;
    }

    static fromJson(json = {}) {
        return new KcpStreamSettings(
            json.mtu,
            json.tti,
            json.uplinkCapacity,
            json.downlinkCapacity,
            json.cwndMultiplier,
            json.maxSendingWindow,
        );
    }

    toJson() {
        return {
            mtu: this.mtu,
            tti: this.tti,
            uplinkCapacity: this.upCap,
            downlinkCapacity: this.downCap,
            cwndMultiplier: this.cwndMultiplier,
            maxSendingWindow: this.maxSendingWindow,
        };
    }
}

class WsStreamSettings extends CommonClass {
    constructor(
        path = '/',
        host = '',
        heartbeatPeriod = 0,

    ) {
        super();
        this.path = path;
        this.host = host;
        this.heartbeatPeriod = heartbeatPeriod;
    }

    static fromJson(json = {}) {
        return new WsStreamSettings(
            json.path,
            json.host,
            json.heartbeatPeriod,
        );
    }

    toJson() {
        return {
            path: this.path,
            host: this.host,
            heartbeatPeriod: this.heartbeatPeriod
        };
    }
}

class GrpcStreamSettings extends CommonClass {
    constructor(
        serviceName = "",
        authority = "",
        multiMode = false
    ) {
        super();
        this.serviceName = serviceName;
        this.authority = authority;
        this.multiMode = multiMode;
    }

    static fromJson(json = {}) {
        return new GrpcStreamSettings(json.serviceName, json.authority, json.multiMode);
    }

    toJson() {
        return {
            serviceName: this.serviceName,
            authority: this.authority,
            multiMode: this.multiMode
        }
    }
}

class HttpUpgradeStreamSettings extends CommonClass {
    constructor(path = '/', host = '') {
        super();
        this.path = path;
        this.host = host;
    }

    static fromJson(json = {}) {
        return new HttpUpgradeStreamSettings(
            json.path,
            json.host,
        );
    }

    toJson() {
        return {
            path: this.path,
            host: this.host,
        };
    }
}

class xHTTPStreamSettings extends CommonClass {
    constructor(
        path = '/',
        host = '',
        mode = '',
        noGRPCHeader = false,
        scMinPostsIntervalMs = "30",
        xmux = {
            maxConcurrency: "16-32",
            maxConnections: 0,
            cMaxReuseTimes: 0,
            hMaxRequestTimes: "600-900",
            hMaxReusableSecs: "1800-3000",
            hKeepAlivePeriod: 0,
        },
    ) {
        super();
        this.path = path;
        this.host = host;
        this.mode = mode;
        this.noGRPCHeader = noGRPCHeader;
        this.scMinPostsIntervalMs = scMinPostsIntervalMs;
        this.xmux = xmux;
    }

    static fromJson(json = {}) {
        return new xHTTPStreamSettings(
            json.path,
            json.host,
            json.mode,
            json.noGRPCHeader,
            json.scMinPostsIntervalMs,
            json.xmux
        );
    }

    toJson() {
        return {
            path: this.path,
            host: this.host,
            mode: this.mode,
            noGRPCHeader: this.noGRPCHeader,
            scMinPostsIntervalMs: this.scMinPostsIntervalMs,
            xmux: {
                maxConcurrency: this.xmux.maxConcurrency,
                maxConnections: this.xmux.maxConnections,
                cMaxReuseTimes: this.xmux.cMaxReuseTimes,
                hMaxRequestTimes: this.xmux.hMaxRequestTimes,
                hMaxReusableSecs: this.xmux.hMaxReusableSecs,
                hKeepAlivePeriod: this.xmux.hKeepAlivePeriod,
            },
        };
    }
}

class TlsStreamSettings extends CommonClass {
    constructor(
        serverName = '',
        alpn = [],
        fingerprint = '',
        echConfigList = '',
        verifyPeerCertByName = '',
        pinnedPeerCertSha256 = '',
    ) {
        super();
        this.serverName = serverName;
        this.alpn = alpn;
        this.fingerprint = fingerprint;
        this.echConfigList = echConfigList;
        this.verifyPeerCertByName = verifyPeerCertByName;
        this.pinnedPeerCertSha256 = pinnedPeerCertSha256;
    }

    static fromJson(json = {}) {
        return new TlsStreamSettings(
            json.serverName,
            json.alpn,
            json.fingerprint,
            json.echConfigList,
            json.verifyPeerCertByName,
            json.pinnedPeerCertSha256,
        );
    }

    toJson() {
        return {
            serverName: this.serverName,
            alpn: this.alpn,
            fingerprint: this.fingerprint,
            echConfigList: this.echConfigList,
            verifyPeerCertByName: this.verifyPeerCertByName,
            pinnedPeerCertSha256: this.pinnedPeerCertSha256
        };
    }
}

class RealityStreamSettings extends CommonClass {
    constructor(
        publicKey = '',
        fingerprint = '',
        serverName = '',
        shortId = '',
        spiderX = '',
        mldsa65Verify = ''
    ) {
        super();
        this.publicKey = publicKey;
        this.fingerprint = fingerprint;
        this.serverName = serverName;
        this.shortId = shortId
        this.spiderX = spiderX;
        this.mldsa65Verify = mldsa65Verify;
    }
    static fromJson(json = {}) {
        return new RealityStreamSettings(
            json.publicKey,
            json.fingerprint,
            json.serverName,
            json.shortId,
            json.spiderX,
            json.mldsa65Verify
        );
    }
    toJson() {
        return {
            publicKey: this.publicKey,
            fingerprint: this.fingerprint,
            serverName: this.serverName,
            shortId: this.shortId,
            spiderX: this.spiderX,
            mldsa65Verify: this.mldsa65Verify
        };
    }
};

class HysteriaStreamSettings extends CommonClass {
    constructor(
        version = 2,
        auth = '',
        congestion = '',
        up = '0',
        down = '0',
        udphopPort = '',
        udphopIntervalMin = 30,
        udphopIntervalMax = 30,
        initStreamReceiveWindow = 8388608,
        maxStreamReceiveWindow = 8388608,
        initConnectionReceiveWindow = 20971520,
        maxConnectionReceiveWindow = 20971520,
        maxIdleTimeout = 30,
        keepAlivePeriod = 0,
        disablePathMTUDiscovery = false
    ) {
        super();
        this.version = version;
        this.auth = auth;
        this.congestion = congestion;
        this.up = up;
        this.down = down;
        this.udphopPort = udphopPort;
        this.udphopIntervalMin = udphopIntervalMin;
        this.udphopIntervalMax = udphopIntervalMax;
        this.initStreamReceiveWindow = initStreamReceiveWindow;
        this.maxStreamReceiveWindow = maxStreamReceiveWindow;
        this.initConnectionReceiveWindow = initConnectionReceiveWindow;
        this.maxConnectionReceiveWindow = maxConnectionReceiveWindow;
        this.maxIdleTimeout = maxIdleTimeout;
        this.keepAlivePeriod = keepAlivePeriod;
        this.disablePathMTUDiscovery = disablePathMTUDiscovery;
    }

    static fromJson(json = {}) {
        let udphopPort = '';
        let udphopIntervalMin = 30;
        let udphopIntervalMax = 30;
        if (json.udphop) {
            udphopPort = json.udphop.port || '';
            // Backward compatibility: if old 'interval' exists, use it for both min/max
            if (json.udphop.interval !== undefined) {
                udphopIntervalMin = json.udphop.interval;
                udphopIntervalMax = json.udphop.interval;
            } else {
                udphopIntervalMin = json.udphop.intervalMin || 30;
                udphopIntervalMax = json.udphop.intervalMax || 30;
            }
        }
        return new HysteriaStreamSettings(
            json.version,
            json.auth,
            json.congestion,
            json.up,
            json.down,
            udphopPort,
            udphopIntervalMin,
            udphopIntervalMax,
            json.initStreamReceiveWindow,
            json.maxStreamReceiveWindow,
            json.initConnectionReceiveWindow,
            json.maxConnectionReceiveWindow,
            json.maxIdleTimeout,
            json.keepAlivePeriod,
            json.disablePathMTUDiscovery
        );
    }

    toJson() {
        const result = {
            version: this.version,
            auth: this.auth,
            congestion: this.congestion,
            up: this.up,
            down: this.down,
            initStreamReceiveWindow: this.initStreamReceiveWindow,
            maxStreamReceiveWindow: this.maxStreamReceiveWindow,
            initConnectionReceiveWindow: this.initConnectionReceiveWindow,
            maxConnectionReceiveWindow: this.maxConnectionReceiveWindow,
            maxIdleTimeout: this.maxIdleTimeout,
            keepAlivePeriod: this.keepAlivePeriod,
            disablePathMTUDiscovery: this.disablePathMTUDiscovery
        };
        if (this.udphopPort) {
            result.udphop = {
                port: this.udphopPort,
                intervalMin: this.udphopIntervalMin,
                intervalMax: this.udphopIntervalMax
            };
        }
        return result;
    }
};
class SockoptStreamSettings extends CommonClass {
    constructor(
        dialerProxy = "",
        tcpFastOpen = false,
        tcpKeepAliveInterval = 0,
        tcpMptcp = false,
        penetrate = false,
        addressPortStrategy = Address_Port_Strategy.NONE,
        trustedXForwardedFor = [],
    ) {
        super();
        this.dialerProxy = dialerProxy;
        this.tcpFastOpen = tcpFastOpen;
        this.tcpKeepAliveInterval = tcpKeepAliveInterval;
        this.tcpMptcp = tcpMptcp;
        this.penetrate = penetrate;
        this.addressPortStrategy = addressPortStrategy;
        this.trustedXForwardedFor = trustedXForwardedFor;
    }

    static fromJson(json = {}) {
        if (Object.keys(json).length === 0) return undefined;
        return new SockoptStreamSettings(
            json.dialerProxy,
            json.tcpFastOpen,
            json.tcpKeepAliveInterval,
            json.tcpMptcp,
            json.penetrate,
            json.addressPortStrategy,
            json.trustedXForwardedFor || []
        );
    }

    toJson() {
        const result = {
            dialerProxy: this.dialerProxy,
            tcpFastOpen: this.tcpFastOpen,
            tcpKeepAliveInterval: this.tcpKeepAliveInterval,
            tcpMptcp: this.tcpMptcp,
            penetrate: this.penetrate,
            addressPortStrategy: this.addressPortStrategy
        };
        if (this.trustedXForwardedFor && this.trustedXForwardedFor.length > 0) {
            result.trustedXForwardedFor = this.trustedXForwardedFor;
        }
        return result;
    }
}

class UdpMask extends CommonClass {
    constructor(type = 'salamander', settings = {}) {
        super();
        this.type = type;
        this.settings = this._getDefaultSettings(type, settings);
    }

    _getDefaultSettings(type, settings = {}) {
        switch (type) {
            case 'salamander':
            case 'mkcp-aes128gcm':
                return { password: settings.password || '' };
            case 'header-dns':
                return { domain: settings.domain || '' };
            case 'xdns':
                return { resolvers: Array.isArray(settings.resolvers) ? settings.resolvers : [] };
            case 'xicmp':
                return { ip: settings.ip || '', id: settings.id ?? 0 };
            case 'mkcp-original':
            case 'header-dtls':
            case 'header-srtp':
            case 'header-utp':
            case 'header-wechat':
            case 'header-wireguard':
                return {}; // No settings needed
            case 'header-custom':
                return { client: [], server: [] };
            case 'noise':
                return { reset: 0, noise: [] };
            case 'sudoku':
                return { ascii: '', customTable: '', customTables: [], paddingMin: 0, paddingMax: 0 };
            default:
                return settings;
        }
    }

    static fromJson(json = {}) {
        return new UdpMask(
            json.type || 'salamander',
            json.settings || {}
        );
    }

    toJson() {
        return {
            type: this.type,
            settings: (this.settings && Object.keys(this.settings).length > 0) ? this.settings : undefined
        };
    }
}

class FinalMaskStreamSettings extends CommonClass {
    constructor(udp = []) {
        super();
        this.udp = Array.isArray(udp) ? udp.map(u => new UdpMask(u.type, u.settings)) : [new UdpMask(udp.type, udp.settings)];
    }

    static fromJson(json = {}) {
        return new FinalMaskStreamSettings(json.udp || []);
    }

    toJson() {
        return {
            udp: this.udp.map(udp => udp.toJson())
        };

    }
}

class StreamSettings extends CommonClass {
    constructor(
        network = 'tcp',
        security = 'none',
        tlsSettings = new TlsStreamSettings(),
        realitySettings = new RealityStreamSettings(),
        tcpSettings = new TcpStreamSettings(),
        kcpSettings = new KcpStreamSettings(),
        wsSettings = new WsStreamSettings(),
        grpcSettings = new GrpcStreamSettings(),
        httpupgradeSettings = new HttpUpgradeStreamSettings(),
        xhttpSettings = new xHTTPStreamSettings(),
        hysteriaSettings = new HysteriaStreamSettings(),
        finalmask = new FinalMaskStreamSettings(),
        sockopt = undefined,
    ) {
        super();
        this.network = network;
        this.security = security;
        this.tls = tlsSettings;
        this.reality = realitySettings;
        this.tcp = tcpSettings;
        this.kcp = kcpSettings;
        this.ws = wsSettings;
        this.grpc = grpcSettings;
        this.httpupgrade = httpupgradeSettings;
        this.xhttp = xhttpSettings;
        this.hysteria = hysteriaSettings;
        this.finalmask = finalmask;
        this.sockopt = sockopt;
    }

    addUdpMask(type = 'salamander') {
        this.finalmask.udp.push(new UdpMask(type));
    }

    delUdpMask(index) {
        if (this.finalmask.udp) {
            this.finalmask.udp.splice(index, 1);
        }
    }

    get hasFinalMask() {
        return this.finalmask.udp && this.finalmask.udp.length > 0;
    }

    get isTls() {
        return this.security === 'tls';
    }

    get isReality() {
        return this.security === "reality";
    }

    get sockoptSwitch() {
        return this.sockopt != undefined;
    }

    set sockoptSwitch(value) {
        this.sockopt = value ? new SockoptStreamSettings() : undefined;
    }

    static fromJson(json = {}) {
        return new StreamSettings(
            json.network,
            json.security,
            TlsStreamSettings.fromJson(json.tlsSettings),
            RealityStreamSettings.fromJson(json.realitySettings),
            TcpStreamSettings.fromJson(json.tcpSettings),
            KcpStreamSettings.fromJson(json.kcpSettings),
            WsStreamSettings.fromJson(json.wsSettings),
            GrpcStreamSettings.fromJson(json.grpcSettings),
            HttpUpgradeStreamSettings.fromJson(json.httpupgradeSettings),
            xHTTPStreamSettings.fromJson(json.xhttpSettings),
            HysteriaStreamSettings.fromJson(json.hysteriaSettings),
            FinalMaskStreamSettings.fromJson(json.finalmask),
            SockoptStreamSettings.fromJson(json.sockopt),
        );
    }

    toJson() {
        const network = this.network;
        return {
            network: network,
            security: this.security,
            tlsSettings: this.security == 'tls' ? this.tls.toJson() : undefined,
            realitySettings: this.security == 'reality' ? this.reality.toJson() : undefined,
            tcpSettings: network === 'tcp' ? this.tcp.toJson() : undefined,
            kcpSettings: network === 'kcp' ? this.kcp.toJson() : undefined,
            wsSettings: network === 'ws' ? this.ws.toJson() : undefined,
            grpcSettings: network === 'grpc' ? this.grpc.toJson() : undefined,
            httpupgradeSettings: network === 'httpupgrade' ? this.httpupgrade.toJson() : undefined,
            xhttpSettings: network === 'xhttp' ? this.xhttp.toJson() : undefined,
            hysteriaSettings: network === 'hysteria' ? this.hysteria.toJson() : undefined,
            finalmask: this.hasFinalMask ? this.finalmask.toJson() : undefined,
            sockopt: this.sockopt != undefined ? this.sockopt.toJson() : undefined,
        };
    }
}

class Mux extends CommonClass {
    constructor(enabled = false, concurrency = 8, xudpConcurrency = 16, xudpProxyUDP443 = "reject") {
        super();
        this.enabled = enabled;
        this.concurrency = concurrency;
        this.xudpConcurrency = xudpConcurrency;
        this.xudpProxyUDP443 = xudpProxyUDP443;
    }

    static fromJson(json = {}) {
        if (Object.keys(json).length === 0) return undefined;
        return new Mux(
            json.enabled,
            json.concurrency,
            json.xudpConcurrency,
            json.xudpProxyUDP443,
        );
    }

    toJson() {
        return {
            enabled: this.enabled,
            concurrency: this.concurrency,
            xudpConcurrency: this.xudpConcurrency,
            xudpProxyUDP443: this.xudpProxyUDP443,
        };
    }
}

class Outbound extends CommonClass {
    constructor(
        tag = '',
        protocol = Protocols.VLESS,
        settings = null,
        streamSettings = new StreamSettings(),
        sendThrough,
        mux = new Mux(),
    ) {
        super();
        this.tag = tag;
        this._protocol = protocol;
        this.settings = settings == null ? Outbound.Settings.getSettings(protocol) : settings;
        this.stream = streamSettings;
        this.sendThrough = sendThrough;
        this.mux = mux;
        this.proxySettings = undefined;
    }

    get protocol() {
        return this._protocol;
    }

    set protocol(protocol) {
        this._protocol = protocol;
        this.settings = Outbound.Settings.getSettings(protocol);
        this.stream = new StreamSettings();
        this._nativeExtras = undefined;
        this._nativeStream = undefined;
        this._nativeMux = undefined;
        this._nativeSockoptBaseline = undefined;
        this.proxySettings = undefined;
    }

    get isNative() {
        return this.settings instanceof Outbound.NativeSettings;
    }

    get validationErrors() {
        const errors = this.settings?.validationErrors ? [...this.settings.validationErrors] : [];
        if (this.proxySettings !== undefined) {
            if (!Outbound.NativeSettings.isObject(this.proxySettings)) errors.push('Outbound chaining settings must be an object.');
            else {
                if (typeof this.proxySettings.tag !== 'string' || !this.proxySettings.tag.trim()) errors.push('A carrier outbound tag is required.');
                if (this.proxySettings.tag === this.tag) errors.push('An outbound cannot chain through itself.');
                if (this.proxySettings.transportLayer !== undefined && typeof this.proxySettings.transportLayer !== 'boolean') errors.push('transportLayer must be a boolean.');
            }
        }
        return errors;
    }

    setChainingEnabled(enabled) {
        this.proxySettings = enabled ? {tag: '', transportLayer: true} : undefined;
    }

    get hasChainingObject() {
        return Outbound.NativeSettings.isObject(this.proxySettings);
    }

    canEnableTls() {
        if (this.protocol === Protocols.Hysteria) return true;
        if (![Protocols.VMess, Protocols.VLESS, Protocols.Trojan, Protocols.Shadowsocks].includes(this.protocol)) return false;
        return ["tcp", "ws", "http", "grpc", "httpupgrade", "xhttp"].includes(this.stream.network);
    }

    //this is used for xtls-rprx-vision
    canEnableTlsFlow() {
        if ((this.stream.security != 'none') && (this.stream.network === "tcp")) {
            return this.protocol === Protocols.VLESS;
        }
        return false;
    }

    // Vision seed applies only when vision flow is selected
    canEnableVisionSeed() {
        if (!this.canEnableTlsFlow()) return false;
        const flow = this.settings?.flow;
        return flow === TLS_FLOW_CONTROL.VISION || flow === TLS_FLOW_CONTROL.VISION_UDP443;
    }

    canEnableReality() {
        if (![Protocols.VLESS, Protocols.Trojan].includes(this.protocol)) return false;
        return ["tcp", "http", "grpc", "xhttp"].includes(this.stream.network);
    }

    canEnableStream() {
        return [Protocols.VMess, Protocols.VLESS, Protocols.Trojan, Protocols.Shadowsocks, Protocols.Hysteria].includes(this.protocol);
    }

    canEnableMux() {
        // Disable Mux if flow is set
        if (this.settings.flow && this.settings.flow !== '') {
            this.mux.enabled = false;
            return false;
        }

        // Disable Mux if network is xhttp
        if (this.stream.network === 'xhttp') {
            this.mux.enabled = false;
            return false;
        }

        // Allow Mux only for these protocols
        return [
            Protocols.VMess,
            Protocols.VLESS,
            Protocols.Trojan,
            Protocols.Shadowsocks,
            Protocols.HTTP,
            Protocols.Socks
        ].includes(this.protocol);
    }

    hasServers() {
        return [Protocols.Trojan, Protocols.Shadowsocks, Protocols.Socks, Protocols.HTTP].includes(this.protocol);
    }

    hasAddressPort() {
        if (this.isNative) return false;
        return [
            Protocols.DNS,
            Protocols.VMess,
            Protocols.VLESS,
            Protocols.Trojan,
            Protocols.Shadowsocks,
            Protocols.Socks,
            Protocols.HTTP,
            Protocols.Hysteria
        ].includes(this.protocol);
    }

    hasUsername() {
        return [Protocols.Socks, Protocols.HTTP].includes(this.protocol);
    }

    static fromJson(json = {}) {
        const result = new Outbound(
            json.tag,
            json.protocol,
            Outbound.Settings.fromJson(json.protocol, json.settings),
            StreamSettings.fromJson(json.streamSettings),
            json.sendThrough,
            Mux.fromJson(json.mux),
        );
        result.proxySettings = Outbound.NativeSettings.clone(json.proxySettings);
        if (result.isNative) {
            result._nativeExtras = Outbound.NativeSettings.clone(json);
            for (const key of ["protocol", "settings", "tag", "sendThrough", "streamSettings", "mux", "proxySettings"]) delete result._nativeExtras[key];
            result._nativeStream = json.streamSettings === undefined ? undefined : Outbound.NativeSettings.clone(json.streamSettings);
            result._nativeMux = json.mux === undefined ? undefined : Outbound.NativeSettings.clone(json.mux);
            result._nativeSockoptBaseline = result.stream?.sockopt ? Outbound.NativeSettings.clone(result.stream.sockopt.toJson()) : undefined;
        }
        return result;
    }

    toJson() {
        if (this.isNative) {
            // Native carriers own their framing/TLS. Preserve explicitly imported
            // top-level chaining/socket options without inventing an outer layer.
            const stream = this._nativeStream === undefined ? {} : Outbound.NativeSettings.clone(this._nativeStream);
            if (this.stream?.sockopt) {
                const current = Outbound.NativeSettings.clone(this.stream.sockopt.toJson());
                const baseline = this._nativeSockoptBaseline || {};
                const socket = stream.sockopt || {};
                // Apply only edited typed fields; retain socket options the UI
                // does not yet know, such as a routing mark.
                for (const key of new Set([...Object.keys(baseline), ...Object.keys(current)])) {
                    if (JSON.stringify(current[key]) === JSON.stringify(baseline[key])) continue;
                    if (current[key] === undefined) delete socket[key];
                    else socket[key] = current[key];
                }
                stream.sockopt = socket;
            } else delete stream.sockopt;
            return {
                ...Outbound.NativeSettings.clone(this._nativeExtras || {}),
                protocol: this.protocol,
                settings: this.settings.toJson(),
                ...(this.tag ? {tag: this.tag} : {}),
                ...(this.sendThrough ? {sendThrough: this.sendThrough} : {}),
                ...(Object.keys(stream).length ? {streamSettings: stream} : {}),
                ...(this._nativeMux ? {mux: Outbound.NativeSettings.clone(this._nativeMux)} : {}),
                ...(this.proxySettings !== undefined ? {proxySettings: Outbound.NativeSettings.clone(this.proxySettings)} : {}),
            };
        }
        var stream;
        if (this.canEnableStream()) {
            stream = this.stream.toJson();
        } else {
            if (this.stream?.sockopt)
                stream = { sockopt: this.stream.sockopt.toJson() };
        }
        let settingsOut = this.settings instanceof CommonClass ? this.settings.toJson() : this.settings;
        return {
            protocol: this.protocol,
            settings: settingsOut,
            // Only include tag, streamSettings, sendThrough, mux if present and not empty
            ...(this.tag ? { tag: this.tag } : {}),
            ...(stream ? { streamSettings: stream } : {}),
            ...(this.sendThrough ? { sendThrough: this.sendThrough } : {}),
            ...(this.mux?.enabled ? { mux: this.mux } : {}),
            ...(this.proxySettings !== undefined ? {proxySettings: Outbound.NativeSettings.clone(this.proxySettings)} : {}),
        };
    }

    static fromLink(link) {
        data = link.split('://');
        if (data.length != 2) return null;
        switch (data[0].toLowerCase()) {
            case Protocols.VMess:
                return this.fromVmessLink(JSON.parse(Base64.decode(data[1])));
            case Protocols.VLESS:
            case Protocols.Trojan:
            case 'ss':
                return this.fromParamLink(link);
            case 'hysteria2':
            case Protocols.Hysteria:
                return this.fromHysteriaLink(link);
            default:
                return null;
        }
    }

    static fromVmessLink(json = {}) {
        let stream = new StreamSettings(json.net, json.tls);

        let network = json.net;
        if (network === 'tcp') {
            stream.tcp = new TcpStreamSettings(
                json.type,
                json.host ?? '',
                json.path ?? '');
        } else if (network === 'kcp') {
            stream.kcp = new KcpStreamSettings();
            stream.type = json.type;
            stream.seed = json.path;
        } else if (network === 'ws') {
            stream.ws = new WsStreamSettings(json.path, json.host);
        } else if (network === 'grpc') {
            stream.grpc = new GrpcStreamSettings(json.path, json.authority, json.type == 'multi');
        } else if (network === 'httpupgrade') {
            stream.httpupgrade = new HttpUpgradeStreamSettings(json.path, json.host);
        } else if (network === 'xhttp') {
            stream.xhttp = new xHTTPStreamSettings(json.path, json.host, json.mode);
        }

        if (json.tls && json.tls == 'tls') {
            stream.tls = new TlsStreamSettings(
                json.sni,
                json.alpn ? json.alpn.split(',') : [],
                json.fp);
        }

        const port = json.port * 1;

        return new Outbound(json.ps, Protocols.VMess, new Outbound.VmessSettings(json.add, port, json.id, json.scy), stream);
    }

    static fromParamLink(link) {
        const url = new URL(link);
        let type = url.searchParams.get('type') ?? 'tcp';
        let security = url.searchParams.get('security') ?? 'none';
        let stream = new StreamSettings(type, security);

        let headerType = url.searchParams.get('headerType') ?? undefined;
        let host = url.searchParams.get('host') ?? undefined;
        let path = url.searchParams.get('path') ?? undefined;
        let mode = url.searchParams.get('mode') ?? undefined;

        if (type === 'tcp' || type === 'none') {
            stream.tcp = new TcpStreamSettings(headerType ?? 'none', host, path);
        } else if (type === 'kcp') {
            stream.kcp = new KcpStreamSettings();
            stream.kcp.type = headerType ?? 'none';
            stream.kcp.seed = path;
        } else if (type === 'ws') {
            stream.ws = new WsStreamSettings(path, host);
        } else if (type === 'grpc') {
            stream.grpc = new GrpcStreamSettings(
                url.searchParams.get('serviceName') ?? '',
                url.searchParams.get('authority') ?? '',
                url.searchParams.get('mode') == 'multi');
        } else if (type === 'httpupgrade') {
            stream.httpupgrade = new HttpUpgradeStreamSettings(path, host);
        } else if (type === 'xhttp') {
            stream.xhttp = new xHTTPStreamSettings(path, host, mode);
        }

        if (security == 'tls') {
            let fp = url.searchParams.get('fp') ?? 'none';
            let alpn = url.searchParams.get('alpn');
            let sni = url.searchParams.get('sni') ?? '';
            let ech = url.searchParams.get('ech') ?? '';
            stream.tls = new TlsStreamSettings(sni, alpn ? alpn.split(',') : [], fp, ech);
        }

        if (security == 'reality') {
            let pbk = url.searchParams.get('pbk');
            let fp = url.searchParams.get('fp');
            let sni = url.searchParams.get('sni') ?? '';
            let sid = url.searchParams.get('sid') ?? '';
            let spx = url.searchParams.get('spx') ?? '';
            let pqv = url.searchParams.get('pqv') ?? '';
            stream.reality = new RealityStreamSettings(pbk, fp, sni, sid, spx, pqv);
        }

        const regex = /([^@]+):\/\/([^@]+)@(.+):(\d+)(.*)$/;
        const match = link.match(regex);

        if (!match) return null;
        let [, protocol, userData, address, port,] = match;
        port *= 1;
        if (protocol == 'ss') {
            protocol = 'shadowsocks';
            userData = atob(userData).split(':');
        }
        var settings;
        switch (protocol) {
            case Protocols.VLESS:
                settings = new Outbound.VLESSSettings(address, port, userData, url.searchParams.get('flow') ?? '', url.searchParams.get('encryption') ?? 'none');
                break;
            case Protocols.Trojan:
                settings = new Outbound.TrojanSettings(address, port, userData);
                break;
            case Protocols.Shadowsocks:
                let method = userData.splice(0, 1)[0];
                settings = new Outbound.ShadowsocksSettings(address, port, userData.join(":"), method, true);
                break;
            default:
                return null;
        }
        let remark = decodeURIComponent(url.hash);
        // Remove '#' from url.hash
        remark = remark.length > 0 ? remark.substring(1) : 'out-' + protocol + '-' + port;
        return new Outbound(remark, protocol, settings, stream);
    }

    static fromHysteriaLink(link) {
        // Parse hysteria2://password@address:port[?param1=value1&param2=value2...][#remarks]
        const regex = /^hysteria2?:\/\/([^@]+)@([^:?#]+):(\d+)([^#]*)(#.*)?$/;
        const match = link.match(regex);

        if (!match) return null;

        let [, password, address, port, params, hash] = match;
        port = parseInt(port);

        // Parse URL parameters if present
        let urlParams = new URLSearchParams(params);

        // Create stream settings with hysteria network
        let stream = new StreamSettings('hysteria', 'none');

        // Set hysteria stream settings
        stream.hysteria.auth = password;
        stream.hysteria.congestion = urlParams.get('congestion') ?? '';
        stream.hysteria.up = urlParams.get('up') ?? '0';
        stream.hysteria.down = urlParams.get('down') ?? '0';
        stream.hysteria.udphopPort = urlParams.get('udphopPort') ?? '';
        // Support both old single interval and new min/max range
        if (urlParams.has('udphopInterval')) {
            const interval = parseInt(urlParams.get('udphopInterval'));
            stream.hysteria.udphopIntervalMin = interval;
            stream.hysteria.udphopIntervalMax = interval;
        } else {
            stream.hysteria.udphopIntervalMin = parseInt(urlParams.get('udphopIntervalMin') ?? '30');
            stream.hysteria.udphopIntervalMax = parseInt(urlParams.get('udphopIntervalMax') ?? '30');
        }

        // Optional QUIC parameters
        if (urlParams.has('initStreamReceiveWindow')) {
            stream.hysteria.initStreamReceiveWindow = parseInt(urlParams.get('initStreamReceiveWindow'));
        }
        if (urlParams.has('maxStreamReceiveWindow')) {
            stream.hysteria.maxStreamReceiveWindow = parseInt(urlParams.get('maxStreamReceiveWindow'));
        }
        if (urlParams.has('initConnectionReceiveWindow')) {
            stream.hysteria.initConnectionReceiveWindow = parseInt(urlParams.get('initConnectionReceiveWindow'));
        }
        if (urlParams.has('maxConnectionReceiveWindow')) {
            stream.hysteria.maxConnectionReceiveWindow = parseInt(urlParams.get('maxConnectionReceiveWindow'));
        }
        if (urlParams.has('maxIdleTimeout')) {
            stream.hysteria.maxIdleTimeout = parseInt(urlParams.get('maxIdleTimeout'));
        }
        if (urlParams.has('keepAlivePeriod')) {
            stream.hysteria.keepAlivePeriod = parseInt(urlParams.get('keepAlivePeriod'));
        }
        if (urlParams.has('disablePathMTUDiscovery')) {
            stream.hysteria.disablePathMTUDiscovery = urlParams.get('disablePathMTUDiscovery') === 'true';
        }

        // Create settings
        let settings = new Outbound.HysteriaSettings(address, port, 2);

        // Extract remark from hash
        let remark = hash ? decodeURIComponent(hash.substring(1)) : `out-hysteria-${port}`;

        return new Outbound(remark, Protocols.Hysteria, settings, stream);
    }
}

Outbound.Settings = class extends CommonClass {
    constructor(protocol) {
        super();
        this.protocol = protocol;
    }

    static getSettings(protocol) {
        if (Outbound.NativeSettings.supports(protocol)) return new Outbound.NativeSettings(protocol);
        switch (protocol) {
            case Protocols.Freedom: return new Outbound.FreedomSettings();
            case Protocols.Blackhole: return new Outbound.BlackholeSettings();
            case Protocols.DNS: return new Outbound.DNSSettings();
            case Protocols.VMess: return new Outbound.VmessSettings();
            case Protocols.VLESS: return new Outbound.VLESSSettings();
            case Protocols.Trojan: return new Outbound.TrojanSettings();
            case Protocols.Shadowsocks: return new Outbound.ShadowsocksSettings();
            case Protocols.Socks: return new Outbound.SocksSettings();
            case Protocols.HTTP: return new Outbound.HttpSettings();
            case Protocols.Wireguard: return new Outbound.WireguardSettings();
            case Protocols.Hysteria: return new Outbound.HysteriaSettings();
            default: return null;
        }
    }

    static fromJson(protocol, json) {
        if (Outbound.NativeSettings.supports(protocol) || (protocol === Protocols.DNS && json && Object.prototype.hasOwnProperty.call(json, "tunnel"))) {
            return new Outbound.NativeSettings(protocol, json);
        }
        switch (protocol) {
            case Protocols.Freedom: return Outbound.FreedomSettings.fromJson(json);
            case Protocols.Blackhole: return Outbound.BlackholeSettings.fromJson(json);
            case Protocols.DNS: return Outbound.DNSSettings.fromJson(json);
            case Protocols.VMess: return Outbound.VmessSettings.fromJson(json);
            case Protocols.VLESS: return Outbound.VLESSSettings.fromJson(json);
            case Protocols.Trojan: return Outbound.TrojanSettings.fromJson(json);
            case Protocols.Shadowsocks: return Outbound.ShadowsocksSettings.fromJson(json);
            case Protocols.Socks: return Outbound.SocksSettings.fromJson(json);
            case Protocols.HTTP: return Outbound.HttpSettings.fromJson(json);
            case Protocols.Wireguard: return Outbound.WireguardSettings.fromJson(json);
            case Protocols.Hysteria: return Outbound.HysteriaSettings.fromJson(json);
            default: return null;
        }
    }

    toJson() {
        return {};
    }
};
Outbound.FreedomSettings = class extends CommonClass {
    constructor(
        domainStrategy = '',
        redirect = '',
        fragment = {},
        noises = [],
        ipsBlocked = [],
    ) {
        super();
        this.domainStrategy = domainStrategy;
        this.redirect = redirect;
        this.fragment = fragment || {};
        this.noises = Array.isArray(noises) ? noises : [];
        this.ipsBlocked = Array.isArray(ipsBlocked) ? ipsBlocked : [];
    }

    addNoise() {
        this.noises.push(new Outbound.FreedomSettings.Noise());
    }

    delNoise(index) {
        this.noises.splice(index, 1);
    }

    static fromJson(json = {}) {
        return new Outbound.FreedomSettings(
            json.domainStrategy,
            json.redirect,
            json.fragment ? Outbound.FreedomSettings.Fragment.fromJson(json.fragment) : {},
            json.noises ? json.noises.map(noise => Outbound.FreedomSettings.Noise.fromJson(noise)) : [],
            json.ipsBlocked || [],
        );
    }

    toJson() {
        return {
            domainStrategy: ObjectUtil.isEmpty(this.domainStrategy) ? undefined : this.domainStrategy,
            redirect: ObjectUtil.isEmpty(this.redirect) ? undefined : this.redirect,
            fragment: Object.keys(this.fragment).length === 0 ? undefined : this.fragment,
            noises: this.noises.length === 0 ? undefined : Outbound.FreedomSettings.Noise.toJsonArray(this.noises),
            ipsBlocked: this.ipsBlocked.length === 0 ? undefined : this.ipsBlocked,
        };
    }
};

Outbound.FreedomSettings.Fragment = class extends CommonClass {
    constructor(
        packets = '1-3',
        length = '',
        interval = '',
        maxSplit = ''
    ) {
        super();
        this.packets = packets;
        this.length = length;
        this.interval = interval;
        this.maxSplit = maxSplit;
    }

    static fromJson(json = {}) {
        return new Outbound.FreedomSettings.Fragment(
            json.packets,
            json.length,
            json.interval,
            json.maxSplit
        );
    }
};

Outbound.FreedomSettings.Noise = class extends CommonClass {
    constructor(
        type = 'rand',
        packet = '10-20',
        delay = '10-16',
        applyTo = 'ip'
    ) {
        super();
        this.type = type;
        this.packet = packet;
        this.delay = delay;
        this.applyTo = applyTo;
    }

    static fromJson(json = {}) {
        return new Outbound.FreedomSettings.Noise(
            json.type,
            json.packet,
            json.delay,
            json.applyTo
        );
    }

    toJson() {
        return {
            type: this.type,
            packet: this.packet,
            delay: this.delay,
            applyTo: this.applyTo
        };
    }
};

Outbound.BlackholeSettings = class extends CommonClass {
    constructor(type) {
        super();
        this.type = type;
    }

    static fromJson(json = {}) {
        return new Outbound.BlackholeSettings(
            json.response ? json.response.type : undefined,
        );
    }

    toJson() {
        return {
            response: ObjectUtil.isEmpty(this.type) ? undefined : { type: this.type },
        };
    }
};
Outbound.DNSSettings = class extends CommonClass {
    constructor(
        network = 'udp',
        address = '',
        port = 53,
        nonIPQuery = 'reject',
        blockTypes = []
    ) {
        super();
        this.network = network;
        this.address = address;
        this.port = port;
        this.nonIPQuery = nonIPQuery;
        this.blockTypes = blockTypes;
    }

    static fromJson(json = {}) {
        return new Outbound.DNSSettings(
            json.network,
            json.address,
            json.port,
            json.nonIPQuery,
            json.blockTypes,
        );
    }
};
Outbound.VmessSettings = class extends CommonClass {
    constructor(address, port, id, security, rawUuidAuth = false) {
        super();
        this.address = address;
        this.port = port;
        this.id = id;
        this.security = security;
        this.rawUuidAuth = rawUuidAuth;
    }

    get validationErrors() {
        return typeof this.rawUuidAuth === "boolean" ? [] : ["rawUuidAuth must be a boolean."];
    }

    static fromJson(json = {}) {
        if (!ObjectUtil.isArrEmpty(json.vnext)) {
            const v = json.vnext[0] || {};
            const u = ObjectUtil.isArrEmpty(v.users) ? {} : v.users[0];
            return new Outbound.VmessSettings(
                v.address,
                v.port,
                u.id,
                u.security,
                u.rawUuidAuth === undefined ? json.rawUuidAuth : u.rawUuidAuth,
            );
        }
    }

    toJson() {
        return {
            vnext: [{
                address: this.address,
                port: this.port,
                users: [{
                    id: this.id,
                    security: this.security,
                    ...(this.rawUuidAuth !== undefined && this.rawUuidAuth !== false ? {rawUuidAuth: this.rawUuidAuth} : {}),
                }]
            }]
        };
    }
};
Outbound.VLESSSettings = class extends CommonClass {
    constructor(address, port, id, flow, encryption, testpre = 0, testseed = [900, 500, 900, 256]) {
        super();
        this.address = address;
        this.port = port;
        this.id = id;
        this.flow = flow;
        this.encryption = encryption;
        this.testpre = testpre;
        this.testseed = testseed;
    }

    static fromJson(json = {}) {
        if (ObjectUtil.isEmpty(json.address) || ObjectUtil.isEmpty(json.port)) return new Outbound.VLESSSettings();
        return new Outbound.VLESSSettings(
            json.address,
            json.port,
            json.id,
            json.flow,
            json.encryption,
            json.testpre || 0,
            json.testseed && json.testseed.length >= 4 ? json.testseed : [900, 500, 900, 256]
        );
    }

    toJson() {
        const result = {
            address: this.address,
            port: this.port,
            id: this.id,
            flow: this.flow,
            encryption: this.encryption,
        };
        // Only include Vision settings when flow is set
        if (this.flow && this.flow !== '') {
            if (this.testpre > 0) {
                result.testpre = this.testpre;
            }
            if (this.testseed && this.testseed.length >= 4) {
                result.testseed = this.testseed;
            }
        }
        return result;
    }
};
Outbound.TrojanSettings = class extends CommonClass {
    constructor(address, port, password, uuidHashPrefix = false) {
        super();
        this.address = address;
        this.port = port;
        this.password = password;
        this.uuidHashPrefix = uuidHashPrefix;
    }

    get validationErrors() {
        return typeof this.uuidHashPrefix === "boolean" ? [] : ["uuidHashPrefix must be a boolean."];
    }

    static fromJson(json = {}) {
        if (ObjectUtil.isArrEmpty(json.servers)) return new Outbound.TrojanSettings();
        return new Outbound.TrojanSettings(
            json.servers[0].address,
            json.servers[0].port,
            json.servers[0].password,
            json.servers[0].uuidHashPrefix === undefined ? json.uuidHashPrefix : json.servers[0].uuidHashPrefix,
        );
    }

    toJson() {
        return {
            servers: [{
                address: this.address,
                port: this.port,
                password: this.password,
                ...(this.uuidHashPrefix !== undefined && this.uuidHashPrefix !== false ? {uuidHashPrefix: this.uuidHashPrefix} : {}),
            }],
        };
    }
};
Outbound.ShadowsocksSettings = class extends CommonClass {
    constructor(address, port, password, method, uot, UoTVersion, uuidIdentityKeys = false) {
        super();
        this.address = address;
        this.port = port;
        this.password = password;
        this.method = method;
        this.uot = uot;
        this.UoTVersion = UoTVersion;
        this.uuidIdentityKeys = uuidIdentityKeys;
    }

    get supportsUuidIdentityKeys() {
        return ['2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305'].includes(this.method);
    }

    get validationErrors() {
        if (typeof this.uuidIdentityKeys !== 'boolean') return ['uuidIdentityKeys must be a boolean.'];
        return this.uuidIdentityKeys && !this.supportsUuidIdentityKeys ? ['UUID identity key import requires an SS2022 method.'] : [];
    }

    static fromJson(json = {}) {
        let servers = json.servers;
        if (ObjectUtil.isArrEmpty(servers)) servers = [{}];
        return new Outbound.ShadowsocksSettings(
            servers[0].address,
            servers[0].port,
            servers[0].password,
            servers[0].method,
            servers[0].uot,
            servers[0].UoTVersion,
            servers[0].uuidIdentityKeys,
        );
    }

    toJson() {
        return {
            servers: [{
                address: this.address,
                port: this.port,
                password: this.password,
                method: this.method,
                uot: this.uot,
                UoTVersion: this.UoTVersion,
                ...(this.uuidIdentityKeys !== false ? {uuidIdentityKeys: this.uuidIdentityKeys} : {}),
            }],
        };
    }
};

Outbound.SocksSettings = class extends CommonClass {
    constructor(address, port, user, pass) {
        super();
        this.address = address;
        this.port = port;
        this.user = user;
        this.pass = pass;
    }

    static fromJson(json = {}) {
        let servers = json.servers;
        if (ObjectUtil.isArrEmpty(servers)) servers = [{ users: [{}] }];
        return new Outbound.SocksSettings(
            servers[0].address,
            servers[0].port,
            ObjectUtil.isArrEmpty(servers[0].users) ? '' : servers[0].users[0].user,
            ObjectUtil.isArrEmpty(servers[0].users) ? '' : servers[0].users[0].pass,
        );
    }

    toJson() {
        return {
            servers: [{
                address: this.address,
                port: this.port,
                users: ObjectUtil.isEmpty(this.user) ? [] : [{ user: this.user, pass: this.pass }],
            }],
        };
    }
};
Outbound.HttpSettings = class extends CommonClass {
    constructor(address, port, user, pass) {
        super();
        this.address = address;
        this.port = port;
        this.user = user;
        this.pass = pass;
    }

    static fromJson(json = {}) {
        let servers = json.servers;
        if (ObjectUtil.isArrEmpty(servers)) servers = [{ users: [{}] }];
        return new Outbound.HttpSettings(
            servers[0].address,
            servers[0].port,
            ObjectUtil.isArrEmpty(servers[0].users) ? '' : servers[0].users[0].user,
            ObjectUtil.isArrEmpty(servers[0].users) ? '' : servers[0].users[0].pass,
        );
    }

    toJson() {
        return {
            servers: [{
                address: this.address,
                port: this.port,
                users: ObjectUtil.isEmpty(this.user) ? [] : [{ user: this.user, pass: this.pass }],
            }],
        };
    }
};

Outbound.WireguardSettings = class extends CommonClass {
    constructor(
        mtu = 1420,
        secretKey = '',
        address = [''],
        workers = 2,
        domainStrategy = '',
        reserved = '',
        peers = [new Outbound.WireguardSettings.Peer()],
        noKernelTun = false,
    ) {
        super();
        this.mtu = mtu;
        this.secretKey = secretKey;
        this.pubKey = secretKey.length > 0 ? Wireguard.generateKeypair(secretKey).publicKey : '';
        this.address = Array.isArray(address) ? address.join(',') : address;
        this.workers = workers;
        this.domainStrategy = domainStrategy;
        this.reserved = Array.isArray(reserved) ? reserved.join(',') : reserved;
        this.peers = peers;
        this.noKernelTun = noKernelTun;
    }

    addPeer() {
        this.peers.push(new Outbound.WireguardSettings.Peer());
    }

    delPeer(index) {
        this.peers.splice(index, 1);
    }

    static fromJson(json = {}) {
        return new Outbound.WireguardSettings(
            json.mtu,
            json.secretKey,
            json.address,
            json.workers,
            json.domainStrategy,
            json.reserved,
            json.peers.map(peer => Outbound.WireguardSettings.Peer.fromJson(peer)),
            json.noKernelTun,
        );
    }

    toJson() {
        return {
            mtu: this.mtu ?? undefined,
            secretKey: this.secretKey,
            address: this.address ? this.address.split(",") : [],
            workers: this.workers ?? undefined,
            domainStrategy: WireguardDomainStrategy.includes(this.domainStrategy) ? this.domainStrategy : undefined,
            reserved: this.reserved ? this.reserved.split(",").map(Number) : undefined,
            peers: Outbound.WireguardSettings.Peer.toJsonArray(this.peers),
            noKernelTun: this.noKernelTun,
        };
    }
};

Outbound.WireguardSettings.Peer = class extends CommonClass {
    constructor(
        publicKey = '',
        psk = '',
        allowedIPs = ['0.0.0.0/0', '::/0'],
        endpoint = '',
        keepAlive = 0
    ) {
        super();
        this.publicKey = publicKey;
        this.psk = psk;
        this.allowedIPs = allowedIPs;
        this.endpoint = endpoint;
        this.keepAlive = keepAlive;
    }

    static fromJson(json = {}) {
        return new Outbound.WireguardSettings.Peer(
            json.publicKey,
            json.preSharedKey,
            json.allowedIPs,
            json.endpoint,
            json.keepAlive
        );
    }

    toJson() {
        return {
            publicKey: this.publicKey,
            preSharedKey: this.psk.length > 0 ? this.psk : undefined,
            allowedIPs: this.allowedIPs ? this.allowedIPs : undefined,
            endpoint: this.endpoint,
            keepAlive: this.keepAlive ?? undefined,
        };
    }
};

Outbound.HysteriaSettings = class extends CommonClass {
    constructor(address = '', port = 443, version = 2) {
        super();
        this.address = address;
        this.port = port;
        this.version = version;
    }

    static fromJson(json = {}) {
        if (Object.keys(json).length === 0) return new Outbound.HysteriaSettings();
        return new Outbound.HysteriaSettings(
            json.address,
            json.port,
            json.version
        );
    }

    toJson() {
        return {
            address: this.address,
            port: this.port,
            version: this.version
        };
    }
};
// Dialect11 native carrier editors keep their JSON as data. This avoids losing
// nested protocol options when switching between the typed form and JSON tab.
Outbound.NativeSettings = class extends CommonClass {
    static supports(protocol) {
        return [Protocols.Orbit, Protocols.DNSTT, Protocols.OpenVPN, Protocols.AnyTLS, Protocols.ShadowTLS, Protocols.Mieru, 'ov'].includes(protocol);
    }

    static clone(value) {
        return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
    }

    static isObject(value) {
        return value !== null && typeof value === 'object' && !Array.isArray(value);
    }

    static defaults(kind) {
        switch (kind) {
            case 'orbit': return {address: '', port: 443, key: '', transport: 'tcp'};
            case 'dnstt': return {domain: '', publicKey: '', resolvers: [{transport: 'udp', address: ''}], inner: {protocol: 'vless', uuid: ''}};
            case 'openvpn': return {server: {address: '', port: 1194, network: 'udp'}, certificates: {ca: '', cert: '', key: ''}, advanced: {dev: 'tun', nobind: true, remoteCertTls: 'server', mtu: 1400}};
            case 'anytls': return {address: '', port: 443, password: ''};
            case 'shadowtls': return {address: '', port: 443, password: '', version: 3, serverName: ''};
            case 'mieru': return {address: '', port: 443, username: '', password: '', transport: 'tcp'};
            default: return {};
        }
    }

    constructor(protocol, json) {
        super();
        this.protocol = protocol;
        this.kind = protocol === 'dns' ? 'dnstt' : protocol === 'ov' ? 'openvpn' : protocol;
        this.envelope = {};
        if (protocol === 'dns' && Outbound.NativeSettings.isObject(json)) {
            this.envelope = Outbound.NativeSettings.clone(json);
            delete this.envelope.tunnel;
            this.data = Outbound.NativeSettings.clone(json.tunnel);
        } else {
            this.data = json === undefined ? Outbound.NativeSettings.defaults(this.kind) : Outbound.NativeSettings.clone(json);
        }
        this.inputMode = this.kind === 'openvpn'
            ? (this.read('ovpn') !== undefined ? 'text' : this.read('ovpnBase64') !== undefined ? 'base64' : 'structured')
            : this.read('link') !== undefined ? 'link' : 'fields';
    }

    read(path) {
        let value = this.data;
        for (const key of path.split('.')) {
            if (value === null || typeof value !== 'object' || !Object.prototype.hasOwnProperty.call(value, key)) return undefined;
            value = value[key];
        }
        return value;
    }

    write(path, value) {
        const keys = path.split('.');
        if (keys.some(key => ['__proto__', 'prototype', 'constructor'].includes(key))) throw new Error('Invalid settings path');
        if (!Outbound.NativeSettings.isObject(this.data)) return;
        const assign = (object, key, item) => {
            if (typeof Vue !== 'undefined' && Vue.set) Vue.set(object, key, item);
            else object[key] = item;
        };
        let target = this.data;
        for (let i = 0; i < keys.length - 1; i++) {
            if (target[keys[i]] === null || typeof target[keys[i]] !== 'object') assign(target, keys[i], {});
            target = target[keys[i]];
        }
        const key = keys[keys.length - 1];
        if (value === undefined) {
            if (typeof Vue !== 'undefined' && Vue.delete) Vue.delete(target, key);
            else delete target[key];
        } else assign(target, key, value);
    }

    value(field) {
        const value = this.read(field.path);
        if (field.type === 'boolean') return value === undefined ? field.default === true : value === true;
        if (field.path === 'browser' && typeof value === 'boolean') return value ? 'on' : 'off';
        if (field.type === 'textarea' && Array.isArray(value)) return value.join('\n');
        return value;
    }

    setField(field, event) {
        let value = event && event.target ? event.target.value : event;
        if (field.path === 'certificates.keyDirection' && (value === '' || value === null)) value = undefined;
        if (field.type === 'number') value = value === '' || value === null ? undefined : Number(value);
        if (field.omitFalse && value === false) value = undefined;
        this.write(field.path, value);
    }

    changeInputMode(mode) {
        if (this.kind === 'openvpn') {
            for (const key of ['server', 'auth', 'crypto', 'certificates', 'advanced', 'ovpn', 'ovpnBase64']) this.write(key, undefined);
            if (mode === 'structured') for (const [key, value] of Object.entries(Outbound.NativeSettings.defaults('openvpn'))) this.write(key, value);
            else this.write(mode === 'text' ? 'ovpn' : 'ovpnBase64', '');
        } else if (this.kind === 'orbit') {
            for (const key of ['link', 'address', 'port', 'key', 'transport', 'host', 'path', 'peer', 'fingerprint', 'fp', 'userAgent', 'ua', 'headers', 'browser', 'security', 'reality']) this.write(key, undefined);
            if (mode === 'link') this.write('link', '');
            else for (const [key, value] of Object.entries(Outbound.NativeSettings.defaults('orbit'))) this.write(key, value);
        }
        this.inputMode = mode;
    }

    get proofEnabled() { return this.read('clientProof') !== undefined; }
    setProofEnabled(enabled) { this.write('clientProof', enabled ? {keyId: '', key: ''} : undefined); }
    get proofKeyMode() { return this.read('clientProof.keyFile') === undefined ? 'key' : 'keyFile'; }
    setProofKeyMode(mode) {
        this.write('clientProof.key', undefined);
        this.write('clientProof.keyFile', undefined);
        this.write('clientProof.' + mode, '');
    }

    get resolvers() { return Array.isArray(this.read('resolvers')) ? this.read('resolvers') : []; }
    addResolver() {
        const resolvers = Outbound.NativeSettings.clone(this.resolvers);
        resolvers.push({transport: 'udp', address: ''});
        this.write('resolvers', resolvers);
    }
    removeResolver(index) { this.write('resolvers', this.resolvers.filter((_, i) => i !== index)); }

    get hasQuicWarning() {
        if (this.kind !== 'orbit') return false;
        if (this.read('transport') === 'quic') return true;
        const link = this.read('link');
        if (typeof link !== 'string' || link.length > 32768 || !/^(orbit|core):\/\//i.test(link)) return false;
        const start = link.indexOf('&');
        if (start < 0) return false;
        return new URLSearchParams(link.slice(start + 1).split('#')[0]).getAll('transport').some(value => value.toLowerCase() === 'quic');
    }

    get help() {
        switch (this.kind) {
            case 'shadowtls': return 'ShadowTLS is a TCP carrier. Route an inner SOCKS, VLESS or Shadowsocks outbound through this tag with proxySettings: {tag: "this-carrier-tag", transportLayer: true}. It does not send destination addresses itself.';
            case 'dnstt': return 'DNS tunneling carries an authenticated inner VLESS or SOCKS connection. Use the public key of your DNSTT listener and a resolver that can resolve its delegated domain. Ordinary DNS outbound behavior is separate.';
            case 'openvpn': return 'Choose exactly one OpenVPN configuration format. clientProof is optional authentication compatibility and requires a server configured for the same key ID and secret.';
            case 'orbit': return 'Use a complete Orbit link or separate connection fields. TCP/QUIC require a numeric server IP. Reality is available only with the TCP carrier.' + (this.hasQuicWarning ? ' Warning: this QUIC compatibility mode exposes bearer credentials to a passive network observer. Use TCP, WS, WSS or TCP Reality for TLS-protected credentials.' : '');
            case 'anytls': return 'TLS is configured inside these settings. UUID hash compatibility is optional and must match the server; it is not stronger encryption.';
            case 'mieru': return 'The native TCP or UDP transport carries both TCP and UDP destinations. UUID metadata compatibility is optional and requires a UUID username and matching server.';
            default: return '';
        }
    }

    get fields() {
        const fields = [];
        const add = (path, label, type = 'text', options = {}) => fields.push({path, label, type, ...options});
        const endpoint = (prefix = '') => {
            add(prefix + 'address', 'Server address');
            add(prefix + 'port', 'Server port', 'number', {min: 1, max: 65535});
        };
        const compatibility = (path, label, help) => add(path, label, 'boolean', {omitFalse: true, help});
        switch (this.kind) {
            case 'orbit':
                if (this.inputMode === 'link') add('link', 'Orbit link', 'password');
                else {
                    endpoint(); add('key', 'Connection key', 'password');
                    add('transport', 'Carrier', 'select', {options: ['tcp', 'quic', 'ws', 'wss']});
                    if (['ws', 'wss'].includes(this.read('transport'))) {
                        add('host', 'HTTP host'); add('path', 'WebSocket path'); add('peer', 'Peer name');
                        if (this.read('transport') === 'wss') add(this.read('fp') === undefined ? 'fingerprint' : 'fp', 'TLS fingerprint');
                        add(this.read('ua') === undefined ? 'userAgent' : 'ua', 'User agent');
                        add('browser', 'Browser handshake', 'select', {options: ['on', 'off']});
                    }
                    if (!this.read('transport') || this.read('transport') === 'tcp') {
                        add('security', 'TCP security', 'select', {options: ['', 'reality']});
                        if (this.read('security') === 'reality') {
                            for (const [path, label] of [['serverName', 'Reality server name'], ['publicKey', 'Reality public key'], ['shortId', 'Reality short ID'], ['fingerprint', 'Reality fingerprint']]) add('reality.' + path, label);
                        }
                    }
                }
                add('resolver', 'DNS resolver (numeric IP:port)');
                break;
            case 'dnstt':
                add('domain', 'Delegated tunnel domain'); add('publicKey', 'Server public key (64 hex)');
                add('inner.protocol', 'Inner protocol', 'select', {options: ['vless', 'socks']});
                if (this.read('inner.protocol') === 'socks') { add('inner.username', 'Inner username'); add('inner.password', 'Inner password', 'password'); }
                else add('inner.uuid', 'Inner VLESS UUID');
                for (const [path, label, min, max] of [
                    ['queryTimeout', 'Query timeout (s)', 0, 60], ['maxConcurrentQueries', 'Concurrent queries', 0, 256],
                    ['minQueryIntervalMs', 'Minimum query interval (ms)', 0, 60000], ['ednsPayloadSize', 'EDNS payload size', 512, 4096],
                    ['maxQnameLength', 'Maximum QName length', 64, 255], ['labelMin', 'Minimum label length', 1, 63], ['labelMax', 'Maximum label length', 1, 63],
                ]) add(path, label, 'number', {min, max});
                break;
            case 'openvpn':
                if (this.inputMode === 'text') add('ovpn', 'Inline OpenVPN configuration', 'textarea');
                else if (this.inputMode === 'base64') add('ovpnBase64', 'Base64 OpenVPN configuration', 'textarea');
                else {
                    endpoint('server.'); add('server.network', 'Network', 'select', {options: ['udp', 'tcp', 'udp4', 'udp6', 'tcp4', 'tcp6']});
                    add('auth.user', 'Username'); add('auth.pass', 'Password', 'password');
                    add('crypto.cipher', 'Cipher'); add('crypto.dataCiphers', 'Data ciphers', 'tags'); add('crypto.authHash', 'Auth hash');
                    for (const [key, label] of [['ca', 'CA certificate'], ['cert', 'Client certificate'], ['key', 'Client private key'], ['tlsCrypt', 'tls-crypt key'], ['tlsAuth', 'tls-auth key'], ['tlsCryptV2', 'tls-crypt-v2 key']]) add('certificates.' + key, label, 'textarea');
                    add('certificates.keyDirection', 'tls-auth key direction', 'select', {options: ['', 0, 1], help: 'Default leaves key direction unset (bidirectional). Use 0/1 only when the server uses the complementary direction.'});
                    add('advanced.mtu', 'Tunnel MTU', 'number', {min: 576, max: 65535});
                    add('advanced.remoteCertTls', 'Verify server certificate usage', 'select', {options: ['server', '']});
                    add('advanced.nobind', 'Do not bind local port', 'boolean');
                }
                if (this.inputMode !== 'structured') { add('username', 'Username override'); add('password', 'Password override', 'password'); add('mtu', 'Tunnel MTU', 'number', {min: 0, max: 65535}); }
                add('domainStrategy', 'Domain strategy', 'select', {options: ['', 'ForceIP', 'ForceIPv4', 'ForceIPv6', 'ForceIPv4v6', 'ForceIPv6v4']});
                if (this.proofEnabled) {
                    add('clientProof.keyId', 'Proof key ID');
                    add('clientProof.' + this.proofKeyMode, this.proofKeyMode === 'key' ? 'Proof secret (64 hex)' : 'Proof secret file', this.proofKeyMode === 'key' ? 'password' : 'text');
                }
                break;
            case 'anytls':
                endpoint(); add('password', 'Password', 'password');
                compatibility('uuidHashMiddle', 'UUID hash compatibility', 'Match the server account mode. This changes authentication compatibility, not encryption strength.');
                add('tlsSettings.serverName', 'TLS server name'); add('tlsSettings.fingerprint', 'TLS fingerprint');
                add('tlsSettings.allowInsecure', 'Allow insecure certificate', 'boolean', {omitFalse: true});
                for (const [path, label] of [['idleSessionCheckInterval', 'Idle check interval (s)'], ['idleSessionTimeout', 'Idle timeout (s)'], ['minIdleSession', 'Minimum idle sessions']]) add(path, label, 'number', {min: 0, max: 4294967295});
                break;
            case 'shadowtls':
                endpoint(); add('version', 'Version', 'select', {options: [1, 2, 3]}); add('password', 'Password', 'password');
                add('serverName', 'Handshake server name'); add('fingerprint', 'TLS fingerprint');
                add('strict', 'Strict handshake verification', 'boolean', {default: true});
                add('allowInsecure', 'Allow insecure certificate', 'boolean', {omitFalse: true}); add('caPem', 'Custom CA PEM', 'textarea');
                compatibility('uuidSessionId', 'UUID session compatibility', 'Version 3 only; requires a UUID password and the matching server account mode.');
                break;
            case 'mieru':
                endpoint(); add('username', 'Username'); add('password', 'Password', 'password');
                add('transport', 'Transport', 'select', {options: ['tcp', 'udp']});
                compatibility('uuidMetadataTrailer', 'UUID metadata compatibility', 'Requires a UUID username and the matching server account mode.');
                break;
        }
        if (this.kind !== 'openvpn') add('handshakeTimeout', 'Handshake timeout (s)', 'number', {min: 0, max: this.kind === 'orbit' ? 90 : this.kind === 'anytls' ? 4294967295 : 300});
        return fields;
    }

    resolverFields(index) {
        const prefix = 'resolvers.' + index + '.';
        const fields = [{path: prefix + 'transport', label: 'Resolver transport', type: 'select', options: ['udp', 'dot', 'doh']}, {path: prefix + 'address', label: 'Resolver address', type: 'text'}];
        if (this.read(prefix + 'transport') !== 'udp') {
            for (const [path, label] of [['bootstrap', 'Bootstrap IP'], ['serverName', 'TLS server name'], ['fingerprint', 'TLS fingerprint'], ['caPem', 'Custom CA PEM']]) fields.push({path: prefix + path, label, type: path === 'caPem' ? 'textarea' : 'text'});
        }
        return fields;
    }

    get validationErrors() {
        const errors = [];
        const object = Outbound.NativeSettings.isObject;
        if (!object(this.data)) return ['Protocol settings must be a JSON object.'];
        const required = (path, label = path) => { if (typeof this.read(path) !== 'string' || !this.read(path).trim()) errors.push(label + ' is required.'); };
        const integer = (path, min, max, required = false) => {
            const value = this.read(path);
            if (value === undefined && !required) return;
            if (!Number.isInteger(value) || value < min || value > max) errors.push(path + ' must be an integer between ' + min + ' and ' + max + '.');
        };
        const endpoint = (prefix = '') => { required(prefix + 'address'); integer(prefix + 'port', 1, 65535, true); };
        const uuid = path => { if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(this.read(path) || '')) errors.push(path + ' must be a UUID.'); };
        const choice = (path, choices) => { if (this.read(path) !== undefined && !choices.includes(this.read(path))) errors.push(path + ' has an unsupported value.'); };
        for (const field of this.fields) if (field.type === 'boolean' && this.read(field.path) !== undefined && typeof this.read(field.path) !== 'boolean') errors.push(field.path + ' must be a boolean.');
        switch (this.kind) {
            case 'orbit':
                if (this.read('link') !== undefined) {
                    required('link');
                    if (['address', 'port', 'key', 'transport', 'host', 'path', 'peer', 'fingerprint', 'fp', 'userAgent', 'ua', 'headers', 'browser', 'security', 'reality'].some(key => this.read(key) !== undefined)) errors.push('Use an Orbit link or separate fields, not both.');
                } else {
                    endpoint(); required('key'); choice('transport', ['tcp', 'quic', 'ws', 'wss']); choice('browser', [true, false, 'on', 'off']);
                    if (this.read('security') === 'reality' && ![undefined, 'tcp'].includes(this.read('transport'))) errors.push('Reality requires the TCP carrier.');
                    if (this.read('security') === 'reality') { required('reality.serverName'); required('reality.publicKey'); }
                }
                break;
            case 'dnstt':
                required('domain');
                if (!/^[0-9a-f]{64}$/i.test(this.read('publicKey') || '') || /^0{64}$/.test(this.read('publicKey') || '')) errors.push('A nonzero 64-hex server public key is required.');
                if (this.resolvers.length < 1 || this.resolvers.length > 16) errors.push('Use between 1 and 16 DNS resolvers.');
                this.resolvers.forEach((resolver, i) => {
                    if (!object(resolver)) { errors.push('Each DNS resolver must be an object.'); return; }
                    required('resolvers.' + i + '.address');
                    if (!['udp', 'dot', 'doh'].includes(resolver.transport)) errors.push('Resolver transport must be udp, dot or doh.');
                    if (resolver.transport === 'udp' && ['bootstrap', 'serverName', 'fingerprint', 'caPem'].some(key => resolver[key])) errors.push('UDP resolvers cannot use TLS fields.');
                });
                if (!object(this.read('inner')) || !['vless', 'socks'].includes(this.read('inner.protocol'))) errors.push('Choose the inner VLESS or SOCKS protocol.');
                if (this.read('inner.protocol') === 'vless') uuid('inner.uuid');
                integer('queryTimeout', 0, 60); integer('maxConcurrentQueries', 0, 256); integer('minQueryIntervalMs', 0, 60000);
                for (const [key, min, max] of [['ednsPayloadSize', 512, 4096], ['maxQnameLength', 64, 255], ['labelMin', 1, 63], ['labelMax', 1, 63]]) if (this.read(key) !== 0) integer(key, min, max);
                if (this.read('labelMin') && this.read('labelMax') && this.read('labelMin') > this.read('labelMax')) errors.push('Minimum label length cannot exceed maximum label length.');
                break;
            case 'openvpn': {
                const structured = ['server', 'auth', 'crypto', 'certificates', 'advanced'].some(key => this.read(key) !== undefined);
                const text = this.read('ovpn') !== undefined;
                const base64 = this.read('ovpnBase64') !== undefined;
                if ([structured, text, base64].filter(Boolean).length !== 1) errors.push('Choose exactly one OpenVPN configuration format.');
                if (structured) endpoint('server.');
                if (text && !(typeof this.read('ovpn') === 'string' && this.read('ovpn').trim()) && !(Array.isArray(this.read('ovpn')) && this.read('ovpn').length && this.read('ovpn').every(line => typeof line === 'string'))) errors.push('Inline OpenVPN configuration is required.');
                if (base64) required('ovpnBase64');
                if (this.proofEnabled) {
                    if (!object(this.read('clientProof'))) errors.push('clientProof must be an object.');
                    required('clientProof.keyId');
                    const key = this.read('clientProof.key'), keyFile = this.read('clientProof.keyFile');
                    if ((key !== undefined) === (keyFile !== undefined)) errors.push('clientProof requires exactly one secret or secret file.');
                    if (key !== undefined && !/^[0-9a-f]{64}$/i.test(key)) errors.push('Proof secret must be exactly 64 hexadecimal characters.');
                    if (keyFile !== undefined) required('clientProof.keyFile');
                }
                break;
            }
            case 'anytls':
                endpoint(); required('password');
                for (const path of ['idleSessionCheckInterval', 'idleSessionTimeout', 'minIdleSession']) integer(path, 0, 4294967295);
                break;
            case 'shadowtls':
                endpoint(); required('serverName'); choice('version', [1, 2, 3]);
                if (this.read('version') !== 1) required('password');
                if (this.read('uuidSessionId') === true) {
                    if (![undefined, 3].includes(this.read('version'))) errors.push('UUID session compatibility requires version 3.');
                    uuid('password');
                }
                break;
            case 'mieru':
                endpoint(); required('username'); required('password'); choice('transport', ['tcp', 'udp']);
                if (this.read('uuidMetadataTrailer') === true) uuid('username');
                if ((this.read('username') || '').length > 256 || (this.read('password') || '').length > 4096) errors.push('Mieru credentials exceed the supported length.');
                break;
        }
        if (this.kind !== 'openvpn') integer('handshakeTimeout', 0, this.kind === 'orbit' ? 90 : this.kind === 'anytls' ? 4294967295 : 300);
        return errors;
    }

    toJson() {
        const data = Outbound.NativeSettings.clone(this.data);
        return this.protocol === 'dns' ? {...Outbound.NativeSettings.clone(this.envelope), tunnel: data} : data;
    }
};
