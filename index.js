const WebSocket = require('ws');
const { PacketFactory, Packet } = require('./packets');
const { Helpers } = require('./helpers');
const {LoginServer} = require("./servers/login");
const {CharServer} = require("./servers/char");

class NetunoServer {
    packets = {};
    LoginServer = null;

    constructor(port = 5999, host = '0.0.0.0', packetVer = '20211103') {
        this.wss = new WebSocket.Server({port, host});

        this.sessions = new Map();
        this.authNodes = new Map();
        this.characters = new Map();
        this.packets = PacketFactory.get(packetVer);
        this.helpers = new Helpers();
        this.LoginServer = new LoginServer(packetVer, this.packets);

        this.setupHandlers();
        console.log(`Started server on ws://${host}:${port}`);
        console.log(`Simulating ports: 6900=Login, 6121=Char, 5121=Map`);
        console.log(`Using ${packetVer} with charBlockSize ${this.packets.getCharBlockSize()}`);
    }

    handlePacket(conn, data) {
        if (data.length < 2) return;
        const packetId = data.readUInt16LE(0);

        this.helpers.log('INFO', `Received packet: 0x${packetId.toString(16)}`);

        if (packetId === this.packets.getClientPacket('CH_SECOND_PASSWD_ACK') ||
            packetId === this.packets.getClientPacket('CH_MAKE_SECOND_PASSWD') ||
            packetId === this.packets.getClientPacket('CH_EDIT_SECOND_PASSWD')) {
            return this.handlePinPacket(conn, packetId, data);
        }

        // Auto-detect server type by packet ID if unknown
        if (conn.serverType === 'unknown') {
            if (packetId === this.packets.getClientPacket('CA_LOGIN') || packetId === this.packets.getClientPacket('CA_LOGIN2')) {
                conn.serverType = 'login';
            } else if (packetId === this.packets.getClientPacket('CH_ENTER') || packetId === 0x0065) {
                conn.serverType = 'char';
            } else if (packetId === this.packets.getClientPacket('CZ_ENTER') || packetId === 0x0436) {
                conn.serverType = 'map';
            }
        }

        switch (conn.serverType) {
            case 'login': {
                const {sessionData, packetData} = this.LoginServer.login(conn.id, packetId, data);
                this.sessions.set(sessionData.aid, sessionData);
                conn.ws.send(packetData);
            }
            case 'char': {
                const xpto = this.CharServer.char(conn.id, this.sessions, packetId, data);
            }
            default:
                if (packetId === this.packets.getClientPacket('CA_LOGIN')  || packetId === this.packets.getClientPacket('CA_LOGIN2')) {
                    const {sessionData, packetData} = this.LoginServer.login(conn.id, packetId, data);
                    this.sessions.set(sessionData.aid, sessionData);
                    conn.ws.send(packetData);
                }
                console.log(`[${conn.id}] Unknown packet: 0x${packetId.toString(16)}`);
        }
    }

    setupHandlers() {
        this.wss.on('connection', (ws, req) => {
            const {host, port} = this.helpers.parseProxyPath(req?.url);
            const serverType = this.helpers.serverTypePort(port);

            const conn = {
                ws,
                url: req?.url || '',
                targetHost: host,
                targetPort: port,
                serverType,

                aid: null,
                login_id1: null,
                login_id2: null,
                sex: 1,
                clientType: 0,
                userLevel: 0,

                pinSeed: null,
                pinVerified: false,
                hasPin: false,

                selectedChar: null,
                charList: null,

                id: this.helpers.randU32(),
                connectedAt: Date.now(),
            };

            console.log(`[${conn.id}] Connected to ${serverType} server (port ${port})`);

            ws.on('message', (data) => {
                if (!Buffer.isBuffer(data)) data = Buffer.from(data);
                try {
                    this.handlePacket(conn, data);
                } catch (e) {
                    console.error(`[${conn.id}] Error:`, e);
                }
            });

            ws.on('close', () => {
                console.log(`[${conn.id}] Disconnected from ${conn.serverType}`);
            });
        });
    }
}

const _server = new NetunoServer();

process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});