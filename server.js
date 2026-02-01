const WebSocket = require('ws');
const { PacketFactory, Packet } = require('./packets');
const crypto = require('crypto');
const { Helpers } = require('./helpers');

class NetunoServer {
    packets = {};
    constructor(port = 5999, host = '0.0.0.0', packetVer = '20211103') {
        this.wss = new WebSocket.Server({ port, host });

        this.sessions = new Map();
        this.authNodes = new Map();
        this.characters = new Map();
        this.packets = PacketFactory.get(packetVer);
        this.helpers = new Helpers();

        this.setupHandlers();
        console.log(`Started server on ws://${host}:${port}`);
        console.log(`Simulating ports: 6900=Login, 6121=Char, 5121=Map`);
        console.log(`Using ${packetVer} with charBlockSize ${this.packets.getCharBlockSize()}`);
    }

    setupHandlers() {
        this.wss.on('connection', (ws, req) => {
            const { host, port } = this.helpers.parseProxyPath(req?.url);
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
    handlePacket(conn, data) {
        if (data.length < 2) return;
        const packetId = data.readUInt16LE(0);

        this.packets.logPacket('RX', conn, packetId, data);


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
            case 'login': return this.handleLogin(conn, packetId, data);
            case 'char': return this.handleChar(conn, packetId, data);
            case 'map': return this.handleMap(conn, packetId, data);
            default:
                if (packetId === this.packets.getClientPacket('CA_LOGIN')  || packetId === this.packets.getClientPacket('CA_LOGIN2'))
                    return this.handleLogin(conn, packetId, data);
                if (packetId === this.packets.getClientPacket('CH_ENTER') || packetId === this.packets.getClientPacket('CZ_ENTER'))
                    return this.handleChar(conn, packetId, data);
                console.log(`[${conn.id}] Unknown packet: 0x${packetId.toString(16)}`);
        }
    }

    handleLogin(conn, packetId, data) {
        switch (packetId) {
            case this.packets.getClientPacket('CA_LOGIN'):
            case this.packets.getClientPacket('CA_LOGIN2'):
                return this.handleClientLogin(conn, packetId, data);

            case this.packets.getClientPacket('CA_CONNECT_INFO_CHANGED'):
                console.log(`[${conn.id}] Client info changed (ignored)`);
                return;

            default:
                console.log(`[${conn.id}] Unknown login packet: 0x${packetId.toString(16)}`);
        }
    }

    handleClientLogin(conn, pid, data) {
        const version = data.readUInt32LE(2);
        const username = this.helpers.zstr(data, 6, 24);

        let password = '';
        if (pid === this.packets.getClientPacket('CA_LOGIN')) {
            password = this.helpers.zstr(data, 30, 24);
        } else if (pid === this.packets.getClientPacket('CA_LOGIN2')) {
            const md5Hash = data.slice(30, 46);
            password = md5Hash.toString('hex');
        }

        const clientType = data.length >= 55 ? data.readUInt8(54) : 0;

        console.log(`[${conn.id}] Login: user="${username}", password="${password}", clientType=${clientType}, version=${version}`);

        // Generate IDs like rAthena
        const aid = 2000000 + (this.helpers.randU32() % 1000000);  // 2xxxxxx range
        conn.aid = aid;
        conn.login_id1 = this.helpers.randI32();  // Will be AuthCode
        conn.login_id2 = this.helpers.randU32();  // Will be userLevel
        conn.sex = Math.random() > 0.5 ? 0 : 1;

        this.sessions.set(aid, {
            aid,
            login_id1: conn.login_id1,
            login_id2: conn.login_id2,
            sex: conn.sex,
            accountName: username,
            clientType,
            lastLogin: Date.now(),
        });

        // Send AC_ACCEPT_LOGIN3 (0x0AC4)
        this.sendAcceptLogin3(conn, {
            aid,
            login_id1: conn.login_id1,
            login_id2: conn.login_id2,
            sex: conn.sex,
        });
    }

    sendAcceptLogin3(conn, { aid, login_id1, login_id2, sex }) {
        // PACKET_AC_ACCEPT_LOGIN3 (0x0AC4) - 224 bytes
        const buf = Buffer.alloc(224);
        let offset = 0;
        const pkt = this.packets.getServerPacket('AC_ACCEPT_LOGIN3');

        // Header
        buf.writeUInt16LE(pkt, offset); offset += 2;
        buf.writeUInt16LE(224, offset); offset += 2;  // Fixed length

        // AuthCode (login_id1) - signed
        buf.writeInt32LE(login_id1, offset); offset += 4;

        // AID
        buf.writeUInt32LE(aid, offset); offset += 4;

        // userLevel (login_id2)
        buf.writeUInt32LE(login_id2, offset); offset += 4;

        // lastLoginIP (0 in log)
        buf.writeUInt32LE(0, offset); offset += 4;

        // lastLoginTime (26 bytes), empty
        buf.fill(0, offset, offset + 26); offset += 26;

        // Sex (1=male, 0=female in rAthena)
        buf.writeUInt8(sex, offset); offset += 1;

        // Web auth token (17 bytes) - 16 bytes token + 1 null terminator
        const token = crypto.randomBytes(8).toString('hex');  // 16 chars = 16 bytes
        buf.write(token, offset, 'ascii'); offset += 16;
        buf.writeUInt8(0, offset); offset += 1;  // Null terminator

        // Server count (1)
        buf.writeUInt8(1, offset); offset += 1;

        // Server entry, server data starts here
        // IP (127.0.0.1 = 0x7f000001 for local testing)
        buf.writeUInt32LE(0x7f000001, offset); offset += 4;

        // Port (6121 = 0x17E9)
        buf.writeUInt16LE(6121, offset); offset += 2;

        // Server name (20 bytes) - "rAthena"
        buf.fill(0, offset, offset + 20);
        buf.write('rAthena', offset, 'ascii');
        offset += 20;

        // User count (50)
        buf.writeUInt16LE(50, offset); offset += 2;

        // State (0)
        buf.writeUInt16LE(0, offset); offset += 2;

        // Property (0)
        buf.writeUInt16LE(0, offset); offset += 2;

        // Remaining padding to reach 224 bytes total
        // We've written: 2+2+4+4+4+4+26+1+17+1+4+2+20+2+2+2 = 97 bytes
        // Need 224 total, so 224 - 97 = 127 bytes padding
        const remaining = 224 - offset;
        if (remaining > 0) {
            buf.fill(0, offset, offset + remaining);
            offset += remaining;
        }

        conn.ws.send(buf);
        this.packets.logPacket('TX', conn, pkt, buf,
            `AID=${aid}, AuthCode=${login_id1}, userLevel=${login_id2}`);

        console.log(`[${conn.id}] Sent AC_ACCEPT_LOGIN3 (${pkt}), ${offset} bytes`);
    }

    handlePinPacket(conn, pid, data) {
        switch (pid) {
            case this.packets.getClientPacket('CH_SECOND_PASSWD_ACK'):
                return this.handlePinAck(conn, data);

            case this.packets.getClientPacket('CH_MAKE_SECOND_PASSWD'):
                return this.handleMakePin(conn, data);

            case this.packets.getClientPacket('CH_EDIT_SECOND_PASSWD'):
                return this.handleEditPin(conn, data);
        }
    }

    handlePinAck(conn, data) {
        if (data.length < 10) return;

        const aid = data.readUInt32LE(2);
        const pin = this.helpers.zstr(data, 6, 4);

        console.log(`[${conn.id}] PIN entered for AID=${aid}: "${pin}"`);

        // Accept any 4-digit PIN
        if (pin.length === 4 && /^\d{4}$/.test(pin)) {
            conn.pinVerified = true;
            this.sendPinRequest(conn, conn.pinSeed || this.helpers.randU32(), 0);  // Success

            console.log(`[${conn.id}] PIN verified successfully`);
        }
    }

    sendPinRequest(conn, seed, state) {
        // HC_SECOND_PASSWD_LOGIN (0x08b9) - 12 bytes
        // Structure: packet header (2) + Seed (4, Long) + Aid (4, Long) + State (2, Short)
        const buf = Buffer.alloc(12);
        const pkt = this.packets.getServerPacket('HC_SECOND_PASSWD_LOGIN')
        buf.writeUInt16LE(pkt, 0);

        // Convert unsigned values to signed for writeInt32LE
        // For values > 2147483647, convert to signed representation
        const signedSeed = seed > 2147483647 ? seed - 4294967296 : seed;
        const signedAid = (conn.aid || 0) > 2147483647 ? (conn.aid || 0) - 4294967296 : (conn.aid || 0);

        buf.writeInt32LE(signedSeed, 2);  // Seed (signed 32-bit)
        buf.writeInt32LE(signedAid, 6);  // Aid (signed 32-bit)
        buf.writeInt16LE(state, 10);  // State (signed 16-bit): 1=request, 0=success

        conn.ws.send(buf);
        this.packets.logPacket('TX', conn, pkt, buf,
            `seed=${seed}, AID=${conn.aid}, state=${state}`);
    }

    handleMakePin(conn, data) {
        const aid = data.readUInt32LE(2);
        const pin = this.helpers.zstr(data, 6, 4);

        console.log(`[${conn.id}] New PIN created for AID=${aid}: "${pin}"`);

        const session = this.sessions.get(aid);
        if (session) {
            session.hasPin = true;
        }

        conn.pinVerified = true;
        this.sendPinRequest(conn, conn.pinSeed || this.helpers.randU32(), 0);
    }

    handleEditPin(conn, data) {
        if (data.length < 14) return;

        const aid = data.readUInt32LE(2);
        const oldPin = this.helpers.zstr(data, 6, 4);
        const newPin = this.helpers.zstr(data, 10, 4);

        console.log(`[${conn.id}] PIN changed for AID=${aid}: "${oldPin}" -> "${newPin}"`);

        // Accept any PIN value - no validation
        const session = this.sessions.get(aid);
        if (session) {
            session.hasPin = true;
        }

        conn.pinVerified = true;
        this.sendPinRequest(conn, conn.pinSeed || this.helpers.randU32(), 0);  // Success

        console.log(`[${conn.id}] PIN modified successfully`);
    }

    handleChar(conn, pid, data) {
        switch (pid) {
            case this.packets.
            ('CH_ENTER'):
                return this.handleCharEnter(conn, data);

            case this.packets.getClientPacket('CH_CHARLIST_REQ'):
                return this.sendCompleteCharacterList(conn); // Send all packets together

            case this.packets.getClientPacket('CH_SELECT_CHAR'):
                return this.handleCharSelect(conn, data);

            default:
                console.log(`[${conn.id}] Unknown char packet: 0x${pid.toString(16)}`);
        }
    }

    handleCharEnter(conn, data) {
        if (data.length < 17) {
            console.log(`[${conn.id}] CH_ENTER too short: ${data.length} bytes`);
            return;
        }

        const aid = data.readUInt32LE(2);
        const authCode = data.readInt32LE(6);
        const userLevel = data.readUInt32LE(10);
        const clientType = data.readUInt16LE(14);
        const sex = data.readUInt8(16);

        console.log(`[${conn.id}] CH_ENTER: AID=${aid}, AuthCode=${authCode}, userLevel=${userLevel}, clientType=${clientType}, sex=${sex}`);

        const session = this.sessions.get(aid);
        if (!session) {
            console.log(`[${conn.id}] No session found for AID=${aid}`);
            return;
        }

        if (session.login_id1 !== authCode || session.login_id2 !== userLevel) {
            console.log(`[${conn.id}] Authentication mismatch!`);
            return;
        }

        conn.aid = aid;
        conn.login_id1 = authCode;
        conn.login_id2 = userLevel;
        conn.sex = sex;
        conn.clientType = clientType;
        conn.userLevel = userLevel;

        console.log(`[${conn.id}] Authentication successful!`);

        // Send complete character list
        setTimeout(() => {
            this.sendCompleteCharacterList(conn);
        }, 100);
    }

    sendCompleteCharacterList(conn) {
        // roBrowser expects:
        // 1. HC_ACCEPT_ENTER_NEO_UNION_HEADER (0x082d) - 29 bytes
        // 2. HC_ACCEPT_ENTER_NEO_UNION (0x006b) - variable size
        // 3. HC_CHARLIST_NOTIFY (0x09a0) - 10 bytes
        // 4. HC_BLOCK_CHARACTER (0x020d) - 4 bytes
        // 5. HC_SECOND_PASSWD_LOGIN (0x08b9) - 12 bytes with State: 1 (request PIN)

        this.sendCharListHeader(conn);
        this.sendCharListData(conn);
        this.sendCharListNotify(conn);
        this.sendBlockCharacter(conn);

        // Send PIN request after character list
        conn.pinSeed = this.helpers.randU32();
        this.sendPinRequest(conn, conn.pinSeed, 1);  // State: 1 = request PIN
    }

    sendCharListHeader(conn) {
        // HC_ACCEPT_ENTER_NEO_UNION_HEADER (0x082d) - 29 bytes
        // real server hex: 2D 08 1D 00 0F 00 00 0F 0F 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        const template = Buffer.from([
            0x2D, 0x08, 0x1D, 0x00, 0x0F, 0x00, 0x00, 0x0F, 0x0F, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ]);

        // Copy the template
        const buf = Buffer.alloc(29);
        template.copy(buf);

        // Set the sex byte
        buf.writeUInt8(conn.sex, 15);

        conn.ws.send(buf);
        this.packets.logPacket('TX', conn, this.packets.getServerPacket('HC_ACCEPT_ENTER_NEO_UNION_HEADER'), buf,
            `slots=15, sex=${conn.sex}`);
    }

    sendCharListData(conn) {
        // HC_ACCEPT_ENTER_NEO_UNION (0x006b) for packetver 20211103
        // Structure: packet header (4) + header fields (23) + character data (n * 175)

        const characters = this.helpers.charactersList();
        const pkt = this.packets.getServerPacket('HC_ACCEPT_ENTER_NEO_UNION');

        conn.charList = characters;
        this.characters.set(conn.aid, characters);

        const CHAR_INFO_SIZE = 175;  // blockSize 175 for packetver 20211103
        const HEADER_FIELDS_SIZE = 23;  // TotalSlotNum(1) + PremiumStartSlot(1) + PremiumEndSlot(1) + dummy1(1) + code(4) + time1(4) + time2(4) + dummy2(7)
        const packetLen = 4 + HEADER_FIELDS_SIZE + (characters.length * CHAR_INFO_SIZE);
        const buf = Buffer.alloc(packetLen);
        let offset = 0;

        // Packet header
        buf.writeUInt16LE(pkt, offset); offset += 2;
        buf.writeUInt16LE(packetLen, offset); offset += 2;

        // Header fields (for packetver >= 20100413)
        buf.writeUInt8(15, offset); offset += 1;  // TotalSlotNum
        buf.writeUInt8(15, offset); offset += 1;  // PremiumStartSlot
        buf.writeUInt8(15, offset); offset += 1;  // PremiumEndSlot
        buf.writeInt8(0, offset); offset += 1;    // dummy1_beginbilling
        buf.writeUInt32LE(0, offset); offset += 4; // code
        buf.writeUInt32LE(0, offset); offset += 4; // time1
        buf.writeUInt32LE(0, offset); offset += 4; // time2
        buf.fill(0, offset, offset + 7); offset += 7; // dummy2_endbilling

        for (let i = 0; i < characters.length; i++) {
            const char = characters[i];
            const charStartOffset = 4 + HEADER_FIELDS_SIZE + (i * CHAR_INFO_SIZE);

            // GID (4 bytes)
            buf.writeUInt32LE(char.GID, offset); offset += 4;

            // Base EXP (4 bytes)
            buf.writeUInt32LE(char.exp, offset); offset += 4;

            // Unknown padding (4 bytes) - for packetver >= 20170830 or blockSize >= 155
            buf.writeUInt32LE(0, offset); offset += 4;

            // Zeny (4 bytes)
            buf.writeUInt32LE(char.money, offset); offset += 4;

            // Job EXP (4 bytes)
            buf.writeUInt32LE(char.jobexp, offset); offset += 4;

            // Unknown padding (4 bytes) - for packetver >= 20170830 or blockSize >= 155
            buf.writeUInt32LE(0, offset); offset += 4;

            // Job Level (4 bytes)
            buf.writeUInt32LE(char.joblevel, offset); offset += 4;

            // Body State (4 bytes)
            buf.writeUInt32LE(char.bodystate, offset); offset += 4;

            // Health State (4 bytes)
            buf.writeUInt32LE(char.healthstate, offset); offset += 4;

            // Effect State (4 bytes)
            buf.writeUInt32LE(char.effectstate, offset); offset += 4;

            // Virtue (4 bytes)
            buf.writeUInt32LE(char.virtue, offset); offset += 4;

            // Honor (4 bytes)
            buf.writeUInt32LE(char.honor, offset); offset += 4;

            // Job Point (2 bytes)
            buf.writeUInt16LE(0, offset); offset += 2;

            // HP and Max HP (8 bytes each for blockSize >= 175)
            buf.writeUInt32LE(char.hp, offset); offset += 4;
            buf.writeUInt32LE(0, offset); offset += 4; // padding
            buf.writeUInt32LE(char.maxhp, offset); offset += 4;
            buf.writeUInt32LE(0, offset); offset += 4; // padding

            // SP and Max SP (8 bytes each for blockSize >= 175)
            buf.writeUInt32LE(char.sp, offset); offset += 4;
            buf.writeUInt32LE(0, offset); offset += 4; // padding
            buf.writeUInt32LE(char.maxsp, offset); offset += 4;
            buf.writeUInt32LE(0, offset); offset += 4; // padding

            // Speed (2 bytes)
            buf.writeUInt16LE(char.speed, offset); offset += 2;

            // Job (2 bytes)
            buf.writeUInt16LE(char.job, offset); offset += 2;

            // Head (2 bytes)
            buf.writeUInt16LE(char.head, offset); offset += 2;

            // Body (2 bytes) - for blockSize >= 147
            buf.writeUInt16LE(0, offset); offset += 2;

            // Weapon (2 bytes)
            buf.writeUInt16LE(char.weapon, offset); offset += 2;

            // Base Level (2 bytes)
            buf.writeUInt16LE(char.level, offset); offset += 2;

            // Skill Points (2 bytes)
            buf.writeUInt16LE(char.sppoint, offset); offset += 2;

            // Accessory (2 bytes)
            buf.writeUInt16LE(char.accessory, offset); offset += 2;

            // Shield (2 bytes)
            buf.writeUInt16LE(char.shield, offset); offset += 2;

            // Accessory2 (2 bytes)
            buf.writeUInt16LE(char.accessory2, offset); offset += 2;

            // Accessory3 (2 bytes)
            buf.writeUInt16LE(char.accessory3, offset); offset += 2;

            // Head Palette (2 bytes)
            buf.writeUInt16LE(char.headpalette, offset); offset += 2;

            // Body Palette (2 bytes)
            buf.writeUInt16LE(char.bodypalette, offset); offset += 2;

            // Name (24 bytes)
            buf.fill(0, offset, offset + 24);
            buf.write(char.name.substring(0, 23), offset, 'ascii');
            offset += 24;

            // Stats (Str, Agi, Vit, Int, Dex, Luk) - 6 bytes
            buf.writeUInt8(char.Str, offset); offset += 1;
            buf.writeUInt8(char.Agi, offset); offset += 1;
            buf.writeUInt8(char.Vit, offset); offset += 1;
            buf.writeUInt8(char.Int, offset); offset += 1;
            buf.writeUInt8(char.Dex, offset); offset += 1;
            buf.writeUInt8(char.Luk, offset); offset += 1;

            // Slot (1 byte) - for blockSize >= 124
            buf.writeUInt8(char.slot, offset); offset += 1;

            // Hair color (1 byte) - for blockSize >= 124
            buf.writeUInt8(0, offset); offset += 1;

            // Rename flag (2 bytes) - for blockSize >= 124
            buf.writeUInt16LE(char.rename, offset); offset += 2;

            // Map Name (16 bytes) - for blockSize >= 124
            buf.fill(0, offset, offset + 16);
            buf.write(char.mapname.substring(0, 15), offset, 'ascii');
            offset += 16;

            // Delete Date (4 bytes) - for blockSize >= 132
            buf.writeUInt32LE(char.delete_date, offset); offset += 4;

            // Robe (4 bytes) - for blockSize >= 136
            buf.writeUInt32LE(char.robe, offset); offset += 4;

            // Slot Addon (4 bytes) - for blockSize >= 140
            buf.writeUInt32LE(0, offset); offset += 4;

            // Rename Addon (4 bytes) - for blockSize >= 144
            buf.writeUInt32LE(0, offset); offset += 4;

            // Sex (1 byte) - for blockSize >= 145
            buf.writeUInt8(char.gender, offset); offset += 1;

            // Remaining padding to reach exactly 175 bytes per character
            const charBytesUsed = offset - charStartOffset;
            const remaining = CHAR_INFO_SIZE - charBytesUsed;
            if (remaining > 0) {
                buf.fill(0, offset, offset + remaining);
                offset += remaining;
            }
        }

        conn.ws.send(buf);
        this.packets.logPacket('TX', conn, pkt, buf,
            `characters=${characters.length}, blockSize=175, total=${packetLen} bytes`);
    }

    sendCharListNotify(conn) {
        // HC_CHARLIST_NOTIFY (0x09a0) - 10 bytes for packetver >= 20151001
        // Structure: packet header (2) + TotalCnt (4) + charSlots (4)
        const charCount = (conn.charList || []).length;
        const buf = Buffer.alloc(10);
        const pkt = this.packets.getServerPacket('HC_CHARLIST_NOTIFY');
        buf.writeUInt16LE(pkt, 0);
        buf.writeUInt32LE(charCount, 2);  // TotalCnt (Long)
        buf.writeUInt32LE(charCount, 6);  // charSlots (Long)

        conn.ws.send(buf);
        this.packets.logPacket('TX', conn, pkt, buf, `TotalCnt=${charCount}`);
    }

    sendBlockCharacter(conn) {
        // HC_BLOCK_CHARACTER (0x020d) - 4 bytes
        const buf = Buffer.alloc(4);
        const pkt = this.packets.getServerPacket('HC_BLOCK_CHARACTER');
        buf.writeUInt16LE(pkt, 0);
        buf.writeUInt16LE(0, 2);  // Empty list

        conn.ws.send(buf);
        this.packets.logPacket('TX', conn, pkt, buf, 'block list');
    }

    handleCharSelect(conn, data) {
        if (data.length < 3) return;

        const slot = data.readUInt8(2);
        console.log(`[${conn.id}] Character selected: slot=${slot}`);

        const characters = this.characters.get(conn.aid) || [];
        const selectedChar = characters.find(c => c.slot === slot);

        if (!selectedChar) {
            console.log(`[${conn.id}] Invalid character slot`);
            return;
        }

        conn.selectedChar = selectedChar;

        // Create auth node
        const authNode = {
            account_id: conn.aid,
            char_id: selectedChar.GID,
            login_id1: conn.login_id1,
            login_id2: conn.login_id2,
            sex: conn.sex,
            clientType: conn.clientType,
            ip: '127.0.0.1',  // Local testing
            port: 5121,
            timestamp: Date.now(),
        };

        this.authNodes.set(conn.aid, authNode);
        console.log(`[${conn.id}] Created auth node: CID=${selectedChar.GID}`);

        // Send map server info
        this.sendMapServerInfo(conn, selectedChar);
    }

    sendMapServerInfo(conn, char) {
        // HC_NOTIFY_ZONESVR2 (0x0ac5) - 156 bytes
        const buf = Buffer.alloc(156);
        const pkt = this.packets.getServerPacket('HC_NOTIFY_ZONESVR2');
        let offset = 0;

        buf.writeUInt16LE(pkt, offset); offset += 2;
        buf.writeUInt32LE(char.GID, offset); offset += 4;

        // Map name (16 bytes) - "prontera.gat"
        buf.fill(0, offset, offset + 16);
        buf.write('prontera.gat', offset, 'ascii');
        offset += 16;

        // IP (127.0.0.1 = 0x7f000001) and port (5121 = 0x1401)
        buf.writeUInt32LE(0x7f000001, offset); offset += 4;
        buf.writeUInt16LE(5121, offset); offset += 2;

        // Fill the rest with zeros (134 bytes)
        buf.fill(0, offset, buf.length);

        conn.ws.send(buf);
        this.packets.logPacket('TX', conn, pkt, buf,
            `CID=${char.GID}, map=prontera.gat`);

        console.log(`[${conn.id}] Sent map server handoff to prontera.gat:5121`);
    }

    handleMap(conn, pid, data) {
        switch (pid) {
            case 0x0436:  // CZ_ENTER2 from log
                return this.handleMapEnter(conn, data);

            default:
                console.log(`[${conn.id}] Unknown map packet: 0x${pid.toString(16)}`);
        }
    }

    handleMapEnter(conn, data) {
        // CZ_ENTER2 (0x0436) - 23 bytes from log
        if (data.length < 23) return;

        const aid = data.readUInt32LE(2);
        const GID = data.readUInt32LE(6);
        const authCode = data.readInt32LE(10);
        const clientTime = data.readUInt32LE(14);
        const unknown = data.readUInt32LE(18);
        const sex = data.readUInt8(22);

        console.log(`[${conn.id}] CZ_ENTER2: AID=${aid}, GID=${GID}, authCode=${authCode}, sex=${sex}, clientTime=${clientTime}`);

        const authNode = this.authNodes.get(aid);
        if (!authNode) {
            console.log(`[${conn.id}] No auth node found`);
            return;
        }

        if (authNode.login_id1 !== authCode) {
            console.log(`[${conn.id}] Auth code mismatch`);
            return;
        }

        conn.aid = aid;

        // Send map server responses
        this.sendMapAccept(conn, authNode);
    }

    sendMapAccept(conn, authNode) {
        // ZC_AID (0x0283) - 6 bytes
        const aidBuf = Buffer.alloc(6);
        const pkt = this.packets.getServerPacket('ZC_AID');
        const pkt2 = this.packets.getServerPacket('ZC_EXTEND_BODYITEM_SIZE');
        const pkt3 = this.packets.getServerPacket('ZC_ACCEPT_ENTER2');
        aidBuf.writeUInt16LE(pkt, 0);
        aidBuf.writeUInt32LE(authNode.account_id, 2);
        conn.ws.send(aidBuf);
        this.packets.logPacket('TX', conn, pkt, aidBuf, `AID=${authNode.account_id}`);

        // ZC_EXTEND_BODYITEM_SIZE (0x0b18) - 4 bytes
        const sizeBuf = Buffer.alloc(4);
        sizeBuf.writeUInt16LE(pkt2, 0);
        sizeBuf.writeUInt16LE(0, 2);  // type=0
        conn.ws.send(sizeBuf);
        this.packets.logPacket('TX', conn, pkt2, sizeBuf, 'extend size');

        // ZC_ACCEPT_ENTER2 (0x02eb) - 13 bytes
        const acceptBuf = Buffer.alloc(13);
        acceptBuf.writeUInt16LE(pkt3, 0);
        acceptBuf.writeUInt32LE(Math.floor(Date.now() / 1000), 2);  // startTime
        acceptBuf.writeUInt16LE(159, 6);  // x
        acceptBuf.writeUInt16LE(187, 8);  // y
        acceptBuf.writeUInt8(0, 10);      // dir
        acceptBuf.writeUInt8(5, 11);      // xSize
        acceptBuf.writeUInt8(5, 12);      // ySize

        conn.ws.send(acceptBuf);
        this.packets.logPacket('TX', conn, pkt3, acceptBuf, 'map accept');

        console.log(`[${conn.id}] Map server authentication successful`);
    }
}

const _server = new NetunoServer();

process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});