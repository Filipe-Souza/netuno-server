const PACKET_DEFINITIONS = {
    '20211103': {
        'charBlockSize': 175,
        'client': {
            // Client -> Server
            CA_LOGIN: 0x0064,
            CA_LOGIN2: 0x0277,
            CA_CONNECT_INFO_CHANGED: 0x0200,
            CH_ENTER: 0x0065,
            CH_SELECT_CHAR: 0x0066,
            CH_CHARLIST_REQ: 0x09a1,
            CH_SECOND_PASSWD_ACK: 0x08b8,  // PIN code check
            CH_MAKE_SECOND_PASSWD: 0x08b7,
            CH_EDIT_SECOND_PASSWD: 0x08bb,
            CZ_ENTER: 0x0436,  // Actually 0x0436 in log, renamed for clarity
        },
        'server': {
            // Server -> Client
            AC_ACCEPT_LOGIN3: 0x0ac4,        // Modern accept login (224 bytes)
            AC_REFUSE_LOGIN: 0x006a,
            HC_ACCEPT_ENTER_NEO_UNION_HEADER: 0x082d,  // Char list header
            HC_ACCEPT_ENTER_NEO_UNION: 0x006b,        // Char list data
            HC_CHARLIST_NOTIFY: 0x09a0,      // Char list notification
            HC_BLOCK_CHARACTER: 0x020d,      // Block character list
            HC_SECOND_PASSWD_LOGIN: 0x08b9,  // PIN request/success
            HC_NOTIFY_ZONESVR2: 0x0ac5,      // Map server info (156 bytes)
            ZC_AID: 0x0283,                  // AID notification
            ZC_ACCEPT_ENTER2: 0x02eb,        // Map server accept
            ZC_EXTEND_BODYITEM_SIZE: 0x0b18, // Extended body item size
        }
    },
    '20170830': {
        'charBlockSize': 155,
        'client': {},
        'server': {}
    }
}
class Packets {
    constructor(packetVer) {
        if (!PACKET_DEFINITIONS[packetVer]) {
            throw new Error(`Unknown packet ID: ${packetVer}`);
        }
        this.definition = PACKET_DEFINITIONS[packetVer];
        this.id = packetVer;
        this.data = null;
    }
    getCharBlockSize() {
        return this.definition.charBlockSize || 0;
    }

    getClientPacket(name) {
        return this.definition.client?.[name];
    }

    getServerPacket(name) {
        return this.definition.server?.[name];
    }

    getClientPacketName(opcode) {
        return Object.keys(this.definition.client || {}).find(
            key => this.definition.client[key] === opcode
        );
    }

    getServerPacketName(opcode) {
        return Object.keys(this.definition.server || {}).find(
            key => this.definition.server[key] === opcode
        );
    }

    getAllClientPackets() {
        return { ...this.definition.client };
    }

    getAllServerPackets() {
        return { ...this.definition.server };
    }

    getDefinition() {
        return { ...this.definition };
    }

    // Logging helper (assuming you have a hex function)
    logPacket(dir, conn, pid, data, extra = '') {
        const pidStr = pid.toString(16).padStart(4, '0');
        const type = (conn.serverType || 'UNKNOWN').toUpperCase().padEnd(5, ' ');
        // Make sure hex function is available
        const hexStr = this._hex(data, 32);
        console.log(`${dir} [${conn.id}] ${type} 0x${pidStr} len=${data.length}` +
            (extra ? ` ${extra}` : '') + ` hex=${hexStr}`);
    }
    _hex(buffer, max = 96) {
        const b = Buffer.from(buffer);
        const s = b.slice(0, max).toString('hex').match(/../g)?.join(' ') ?? '';
        return b.length > max ? `${s} ... (+${b.length - max} bytes)` : s;
    }

    isClientPacket(opcode) {
        return Object.values(this.definition.client || {}).includes(opcode);
    }

    isServerPacket(opcode) {
        return Object.values(this.definition.server || {}).includes(opcode);
    }
    getPacketInfo(opcode) {
        const clientName = this.getClientPacketName(opcode);
        const serverName = this.getServerPacketName(opcode);

        if (clientName) {
            return { direction: 'client', name: clientName, opcode };
        } else if (serverName) {
            return { direction: 'server', name: serverName, opcode };
        }
        return null;
    }
}
class PacketFactory {
    static cache = new Map();

    static get(packetId) {
        if (this.cache.has(packetId)) {
            return this.cache.get(packetId);
        }

        const packet = new Packets(packetId);
        this.cache.set(packetId, packet);
        return packet;
    }

    static getDefinition(packetId) {
        return this.get(packetId).getDefinition();
    }

    static getClientPacket(packetId, packetName) {
        return this.get(packetId).getClientPacket(packetName);
    }

    static getServerPacket(packetId, packetName) {
        return this.get(packetId).getServerPacket(packetName);
    }

    static getPacketInfo(packetId, opcode) {
        return this.get(packetId).getPacketInfo(opcode);
    }

    static getAllIds() {
        return Object.keys(PACKET_DEFINITIONS);
    }
}

// Export both the class and factory
module.exports = {
    Packets,
    PacketFactory,
    PACKET_DEFINITIONS
};