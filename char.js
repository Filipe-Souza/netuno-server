const crypto = require('crypto');
const { Helpers } = require('./helpers');

class CharServer {
    packets = {}
    packetVer = "";

    constructor(packetVer, packets) {
        this.helpers = new Helpers();
        this.packetVer = packetVer;
        this.packets = packets;
    }

    _charactersList() {
        return [
            {
                GID: 150004,
                exp: 0,
                money: 100000,
                jobexp: 0,
                joblevel: 1,
                bodystate: 0,
                healthstate: 0,
                effectstate: 0,
                virtue: 0,
                honor: 0,
                hp: 70,
                maxhp: 70,
                sp: 11,
                maxsp: 11,
                speed: 150,
                job: 0,
                head: 0,
                weapon: 0,
                level: 1,
                sppoint: 0,
                accessory: 0,
                shield: 0,
                accessory2: 0,
                accessory3: 0,
                headpalette: 0,
                bodypalette: 0,
                name: 'Xunda',
                Str: 1,
                Agi: 1,
                Vit: 1,
                Int: 1,
                Dex: 1,
                Luk: 1,
                slot: 0,
                rename: 0,
                mapname: 'prontera.gat',
                delete_date: 0,
                robe: 0,
                gender: 1,
            },
            {
                GID: 150003,
                exp: 0,
                money: 1000000,
                jobexp: 0,
                joblevel: 1,
                bodystate: 0,
                healthstate: 0,
                effectstate: 0,
                virtue: 0,
                honor: 0,
                hp: 171,
                maxhp: 171,
                sp: 11,
                maxsp: 11,
                speed: 150,
                job: 0,
                head: 0,
                weapon: 0,
                level: 1,
                sppoint: 0,
                accessory: 0,
                shield: 0,
                accessory2: 0,
                accessory3: 0,
                headpalette: 0,
                bodypalette: 0,
                name: 'Hot Dog',
                Str: 1,
                Agi: 1,
                Vit: 1,
                Int: 1,
                Dex: 1,
                Luk: 1,
                slot: 1,
                rename: 0,
                mapname: 'prontera.gat',
                delete_date: 0,
                robe: 0,
                gender: 1,
            }
        ];
    }

    // Base template without character data (minimum size)
    _sendCharListHeader(connId, charSex) {
        if (this.packetVer >= 20130000) {
            // PACKET_HC_ACCEPT_ENTER2, HC_ACCEPT_ENTER_NEO_UNION_HEADER (0x082d) - 29 bytes
            // real server hex: 2D 08 1D 00 0F 00 00 0F 0F 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            const template = Buffer.from([
                0x2D, 0x08, 0x1D, 0x00, 0x0F, 0x00, 0x00, 0x0F, 0x0F, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ]);
            const buf = Buffer.alloc(29);
            template.copy(buf);
            buf.writeUInt8(charSex, 15);
            this.helpers.log('INFO', `[${connId}] Sending PACKET_HC_ACCEPT_ENTER2`);
            this.helpers.logPacket(this.packets.getServerPacket('PACKET_HC_ACCEPT_ENTER2'), buf);
            return buf;
        }
    }

    _sendCharListData(connId, aid, characters) {
        const charList = this._charactersList();
        const pkt = this.packets.getServerPacket('HC_ACCEPT_ENTER_NEO_UNION');

        const CHAR_INFO_SIZE = this.packets.getCharBlockSize();
        let HEADER_FIELDS_SIZE = 0;
        if (this.packetVer >= 20100413) {
            HEADER_FIELDS_SIZE = 23;  // TotalSlotNum(1) + PremiumStartSlot(1) + PremiumEndSlot(1) + dummy1(1) + code(4) + time1(4) + time2(4) + dummy2(7)
        } else {
            // Header fields size for PACKET_HC_ACCEPT_ENTER_NEO_UNION (0x006b)
            HEADER_FIELDS_SIZE = 20;
        }

        const pktLen = 4 + HEADER_FIELDS_SIZE + (charList.length * CHAR_INFO_SIZE);
        const buf = Buffer.alloc(pktLen);

        if (this.packetVer < 20100413) {
            let offset = 0;

            // Packet header
            buf.writeUInt16LE(pkt, offset); offset += 2;
            buf.writeUInt16LE(packetLen, offset); offset += 2;

            // Header fields (for packetver <= 20100413 - no slot fields)
            buf.writeInt8(0, offset); offset += 1;    // dummy1_beginbilling
            buf.writeUInt32LE(0, offset); offset += 4; // code
            buf.writeUInt32LE(0, offset); offset += 4; // time1
            buf.writeUInt32LE(0, offset); offset += 4; // time2
            buf.fill(0, offset, offset + 7); offset += 7; // dummy2_endbilling

            for (let i = 0; i < charList.length; i++) {
                const char = charList[i];
                const charStartOffset = 4 + HEADER_FIELDS_SIZE + (i * CHAR_INFO_SIZE); // HEADER_FIELDS_SIZE is now 20

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
    }
        else {
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
        }

        this.helpers.log('INFO', `[${connId}] Sending HC_ACCEPT_ENTER_NEO_UNION, charBlockSize=${CHAR_INFO_SIZE}, total=${pktLen}`);
        this.helpers.logPacket(pkt, buf);

        return buf;
    }

    _sendCharListNotify(connId, charList){
        const pkt = this.packets.getServerPacket('HC_CHARLIST_NOTIFY');
        const charCount = (charList || []).length;
        if (this.packetVer >= 20151001) {
            // HC_CHARLIST_NOTIFY (0x09a0) - 10 bytes for packetver >= 20151001
            // Structure: packet header (2) + TotalCnt (4) + charSlots (4)
            const buf = Buffer.alloc(10);
            buf.writeUInt16LE(pkt, 0);
            buf.writeUInt32LE(charCount, 2);  // TotalCnt (Long)
            buf.writeUInt32LE(charCount, 6);  // charSlots (Long)
            this.helpers.log('INFO', `[${connId}] Sending HC_CHARLIST_NOTIFY`);
            this.helpers.logPacket(pkt, buf);
            return buf;
        } else {
            const buf = Buffer.alloc(6);
            buf.writeUInt16LE(pkt, 0);
            buf.writeUInt32LE(charCount, 2);  // TotalCnt (Long)
            this.helpers.log('INFO', `[${connId}] Sending HC_CHARLIST_NOTIFY`);
            this.helpers.logPacket(pkt, buf);
            return buf;
        }
    }

    _sendBlockCharacter(connId) {
        // HC_BLOCK_CHARACTER (0x020d) - 4 bytes
        if (this.packetVer > 20060819) {
            const buf = Buffer.alloc(4);
            const pkt = this.packets.getServerPacket('HC_BLOCK_CHARACTER');
            buf.writeUInt16LE(pkt, 0);
            buf.writeUInt16LE(0, 2);
            return buf;
        } else {
            this.helpers.log('ERROR', `[${connId}] Cannot send HC_BLOCK_CHARACTER for clients older than 20060819, different packet structure.`)
            return null;
        }
    }

    char(connId, sessions, packetId, data) {
        switch (packetId) {
            case this.packets.getClientPacket('CH_ENTER'):
                return this.handleCharEnter(connId, sessions, data);

            case this.packets.getClientPacket('CH_CHARLIST_REQ'):
                return this.sendCompleteCharacterList(connId); // Send all packets together

            case this.packets.getClientPacket('CH_SELECT_CHAR'):
                return this.handleCharSelect(connId, data);

            default:
                this.helpers.log('ERROR', `[${connId}] Unknown login packet: 0x${packetId.toString(16)}`);
        }
    }

    handleCharEnter(conn, sessions, data){
        if (data.length < 17) {
            this.helpers.log('ERROR', `[${conn.id}] CH_ENTER too short: ${data.length} bytes`);
            return;
        }

        const aid = data.readUInt32LE(2);
        const authCode = data.readInt32LE(6);
        const userLevel = data.readUInt32LE(10);
        const clientType = data.readUInt16LE(14);
        const sex = data.readUInt8(16);

        this.helpers.log('INFO', `[${connId}]CH_ENTER: AID=${aid}, AuthCode=${authCode}, userLevel=${userLevel}, clientType=${clientType}, sex=${sex}`);

        const session = sessions.get(aid);
        if (!session) {
            this.helpers.log('ERROR', `[${conn.id}] No session found for AID=${aid}`);
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

        const charList = this.sendCompleteCharList()
    }

    sendCompleteCharList(conn) {

        _sendCharListHeader();
        _sendCharListData();
        _sendCharListNotify();
        _sendBlockCharacter();

    }

}

// Export both the class and factory
module.exports = {
    CharServer
};