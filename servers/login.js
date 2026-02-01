const crypto = require('crypto');
const { Helpers } = require('../helpers');

class LoginServer {
    packets = {}
    packetVer = "";

    _processAuthentication(packetId, data) {
        const username = this.helpers.zstr(data, 30, 24);

        let password = '';
        if (packetId === this.packets.getClientPacket('CA_LOGIN')) {
            password = this.helpers.zstr(data, 30, 24);
        } else if (packetId === this.packets.getClientPacket('CA_LOGIN2')) {
            const md5Hash = data.slice(30, 46);
            password = md5Hash.toString('hex');
        }
        return {username, password}
    }

    constructor(packetVer, packets) {
        this.helpers = new Helpers();
        this.packetVer = packetVer;
        this.packets = packets;
    }

    login(connId, packetId, data) {
        switch (packetId) {
            case this.packets.getClientPacket('CA_LOGIN'):
            case this.packets.getClientPacket('CA_LOGIN2'): {
                const loginInfo = this.processLoginInfo(packetId, data);
                const packetData = this.buildLoginPacket(connId, this.packetVer, loginInfo);
                return { loginInfo, packetData };
            }
            case this.packets.getClientPacket('CA_CONNECT_INFO_CHANGED'): {
                this.helpers.logPacket(this.packets.getClientPacket('CA_CONNECT_INFO_CHANGED'), 0);
                this.helpers.log('Client info changed, ignoring.');
                return;
            }
            default:
                this.helpers.log('ERROR', `[${connId}] Unknown login packet: 0x${packetId.toString(16)}`)
        }
    }

    buildLoginPacket(connId, packetVer, loginInfo) {
        let buf;
        if (packetVer < 20170315) {
            // TODO
        } else {
            buf = Buffer.alloc(224);
            let offset = 0;
            const pkt = this.packets.getServerPacket('AC_ACCEPT_LOGIN3');
            // Header
            buf.writeUInt16LE(pkt, offset); offset += 2;
            buf.writeUInt16LE(224, offset); offset += 2;  // Fixed length
            buf.writeInt32LE(loginInfo.login_id1, offset); offset += 4; // AuthCode (login_id1) - signed
            buf.writeUInt32LE(loginInfo.aid, offset); offset += 4;
            buf.writeUInt32LE(loginInfo.login_id2, offset); offset += 4; // userLevel (login_id2)
            buf.writeUInt32LE(0, offset); offset += 4; // lastLoginIP (0 in log)
            buf.fill(0, offset, offset + 26); offset += 26; // lastLoginTime (26 bytes), empty
            buf.writeUInt8(loginInfo.sex, offset); offset += 1; // Sex (1=male, 0=female in rAthena)

            // Web auth token (17 bytes) - 16 bytes token + 1 null terminator
            const token = crypto.randomBytes(8).toString('hex');  // 16 chars = 16 bytes
            buf.write(token, offset, 'ascii'); offset += 16;
            buf.writeUInt8(0, offset); offset += 1;  // Null terminator

            buf.writeUInt8(1, offset); offset += 1; // Server count (1)
            // Server entry, server data starts here
            // IP (127.0.0.1 = 0x7f000001 for local testing)
            buf.writeUInt32LE(0x7f000001, offset); offset += 4;

            // Port (6121 = 0x17E9)
            buf.writeUInt16LE(6121, offset); offset += 2;

            // Server name (max 20 bytes) - "Netuno Server"
            buf.fill(0, offset, offset + 20);
            buf.write('Netuno Server', offset, 'ascii');
            offset += 20;

            buf.writeUInt16LE(50, offset); offset += 2; // User count (50)
            buf.writeUInt16LE(0, offset); offset += 2; // State (0)
            buf.writeUInt16LE(0, offset); offset += 2;// Property (0)

            // Remaining padding to reach 224 bytes total
            // We've written: 2+2+4+4+4+4+26+1+17+1+4+2+20+2+2+2 = 97 bytes
            // Need 224 total, so 224 - 97 = 127 bytes padding
            const remaining = 224 - offset;
            if (remaining > 0) {
                buf.fill(0, offset, offset + remaining);
                offset += remaining;
            }
            this.helpers.log('INFO', `[${connId}] AID=${loginInfo.aid}, AuthCode=${loginInfo.login_id1}, userLevel=${loginInfo.login_id2}`);
            this.helpers.logPacket(pkt, buf);
        }
        return buf;
    }

    processLoginInfo(connId, packetId, data) {
        const version = data.readUInt32LE(2);
        const clientType = data.length >= 55 ? data.readUInt8(54) : 0;
        const aid = this.helpers.generateAID();
        const {username, password} = this._processAuthentication(packetId, data);

        this.helpers.log('INFO', `[${connId}] Generating login info, client version ${version}`);

        return {
            aid: aid,
            login_id1: this.helpers.randI32(),
            login_id2: this.helpers.randU32(),
            sex: Math.random() > 0.5 ? 0 : 1,
            accountName: username,
            password: password,
            clientType: clientType,
            lastLogin: Date.now(),
        };
    }
}

// Export both the class and factory
module.exports = {
    LoginServer
};