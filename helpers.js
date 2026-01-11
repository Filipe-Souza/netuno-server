const crypto = require('crypto');
class Helpers {
    serverTypePort(port) {
        const portToType = {
            6900: 'login',
            6901: 'login',
            6121: 'char',
            6122: 'char',
            5121: 'char',
            5122: 'map'
        };
        return portToType[port] || 'unknown';
    }

    parseProxyPath(urlPath) {
        const raw = String(urlPath || '').replace(/^\/+/, '');
        const m = raw.match(/^(.+):(\d+)$/);
        if (!m) return { host: null, port: null, raw };
        return { host: m[1], port: parseInt(m[2], 10), raw };
    }

    randU32() {
        return crypto.randomBytes(4).readUInt32LE(0) >>> 0;
    }

    randI32() {
        return crypto.randomBytes(4).readInt32LE(0) | 0;
    }

    zstr(buf, offset, maxLen) {
        const slice = buf.slice(offset, offset + maxLen);
        const zero = slice.indexOf(0);
        return (zero >= 0 ? slice.slice(0, zero) : slice).toString('ascii');
    }

    charactersList(){
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
}

module.exports = {
    Helpers
}