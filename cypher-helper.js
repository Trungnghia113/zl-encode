"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.CypherHelper = void 0;
const crypto_js_1 = __importDefault(require("crypto-js"));
class CypherHelper {
    constructor(cypherConfig) {
        this.enc_ver = 'v2';
        const { type, imei, firstLaunchTime } = cypherConfig;
        this.createZcid(type, imei, firstLaunchTime);
        this.zcid_ext = CypherHelper.randomString();
        this.createEncryptKey();
    }
    createZcid(type, imei, firstLaunchTime) {
        const zcidParams = `${type}, ${imei}, ${firstLaunchTime}`;
        this.zcid = CypherHelper.encodeAES('3FC4F0D2AB50057BCE0D90D9187A22B1', zcidParams, 'hex', !0);
    }
    createEncryptKey() {
        let zcidExtMD5 = crypto_js_1.default.MD5(this.zcid_ext).toString().toUpperCase();
        const { even: zcidExtMD5Even } = CypherHelper.processStr(zcidExtMD5);
        const { even: zcidEven, odd: zcidOdd } = CypherHelper.processStr(this.zcid);
        this.encryptKey =
            zcidExtMD5Even.slice(0, 8).join('') +
                zcidEven.slice(0, 12).join('') +
                zcidOdd.reverse().slice(0, 12).join('');
    }
    getParams() {
        return {
            zcid: this.zcid,
            zcid_ext: this.zcid_ext,
            enc_ver: this.enc_ver,
        };
    }
    getEncryptedKey() {
        return this.encryptKey;
    }
    static encodeAES(prefix, zcidParams, hashType, uppercase) {
        try {
            const hashMethod = hashType === 'hex' ? crypto_js_1.default.enc.Hex : crypto_js_1.default.enc.Base64;
            const encryptKey = crypto_js_1.default.enc.Utf8.parse(prefix);
            const iv = {
                words: [0, 0, 0, 0],
                sigBytes: 16,
            };
            const encryptString = crypto_js_1.default.AES.encrypt(zcidParams, encryptKey, {
                iv: iv,
                mode: crypto_js_1.default.mode.CBC,
                padding: crypto_js_1.default.pad.Pkcs7,
            }).ciphertext.toString(hashMethod);
            return uppercase ? encryptString.toUpperCase() : encryptString;
        }
        catch (e) {
            console.log('[encodeAES]', e);
        }
    }
    static randomString(minLength, maxLength) {
        minLength = minLength !== null && minLength !== void 0 ? minLength : 6;
        maxLength = maxLength && maxLength > minLength ? maxLength : 12;
        let randomLength = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
        if (randomLength > 12) {
            let randomString = '';
            for (; randomLength > 0;) {
                randomString += Math.random()
                    .toString(16)
                    .substr(2, randomLength > 12 ? 12 : randomLength);
                randomLength -= 12;
            }
        }
        return Math.random().toString(16).substr(2, randomLength);
    }
    static processStr(str) {
        console.log("str: ", str);
        const [even, odd] = str.split('').reduce((prev, cur, index) => {
            return prev[index % 2].push(cur), prev;
        }, [[], []]);
        return {
            even,
            odd,
        };
    }
    static get crypto() {
        return crypto_js_1.default;
    }
}
exports.CypherHelper = CypherHelper;
