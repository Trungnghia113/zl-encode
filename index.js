"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Zalo = void 0;
const cypher_helper_1 = require("./cypher-helper");
class Zalo {
    constructor() {
        this.default = {
            zaloClientID: '',
            apiType: 30,
            apiVersion: 'v2',
            authDomain: 'https://zalo.me',
            clientVersion: 625,
        };
    }
    preEncryptParams(rawParams) {
        const { zaloClientID, apiType } = this.default;
        const cypherHelper = new cypher_helper_1.CypherHelper({
            type: apiType,
            imei: zaloClientID,
            // firstLaunchTime: Date.now(),
            firstLaunchTime: 17000000000,
        });
        const paramsStringified = JSON.stringify(rawParams);
        const encryptedKey = cypherHelper.getEncryptedKey();
        const encodedParams = cypher_helper_1.CypherHelper.encodeAES(encryptedKey, paramsStringified, 'base64', false);
        const params = cypherHelper.getParams();
        return params
            ? {
                encrypted_data: encodedParams,
                encrypted_params: params,
                enk: encryptedKey,
            }
            : null;
    }
    getSignKey(route, processedParams) {
        const keyList = Object.keys(processedParams);
        keyList.sort();
        let rawSignKey = 'zsecure' + route;
        keyList.forEach(key => {
            rawSignKey += processedParams[key];
        });
        return cypher_helper_1.CypherHelper.crypto.MD5(rawSignKey).toString();
    }
    encryptParams(rawParams, route) {
        const { apiType, clientVersion } = this.default;
        const preEncryptedParamsPayload = this.preEncryptParams(rawParams);
        let processedParams;
        if (preEncryptedParamsPayload) {
            const { encrypted_params, encrypted_data } = preEncryptedParamsPayload;
            processedParams = encrypted_params;
            processedParams.params = encrypted_data;
        }
        else {
            processedParams = rawParams;
        }
        processedParams.type = apiType;
        processedParams.client_version = clientVersion;
        processedParams.signKey = this.getSignKey(route, processedParams);
        return {
            params: processedParams,
            enk: processedParams ? preEncryptedParamsPayload.enk : null,
        };
    }
    getLoginInfo(getLoginParams) {
        this.default.zaloClientID = getLoginParams.imei;
        this.default.apiType = 30;
        const { params, enk } = this.encryptParams(getLoginParams, 'getlogininfo');
        console.log(params, enk);
    }
}
exports.Zalo = Zalo;
// Create an instance of the Zalo class
const zaloInstance = new Zalo();
// Define the login parameters
const loginParams = {
    imei: '129dfe26-b8b9-4cea-a550-81c2837ea77d-ac61c259b412df784ffd75475c7a865e', // Replace with the actual IMEI value
    // Other login parameters as needed
};
// Call the getLoginInfo method
zaloInstance.getLoginInfo(loginParams);
