import json, time
from hashlib import md5
from Crypto.Hash import MD5
import random

class CypherHelper:
    def __init__(self, cypherConfig):
        type_, imei, firstLaunchTime = cypherConfig.values()
        self.createZcid(type_, imei, firstLaunchTime)
        self.zcid_ext = self.randomString()
        self.createEncryptKey()

    def createZcid(self, type_, imei, firstLaunchTime):
        zcidParams = f"{type_}, {imei}, {firstLaunchTime}"
        print('zcidParams: ',zcidParams)
        self.zcid = self.encode_aes(
            '3FC4F0D2AB50057BCE0D90D9187A22B1',
            zcidParams,
            'hex',
            True,
        )
        print("self.zcid,",self.zcid)

    def createEncryptKey(self):
        zcidExtMD5 = MD5.new(self.zcid_ext.encode()).hexdigest().upper()
        zcidExtMD5Even = self.processStr(zcidExtMD5)['even']
        zcidEven, zcidOdd = self.processStr(self.zcid)['even'], self.processStr(self.zcid)['odd']
        self.encryptKey = (
            ''.join(zcidExtMD5Even[:8]) +
            ''.join(zcidEven[:12]) +
            ''.join(zcidOdd[::-1][:12])
        )

    def get_params(self):
        return {
            'zcid': self.zcid,
            'zcid_ext': self.zcid_ext,
            'enc_ver': 'v2',
        }

    def get_encrypted_key(self):
        return self.encryptKey

    @staticmethod
    def encode_aes(prefix, zcid_params, hash_type, uppercase):
        print("prefix:",prefix)
        print("zcid_params:",zcid_params)
        print("hash_type:",hash_type)
        print("uppercase:",uppercase)
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad, unpad
        from Crypto.Random import get_random_bytes
        try:
            key = prefix.encode('utf-8')
            iv = bytes([0, 0, 0, 0] * 4)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded_data = pad(zcid_params.encode('utf-8'), AES.block_size)
            ciphertext = cipher.encrypt(padded_data)
            if hash_type == 'hex':
                encrypted_string = ciphertext.hex()
            else:
                encrypted_string = ciphertext
            return encrypted_string.upper() if uppercase else encrypted_string
        except Exception as e:
            print('[encode_aes]', e)

    @staticmethod
    def randomString(minLength=6, maxLength=12):
        randomLength = random.randint(minLength, maxLength)
        randomString = ''.join(random.choices('abcdef0123456789', k=randomLength))
        return randomString

    @staticmethod
    def processStr(string):
        print("string: ",string)
        even = [string[i] for i in range(0, len(string), 2)]
        odd = [string[i] for i in range(1, len(string), 2)]
        return {'even': even, 'odd': odd}

class Zalo:
    def __init__(self):
        self.default = {
            'zaloClientID': '',
            'apiType': 30,
            'apiVersion': 'v2',
            'authDomain': 'https://zalo.me',
            'clientVersion': 625,
        }

    def pre_encrypt_params(self, raw_params):
        zalo_client_id = self.default['zaloClientID']
        api_type = self.default['apiType']

        cypher_helper = CypherHelper({
            'type': api_type,
            'imei': zalo_client_id,
            'firstLaunchTime': int(time.time() * 1000),
        })

        params_stringified = json.dumps(raw_params)
        encrypted_key = cypher_helper.get_encrypted_key()
        encoded_params = CypherHelper.encode_aes(
            encrypted_key,
            params_stringified,
            'base64',
            False,
        )
        params = cypher_helper.get_params()

        return {
            'encrypted_data': encoded_params,
            'encrypted_params': params,
            'enk': encrypted_key,
        } if params else None

    def get_sign_key(self, route, processed_params):
        key_list = sorted(processed_params.keys())
        raw_sign_key = 'zsecure' + route
        raw_sign_key += ''.join(str(processed_params[key]) for key in key_list)
        return md5(raw_sign_key.encode()).hexdigest()

    def encrypt_params(self, raw_params, route):
        api_type = self.default['apiType']
        client_version = self.default['clientVersion']

        pre_encrypted_params_payload = self.pre_encrypt_params(raw_params)
        processed_params = pre_encrypted_params_payload['encrypted_params'] if pre_encrypted_params_payload else raw_params
        processed_params['type'] = api_type
        processed_params['client_version'] = client_version
        processed_params['signKey'] = self.get_sign_key(route, processed_params)

        return {
            'params': processed_params,
            'enk': pre_encrypted_params_payload['enk'] if pre_encrypted_params_payload else None,
        }

    def get_login_info(self, get_login_params):
        self.default['zaloClientID'] = get_login_params['imei']
        self.default['apiType'] = 30
        result = self.encrypt_params(get_login_params, 'getlogininfo')
        return {
            'params': result['params'],
            'enk': result['enk']
        }

zl = Zalo()
get_login_params = {
    "imei": "fcb4c2c4-f9f3-465d-8539-19e7620ba2e0-ac61c259b412df784ffd75475c7a865e"
}
a = zl.get_login_info(get_login_params)
print(a)
