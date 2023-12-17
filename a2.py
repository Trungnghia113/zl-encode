import base64
import json
import random
from hashlib import md5
import time
import cryptography.hazmat.primitives.padding as padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


class CypherHelper:
    def __init__(self, cypher_config):
        self.enc_ver = 'v2'
        type_value = cypher_config["type"]
        imei_value = cypher_config["imei"]
        first_launch_time_value = cypher_config["firstLaunchTime"]
        self.create_zcid(type_value, imei_value, first_launch_time_value)
        self.zcid_ext = CypherHelper.random_string()
        self.create_encrypt_key()

    def create_zcid(self, type_value, imei_value, first_launch_time_value):
        zcid_params = f"{type_value}, {imei_value}, {first_launch_time_value}"
        self.zcid = CypherHelper.encode_aes(
            '3FC4F0D2AB50057BCE0D90D9187A22B1', zcid_params, 'hex', True
        )

    def create_encrypt_key(self):
        zcid_ext_md5 = md5(self.zcid_ext.encode()).hexdigest().upper()
        zcid_ext_md5_even = CypherHelper.process_str(zcid_ext_md5)["even"]
        zcid_even, zcid_odd = CypherHelper.process_str(self.zcid)["even"], CypherHelper.process_str(self.zcid)["odd"]

        self.encrypt_key = (
            "".join(zcid_ext_md5_even[:8])
            + "".join(zcid_even[:12])
            + "".join(list(reversed(zcid_odd))[:12])
        )

    def get_params(self):
        return {"zcid": self.zcid, "zcid_ext": self.zcid_ext, "enc_ver": self.enc_ver}

    def get_encrypted_key(self):
        return self.encrypt_key

    @staticmethod
    def encode_aes(prefix, zcid_params, hash_type, uppercase):
        try:
            hash_method = (
                hashes.SHA256() if hash_type == 'hex' else hashes.SHA256()
            )
            encrypt_key = prefix.encode('utf-8')
            iv = b'\x00' * 16

            cipher = Cipher(algorithms.AES(encrypt_key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()

            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(zcid_params.encode('utf-8')) + padder.finalize()

            ciphertext = encryptor.update(padded_data) + encryptor.finalize()

            if hash_type == 'hex':
                encrypted_string = ciphertext.hex()
            else:
                encrypted_string = ciphertext

            return encrypted_string.upper() if uppercase else encrypted_string

        except Exception as e:
            print('[encode_aes]', e)

    @staticmethod
    def random_string(min_length=6, max_length=12):
        random_length = random.randint(min_length, max_length)
        return ''.join(random.choices('0123456789abcdef', k=random_length))

    @staticmethod
    def process_str(string):
        even, odd = [], []
        for index, char in enumerate(string):
            if index % 2 == 0:
                even.append(char)
            else:
                odd.append(char)
        return {"even": even, "odd": odd}


class Zalo:
    def __init__(self):
        self.default = {
            "zaloClientID": '',
            "apiType": 30,
            "apiVersion": 'v2',
            "authDomain": 'https://zalo.me',
            "clientVersion": 625,
        }

    def pre_encrypt_params(self, raw_params):
        zalo_client_id = self.default["zaloClientID"]
        api_type = self.default["apiType"]
        cypher_helper = CypherHelper(
            {
                "type": api_type,
                "imei": zalo_client_id,
                "firstLaunchTime":  int(time.time() * 1000),
            }
        )
        params_stringified = json.dumps(raw_params)
        encrypted_key = cypher_helper.get_encrypted_key()
        encoded_params = CypherHelper.encode_aes(
            encrypted_key, params_stringified, 'base64', False
        )
        params = cypher_helper.get_params()
        return (
            {
                "encrypted_data": encoded_params,
                "encrypted_params": params,
                "enk": encrypted_key,
            }
            if params
            else None
        )

    def get_sign_key(self, route, processed_params):
        key_list = list(processed_params.keys())
        key_list.sort()
        raw_sign_key = 'zsecure' + route
        for key in key_list:
            raw_sign_key += str(processed_params[key])  # Convert to string before concatenating
        return md5(raw_sign_key.encode()).hexdigest()

    def encrypt_params(self, raw_params, route):
        api_type = self.default["apiType"]
        client_version = self.default["clientVersion"]
        pre_encrypted_params_payload = self.pre_encrypt_params(raw_params)
        processed_params = None
        if pre_encrypted_params_payload:
            encrypted_params, encrypted_data = (
                pre_encrypted_params_payload["encrypted_params"],
                pre_encrypted_params_payload["encrypted_data"],
            )
            processed_params = encrypted_params
            processed_params["params"] = base64.b64encode(encrypted_data).decode('utf-8')  # Convert bytes to string
        else:
            processed_params = raw_params
        processed_params["type"] = api_type
        processed_params["client_version"] = client_version
        processed_params["signKey"] = self.get_sign_key(route, processed_params)
        return {"params": processed_params, "enk": pre_encrypted_params_payload["enk"]} if processed_params else None

    def get_login_info(self, get_login_params):
        self.default["zaloClientID"] = get_login_params["imei"]
        self.default["apiType"] = 30
        result = self.encrypt_params(get_login_params, 'getlogininfo')
        if result:
            print(result["params"], result["enk"])


# Example usage:
# Create an instance of the Zalo class
zalo_instance = Zalo()
# Define the login parameters
login_params = {
    "imei": '129dfe26-b8b9-4cea-a550-81c2837ea77d-ac61c259b412df784ffd75475c7a865e',  # Replace with the actual IMEI value
    # Other login parameters as needed
}
# Call the get_login_info method
zalo_instance.get_login_info(login_params)
