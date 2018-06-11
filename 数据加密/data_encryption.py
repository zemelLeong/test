# coding: utf-8
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.PublicKey import RSA


class SecretError(Exception):
    def __str__(self):
        return "The secret is None"


class RSAKeyLengthError(Exception):
    def __init__(self, pub_key_length, pri_key_length):
        self.__pub_key_length = pub_key_length
        self.__pri_key_length = pri_key_length

    def __str__(self):
        return "The RSA key length must be equal. " \
               "Public key length: {0}. Private key length: {0}".format(self.__pub_key_length, self.__pri_key_length)


class CiphertextLengthError(Exception):
    def __init__(self, secret_key_len, ciphertext_len):
        self.__secret_key_len = secret_key_len
        self.__ciphertext_len = ciphertext_len

    def __str__(self):
        temp = self.__ciphertext_len % (self.__secret_key_len / 8)
        return "The ciphertext length error." \
               "The ciphertext must be satisfied: ciphertext_len % (secret_key_len / 8) == 0." \
               "Current: {0} % ({1} / 8) = {2}".format(self.__ciphertext_len, self.__secret_key_len, temp)


class DataEncryption(object):
    """
    包含对称加密、解密，非对称加密、解密模块
    使用举例：
        对称加密-加密：DataEncryption.aes_symmetric_encryption(待加密数据，密码，密码填充字串)
        对称加密-解密：DataEncryption.aes_symmetric_decryption(待加密数据，密码，密码填充字串)
    """
    @classmethod
    def aes_cipher_process(cls, secret, pad_str):
        """
        密钥预处理，密钥长度需为16、24、32
        规则：
            if 16 < len < 24 then len = 24
            超过32位将被截断
        :param secret: 待处理密钥
        :param pad_str:将密钥填充到指定长度的字符串
        :return:
        """
        if len(secret) > 32:
            print("The secret key length more than 32. It will be truncate")
            secret = secret[:32]

        if pad_str is None:
            return secret

        pad_str_len = len(pad_str)
        secret_len_v = [16, 24, 32]
        secret_len = len(secret)

        for i in secret_len_v:
            difference = i - secret_len

            if difference == 0:
                break

            if difference > 0:
                secret += (pad_str * (int(difference / pad_str_len) + 1))[:difference]
                break

        return secret

    @classmethod
    def type_check(cls, source_data):
        if not isinstance(source_data, str):
            print("The source data is not string. repr function will processed it.")
            source_data = repr(source_data)

        return source_data

    @classmethod
    def aes_symmetric_encryption(cls, source_data, secret, pad_str=None):
        """
        对称加密：加密，使用给定密钥对数据进行加密
        :param source_data: 待加密数据，长度需为16的整数倍，不足将使用 '\0' 填充
        :param secret: 密钥
        :param pad_str: 密钥不足16、24、32则使用pad_str填充，如果密码长度符合要求则该项可选
        :return:已加密字符串
        """
        if source_data is None:
            return

        if secret is None:
            raise SecretError

        source_data = cls.type_check(source_data)
        secret = cls.type_check(secret)
        processed_secret = cls.aes_cipher_process(secret, pad_str)

        # 待加密数据长度不是16的倍数则补充 "\0"，`注意不是空格`
        source_data += (16 - len(source_data) % 16) * "\0"
        cipher = AES.new(processed_secret)
        secret_data = cipher.encrypt(source_data)

        return secret_data

    @classmethod
    def aes_symmetric_decryption(cls, source_data, secret, pad_str=None):
        """
        对称加密：解密，使用指定密钥对数据进行解密
        :param source_data: 待解密数据
        :param secret: 密钥
        :param pad_str: 密钥填充字串，如果密码长度符合要求则该项可选
        :return:已解密字符串
        """
        if source_data is None:
            return

        if secret is None:
            raise SecretError

        secret = cls.type_check(secret)
        processed_secret = cls.aes_cipher_process(secret, pad_str)
        cipher = AES.new(processed_secret)

        decryption_data = cipher.decrypt(source_data).strip("\0")

        return decryption_data

    class AsymmetricEncryption(object):
        """非对称加密"""
        def __init__(self):
            self.__key_length = None

            self.__random_generator = Random.new().read

        def __key_length_check(self):
            if self.__key_length < 1024:
                self.__key_length = 1024
                print("RSA modulus length < 1024. It will be reset with 1024")
                return

            if self.__key_length % 256 != 0:
                self.__key_length = (int(self.__key_length / 256) + 1) * 256
                print("RSA modulus length must be a multiple of 256."
                            " It will be reset with {0}".format(self.__key_length))

        def __set_key_length(self, length):
            self.__key_length = length
            self.__key_length_check()

        def get_random_generator(self):
            return self.__random_generator

        def get_rsa(self):
            rsa = RSA.generate(self.__key_length, self.__random_generator)
            return rsa

        @classmethod
        def get_ras_signer(cls, pub_or_pri_key):
            """
            获取签名对象
            :param pub_or_pri_key:
            :return:签名对象，ras 模长
            """
            ras_key = RSA.importKey(pub_or_pri_key)
            signer = Signature_pkcs1_v1_5.new(ras_key)
            return signer, ras_key.size() + 1

        @classmethod
        def get_digest(cls, source_data):
            digest = SHA.new()
            try:
                digest.update(source_data.encode("utf-8"))
            except AttributeError:
                digest.update(source_data)

            return digest

        @classmethod
        def get_cipher(cls, pub_or_pri_key):
            """
            获取加密器对象
            :param pub_or_pri_key: 公钥或私钥
            :return: 加密器对象, ras 模长
            """
            ras_key = RSA.importKey(pub_or_pri_key)
            cipher = Cipher_pkcs1_v1_5.new(ras_key)
            return cipher, ras_key.size() + 1

        def generate_secret_key(self, pem_save_path=None, length=1024):
            """
            生成公钥和私钥，公钥将自动加上 _public.pem 后缀，私钥将自动加上 _private.pem 后缀
            :param pem_save_path: 密钥证书保存路径
            :param length:RSA模长
            :return:公钥、私钥
            """
            self.__set_key_length(length)
            rsa = self.get_rsa()
            private_pem = rsa.exportKey()
            public_pem = rsa.publickey().exportKey()

            if pem_save_path is not None:
                pri_pem_save_path = pem_save_path + "_private.pem"
                pub_pem_save_path = pem_save_path + "_public.pem"
                with open(pri_pem_save_path, "w") as f_pri, open(pub_pem_save_path, "w") as f_pub:
                    f_pub.write(public_pem.decode("utf-8"))
                    f_pri.write(private_pem.decode("utf-8"))
                    print("Secret key generate successed."
                                "Save as:\n{0}\n{1}".format(pub_pem_save_path, pri_pem_save_path))

            return public_pem, private_pem

        def data_encryption_signer(self, source_data, pub_key, pri_key=None):
            """
            加密数据、签名数据
            :param source_data: 待加密数据
            :param pri_key: 私钥，用于对数据进行签名
            :param pub_key: 公钥，用于加密
            :return: 加密的数据，数据的签名
            """
            encrypted_data = b""
            data_signature = b""
            signer = None

            cipher, pub_key_length = self.get_cipher(pub_key)
            if pri_key is not None:
                signer, pri_key_length = self.get_ras_signer(pri_key)

                if pub_key_length != pri_key_length:
                    raise RSAKeyLengthError(pub_key_length, pri_key_length)

            key_length = pub_key_length
            data_limit_len = int(key_length / 8 - 11)
            source_data_len = len(source_data)

            for i in range(int(source_data_len / data_limit_len) + 1):
                piece_data = source_data[i * data_limit_len: (i + 1) * data_limit_len]
                encrypted_data += cipher.encrypt(piece_data.encode("utf-8"))

                if pri_key is not None:
                    digest = DataEncryption.AsymmetricEncryption.get_digest(piece_data)
                    data_signature += signer.sign(digest)

            return encrypted_data, data_signature if len(data_signature) == 0 else None

        def signature_verify(self, decrypted_data, data_signature, pub_or_pri_key):
            """
            签名验证
            :param decrypted_data: 已解密的数据
            :param data_signature: 数据签名
            :param pub_or_pri_key: 公钥或私钥
            :return: True or False
            """
            signer, secret_key_len = self.get_ras_signer(pub_or_pri_key=pub_or_pri_key)
            data_limit_len = int(secret_key_len / 8 - 11)
            data_len = len(decrypted_data)

            sig_limit_len = int(secret_key_len / 8)
            is_verify = True

            for i in range(int(data_len / data_limit_len) + 1):
                piece_data = decrypted_data[i * data_limit_len: (i + 1) * data_limit_len]
                piece_sig = data_signature[i * sig_limit_len: (i + 1) * sig_limit_len]

                digest = self.get_digest(source_data=piece_data)
                is_verify = signer.verify(digest, piece_sig)
                if not is_verify:
                    break

            return is_verify

        def decrypt(self, encrypted_data, pri_key):
            """
            数据解密
            :param encrypted_data: 待解密的数据
            :param pri_key: 私钥
            :return: 解密的数据
            """
            decrypted_data = b""
            cipher, private_key_len = DataEncryption.AsymmetricEncryption.get_cipher(pri_key)
            # 密钥长度对应密文的长度
            enc_data_piece_len = int(private_key_len / 8)
            iterations = int(len(encrypted_data) / enc_data_piece_len)

            for i in range(iterations):
                piece_data = encrypted_data[i * enc_data_piece_len: (i + 1) * enc_data_piece_len]
                decrypted_data += cipher.decrypt(piece_data,
                                                 self.get_random_generator())

            return decrypted_data


if __name__ == '__main__':
    s = "123456789hfsfsdfsd1" * 1024
    print("len(s): {0}".format(len(s)))
    obj = DataEncryption.AsymmetricEncryption()
    public_key, private_key = obj.generate_secret_key(length=1024)
    # data, sig = obj.data_encryption_signer(source_data=s, pri_key=private_key, pub_key=public_key)
    data, sig = obj.data_encryption_signer(source_data=s, pub_key=public_key)
    print("len(sig): {0}".format(len(sig)))
    d_data = obj.decrypt(data, private_key)
    print(d_data)
    # is_v = obj.signature_verify(d_data, sig, private_key)
    # print(is_v)
