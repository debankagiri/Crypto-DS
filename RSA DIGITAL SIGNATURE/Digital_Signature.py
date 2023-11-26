from Crypto.PublicKey import RSA
import Crypto.Signature.PKCS1_v1_5 as sign_PKCS1_v1_5 
from Crypto.Cipher import PKCS1_v1_5  
from Crypto import Random
from Crypto import Hash
 
x = RSA.generate(2048)
# y = RSA.generate(2048, Random.new().read)  
s_key = x.export_key()  
print(s_key)
g_key = x.publickey().export_key()  
print('*'*80)
print(g_key)
# --1# with open("c.pem", "wb") as x:#     x.write(s_key)# with open("d.pem", "wb") as x:#     x.write(g_key)# 从文件导入密钥 -- 通过私钥生成公钥  (公钥不会变 -- 用于只知道私钥的情况)--2# with open('c.pem','rb')as x:#     s_key = RSA.importKey(x.read())# # new_g_key = s_key.publickey().export_key()# # print(new_g_key)## cert = s_key.export_key("DER")  #生成证书 -- 它和私钥是唯一对应的# print(cert)
my_private_key = s_key 
my_public_key = g_key   
 
def encrypt_with_rsa(plain_text):
    cipher_pub_obj = PKCS1_v1_5.new(RSA.importKey(my_public_key))
    _secret_byte_obj = cipher_pub_obj.encrypt(plain_text.encode())
 
    return _secret_byte_obj
 
 
def decrypt_with_rsa(_secret_byte_obj):
    cipher_pri_obj = PKCS1_v1_5.new(RSA.importKey(my_private_key))
    _byte_obj = cipher_pri_obj.decrypt(_secret_byte_obj, Random.new().read)
    plain_text = _byte_obj.decode()
 
    return plain_text
 
 
def executer_without_signature():
    text = "I love CA!"
    assert text == decrypt_with_rsa(encrypt_with_rsa(text))
    print("rsa test success！")
 
def to_sign_with_private_key(plain_text):
    signer_pri_obj = sign_PKCS1_v1_5.new(RSA.importKey(my_private_key))
    rand_hash = Hash.SHA256.new()
    rand_hash.update(plain_text.encode())
    signature = signer_pri_obj.sign(rand_hash)
    print(f'\033[31m{signature}\033[0m')
    return signature
 
 
def to_verify_with_public_key(signature, plain_text):
    verifier = sign_PKCS1_v1_5.new(RSA.importKey(my_public_key))
    _rand_hash = Hash.SHA256.new()
    _rand_hash.update(plain_text.encode())
    verify = verifier.verify(_rand_hash, signature)
    print(verify)
    return verify  # true / false
 
 
def executer_with_signature():
    text = "I love CA!"
    assert to_verify_with_public_key(to_sign_with_private_key(text), text)
    print("rsa Signature verified!")
 
 
if __name__ == '__main__':
    # executer_without_signature()  
 
    executer_with_signature()  