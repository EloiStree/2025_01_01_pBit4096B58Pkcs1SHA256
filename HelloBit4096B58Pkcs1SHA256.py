
# pip install base58
import base64
import base58

guid_sent ="Hello World"
received_guid_handshake = """
Hello World|
pBit4096B58Pkcs1SHA2568arQkFZ8ZJYKVVkCiefn9ckvmUDmF9Hy5YEoNn4FoJn61B7bP9fFwYxWMGQpZJAD2374pnfxqaj5aThoR2j5SJk8TpScHwGThbJkfwDogkVoW523YTxP69LiZkE92qcgsrcSYZfkoqFtyFXVVkN9m5o3SDNNy2pSN9eygZGvvGigJMkXGb8xREGAmvkPt8XV79UbxvoooN1HaTRJu6LwiTJ41zFrGfyZnxMVgeRsxa3brrTpYoxt2hvh1otJ3HxajWeFfvqysYadKzoC1u54C7AuZPCpSkUbzEgERDLC5f5fqJ8LTdcTsubrC5BFQZQK6YBGN3PycYEy|
APcYryfXTgnjYGCpeVw4MZwLsn2h8BLwDxFFFn9pvqYZYKhCWHvCW2atb3K5UeDiRq8Cz441rRioSJBt9BLCPdE3mX7PwuaVn35QkfamPTKXS5xxMnAo9Dwaw6TVEHmmczMn1J3sA3fz2xY13w7nsnVLvga6PpyGEPkDt1W5sqz8aeC|
0xDa3239C8ad5C321A1411F3acC2C1f9F8C9D34ECE|
0x86644c8831bd3b4c876fcf72d41604d40636d78681acd3756e83b54f267365c558a10b401f5ef797fce02b0a8d6b2a69a8ee79b9607b15eda7c7e88c25c80d2a1b
"""

hankshake_splits = received_guid_handshake.split("|")
handshake_splits_lenght = len(hankshake_splits)

if handshake_splits_lenght >=1:
    received_guid_handshake = hankshake_splits[0].strip()
if handshake_splits_lenght >=2:
    received_public_address = hankshake_splits[1].strip()
if handshake_splits_lenght >=3:
    received_signature = hankshake_splits[2].strip()
if handshake_splits_lenght >=4:
    received_master_address = hankshake_splits[3].strip()
if handshake_splits_lenght >=5:
    received_master_signature = hankshake_splits[4].strip()



letter_marque = "pBit4096B58Pkcs1SHA2568arQkFZ8ZJYKVVkCiefn9ckvmUDmF9QUU3wGK6LHteBtQvgF6Z2cwy8iMVkrwy7fDtuQwLvF5o1zoSf1T7HaVFxeWiLyVQQqLkWdZMjJ4zufP4dj9rj8j54C7f3XJxLv5eh7x3dgUyMDCimAi3LQuYGwVWqkSMJePuw1vyJLVC519mJuRaDYBNBB8BzLxxFkSFd6APofsg8sybMsCaja92r61hKQsiu9QaWHJjYgpPNUiHpHTWeREpdPaeTTWGsLxSp3cszsPZzswNGdimwd5YyP2TDkeZK4BMWUq17zYFUSPL6g9uxd5pEBa3JLrGE3b2UMXDz5eyy7|0xDa3239C8ad5C321A1411F3acC2C1f9F8C9D34ECE|0x14c96d909de20bbbecb57e55c9b7a32b9812a81ccfaa9b379c9a289e4acae8936f4a8291cdb3248d7c1bb537cdf7c20f6d29c4f133666256b29052b4ac9245641c"
string_public_key_b58="pBit4096B58Pkcs1SHA2568arQkFZ8ZJYKVVkCiefn9ckvmUDmF9QUU3wGK6LHteBtQvgF6Z2cwy8iMVkrwy7fDtuQwLvF5o1zoSf1T7HaVFxeWiLyVQQqLkWdZMjJ4zufP4dj9rj8j54C7f3XJxLv5eh7x3dgUyMDCimAi3LQuYGwVWqkSMJePuw1vyJLVC519mJuRaDYBNBB8BzLxxFkSFd6APofsg8sybMsCaja92r61hKQsiu9QaWHJjYgpPNUiHpHTWeREpdPaeTTWGsLxSp3cszsPZzswNGdimwd5YyP2TDkeZK4BMWUq17zYFUSPL6g9uxd5pEBa3JLrGE3b2UMXDz5eyy7"
string_private_key_b58= "PBit4096B58Pkcs1SHA2563TT9g43oGiJ1Hz7LN9zMaTHk2eKbGXYaG3BSBkaVGuVyxgwUaqRZmVUZtxzpn3YTJ5zKbxBDbGRX6TYiT3G4wGJyBnUCykgbdktpkUnxr419rcVEoZr6yGbGVcnHY6chi4vWbemrAsjHdeh7ghs7A1XFCYyw6sRGkA9ubqDbg76CE56h7cRoNq3W8q2uHNN4GxWxYyMCnESvxpdak9MW4WsJTr8HGWnjg1SBLHtHMeWhBmPidd55Wshaax33dewfaMXw4BRbTqA4AiMCDuanNpnLKdst1VZ4GAfEw3qLjbYPHMwBKi5tGGHeTTGHR98ENVRtpV34t3hpGYra5Bs66sxid2CuKHJW5NapTR5MfV8951iKkC8SzZEygPJ75as1MjhHCFahEH68B9nrKBSpg5cKMP3Q26RWJv16RNqQ77qqLsxvKAk9B9rvfU22Wg6UHPVDmcFBBJoJUdnzvZuSU4hveY2a5cxgTud8rEpJGRvYgNMwKvxzSWBFDbzG1vnNCwRXHdEZWsPc5o7da36bQw35dWosQEQFNdC2pMjTLe6HVxJhH5XQJginGDA8DVzyBy1jCuLiE4DEJg8ExRojeTqiQRgRRyDwKGFEAg6rN83R5si5AxN3pQtnef7tjHxDUwnJZmSLg3j5Yga2Eo9iUGs8Xw1ryF7rQiRjhC3ujQvJNkugKyxyKxu6npdHawxCcPptnCEueK6cjSn7kEqNxfNn8Qf6TpPHLzM3fNGsfnoe4Kqax1omuu7Ekq5JsfqpSvUG8K2hQ9R2rAKLQk3r3YGUQU5HyQrGBJ48wCJhp7RXsVvTRMPL5Enqk2cgcp5SreCkswXmEuWo7hgZh75e49p3ohVdVe6vmDdkCmHueudwqBN8Hj8NHBtTH8RcVxFZ3PundKwmkGkFGvwbQ4bpD17Ue8ufoGCZknZrwvaa4bEDzadqj8AmD2Q62md4hoCGZtP9veirF1JeuAzHdNQYeie4oAmNfoWZR6dufuAxvQntDhrpBtn9Vj9HrMiJPHYT27xoP34VtbcRa4qV6cwaHbKnx2cxhdLroPFfwnvwcxe8C3oZWaq8ous7Vsd8CvWqSdckqhkQLwG3VuqKq9y3HHwMWRWJsVGERrfAvynn4GRNSB4mCFeMoaM7DUoscyVPag178PYiEE9TfmYDw9e72A8m1HZyXiDFBLMQGbSnGVKTzDqn5KAdaBdoYsXpTmU3CkQYDoN48rNBSbDCg6WhcEdnMyfA9cPWZB"



start_public_key_b58 = "pBit4096B58Pkcs1SHA256"
start_private_key_b58 = "PBit4096B58Pkcs1SHA256"


bool_is_ethereum_address = received_public_address.startswith("0x")
bool_is_b58Rsa_address= received_public_address.startswith("pBit4096B58Pkcs1SHA256")
letter_marque_clibpoard = f"{received_public_address}|{received_master_address}|{received_master_signature}"
guid_clipboard= f"{received_guid_handshake}|{received_public_address}|{received_signature}"

print ("Is Ethereum Address: ", bool_is_ethereum_address)
print ("Is B58 RSA Address: ", bool_is_b58Rsa_address)






print(">> Recover XML RSA key.")
print("Bit: 4096")
print("Encoding: base58")
print("Hash: SHA256")
print("Padding: PKCS1")
print("")

print("Public key as base58")
public_key_as_b58 = string_public_key_b58[len(start_public_key_b58):]

print("Private key as base58")
private_key_as_b58 = string_private_key_b58[len(start_private_key_b58):]
print (private_key_as_b58)


# Decode the base58 encoded private key

print("Private key as XML")
decoded_private_key = base58.b58decode(private_key_as_b58).decode('utf-8')
print(decoded_private_key)

print("Public key as XML")
decoded_public_key = base58.b58decode(public_key_as_b58).decode('utf-8')
print(decoded_public_key)


from web3 import Web3
import os
from eth_account.messages import encode_defunct
import uuid
import os


w3 = Web3()


def is_message_signed(given_message):
    
    split_message = given_message.split("|")
    if len(split_message) < 3:
        return False
    message = split_message[0]
    address = split_message[1]
    signature = split_message[2]
    return is_message_signed_from_params(message, address, signature )

def is_message_signed_from_params(message, address, signature):
    # Message to verify

    # Encode the message
    encoded_message = encode_defunct(text=message)

    # Recover the address from the signature
    recovered_address = w3.eth.account.recover_message(encoded_message, signature=signature)
    return  recovered_address.lower() == address.lower()



letter_marque_split= letter_marque.split("|")
string_message_letter_marque= letter_marque_split[0]
string_address_letter_marque= letter_marque_split[1]
string_signature_letter_marque= letter_marque_split[2]

print(">> Letter Marque")
print("Message: ", string_message_letter_marque)
print("Address: ", string_address_letter_marque)
print("Signature: ", string_signature_letter_marque)

print("")
print("Is message signed")
print(is_message_signed(letter_marque))
print("")




from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend



import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from xml.etree import ElementTree

def parse_rsa_key(xml_string):
    root = ElementTree.fromstring(xml_string)
    modulus = int(base64.b64decode(root.find('Modulus').text).hex(), 16)
    exponent = int(base64.b64decode(root.find('Exponent').text).hex(), 16)
    d = int(base64.b64decode(root.find('D').text).hex(), 16)
    p = int(base64.b64decode(root.find('P').text).hex(), 16)
    q = int(base64.b64decode(root.find('Q').text).hex(), 16)
    dp = int(base64.b64decode(root.find('DP').text).hex(), 16)
    dq = int(base64.b64decode(root.find('DQ').text).hex(), 16)
    inverse_q = int(base64.b64decode(root.find('InverseQ').text).hex(), 16)

    private_key = rsa.RSAPrivateNumbers(
        p=p, q=q, d=d, dmp1=dp, dmq1=dq, iqmp=inverse_q,
        public_numbers=rsa.RSAPublicNumbers(e=exponent, n=modulus)
    ).private_key()

    return private_key

# Fuck me that worked.
xml_key = decoded_private_key

# 2048
xml_key = """<RSAKeyValue><Modulus>xDBY2j85AUWCDy+Nij9JMigYpklEwF1jQbmVOiS2+ZDh3DEPfIOMbTPDagD9x4zTVDTCePCCigqkromIJ5IQ1EulMozVoNNaoXVGL6sZtx5Omu/jOgIuAhBkLkwxVmHcTWkpz9ndqV5gvLxlHQq/cPf3zKopWRAPrZDSOE6wAfE=</Modulus><Exponent>AQAB</Exponent><P>3e1csuEkQm87LpGLYry02ofBhqNZlMGskZsA6Rrl87FHAe28jEMXPSRupoy6WHOUkbZ4vXkCRE/0Ck5lVTwrlw==</P><Q>4k9dK0BF7iRFcmjx6C731OdL6mtDZbVB8k3lzXz20rZQb56iu/QHeA2SXdJUYJQn+nfe9TJIqQUBhZhXtrkPtw==</Q><DP>DIagK8x/Umyax4cZeeoyvv7YknPX04iW5+T6yS1mezmvS1GSycvjnOTYhff9cI6dfRfyeqdA1IA6wvYnzAbIYw==</DP><DQ>MkZNPVF+94NpRhxYOStN9ScY70+63jphFxIFDhxHvNGxlspX/occrafeLyeNhRMEupismC3+hEXPa71HJxl/iw==</DQ><InverseQ>j9btIncVTXFm0gYvl2oFIYcTWWpJwcy6vWP2c+fVxPqSBnSU1DR9dZMl45pRugQqLoXUMm6YcAnz2RVRgaatTA==</InverseQ><D>NOe4vjn4XGBrHz86kwJX8b+gTg9KC/njD1FFbaWC9i/cyG0ueOxcjQI9ezODPDG8t2N24fgxq5oNKMgLwGgCQ1S2unyaOnWQ70hwlUycfdHCVTzThvkSpKHoiLhN595FDeEVQsr0N0ZCRPruHyRoPq4maHVpN9Sjt4T/+4BWL8U=</D></RSAKeyValue>"""

# 4096
xml_key = """<RSAKeyValue><Modulus>uS6T7+oyJljRJHQygcN2J9aXBnG8mwjOKp7vrvZzuid9MI0g8UX42q/7rVMe6VBjbDxag/Vq0d3LEkVWf/W6P5VjGG54FfKrnGWkGH/7iywp14IDGDy+00tBjVFy5t7Ik6MV8CKlo2JhbWZsxt+3yaLzl7KNE8a0i63BQkgPWik=</Modulus><Exponent>AQAB</Exponent><P>x+WLPVByMeO6ri2mjdaJTCLVcDmOsk3fwTO6omeZxA/zh7QgB2UeD2hWBb2G0l4XsUpDfQ/PlCsWqDnzLbPu5Q==</P><Q>7SfKbJ5h0WWcMOlY0Ot7+BsuZ5RtZJw3sP9vIYZDG77++Uab5KvypJPgm9ftwdCdVfN7kL0o8gkzH9eYrhhF9Q==</Q><DP>wj0YmdHLxRKmWY3eY8Dt1N+cStqDAFuPaysa1aiZz9w4JcsvvD/Tf+FAhX9uvIfVud6RybpNWIquD3WQCP7oyQ==</DP><DQ>LaY2IbhO7eaYLRYNoZFieHyK7ycz82Tal3hjpNlaO5IFNGhyA49Rknpghr8GpgMI9g17IH44znYU4DE403IarQ==</DQ><InverseQ>VoXCETqZH9Kts/leD7wSNewEgZdJIeCZpE8NYyd0ALfjdRIzb5qeiGb+hhJ/umlEgLhRQFMznNhdCvjLktBucQ==</InverseQ><D>C6FVQTggNjBV0khJ88Rm41Gi4pC6G7KN4DdjLkXkNsjMIAR9ESon2vQ6hkQ2KMkXtXCE7sy3DL81Rcx9BkRUkhZIzJazWCTEs0EkE3P2vOY39W83LrFhjvqu4Km+tUYCP5B4zOqwohW53Zq3Oz/rOBQfc5/FQPDoHTtjsb1S6kE=</D></RSAKeyValue>"""

private_key = parse_rsa_key(xml_key)
print(private_key)
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode('utf-8')
print(private_key_pem)

public_key = private_key.public_key()
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')
print(public_key_pem)



print("-------------------------------------")


def parse_rsa_public_key(xml_string):
    # Parse the XML string
    root = ElementTree.fromstring(xml_string)
    
    # Extract the Modulus and Exponent, decode from Base64, and convert to integers
    modulus = int(base64.b64decode(root.find('Modulus').text).hex(), 16)
    exponent = int(base64.b64decode(root.find('Exponent').text).hex(), 16)
    
    # Create an RSA public key
    public_key = rsa.RSAPublicNumbers(exponent, modulus).public_key()
    return public_key

# Example usage
xml_key = """<RSAKeyValue>
<Modulus>uS6T7+oyJljRJHQygcN2J9aXBnG8mwjOKp7vrvZzuid9MI0g8UX42q/7rVMe6VBjbDxag/Vq0d3LEkVWf/W6P5VjGG54FfKrnGWkGH/7iywp14IDGDy+00tBjVFy5t7Ik6MV8CKlo2JhbWZsxt+3yaLzl7KNE8a0i63BQkgPWik=</Modulus>
<Exponent>AQAB</Exponent>
</RSAKeyValue>"""

xml_key = decoded_public_key

public_key = parse_rsa_public_key(xml_key)

# Serialize the key to PEM format (optional)
pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print(pem.decode('utf-8'))





