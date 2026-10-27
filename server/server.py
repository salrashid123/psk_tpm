
import ssl

from flask import Flask
import hmac
import hashlib
import json
import base64
import binascii

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.maximum_version = ssl.TLSVersion.TLSv1_3
context.set_ciphers('PSK')

psk_table = { 'client1': "my_api_key".encode('utf-8') }

def callback(identity):
    print(identity)
    payload = identity
    try:
     
        decoded_json_bytes = base64.b64decode(identity)
        payload = json.loads(decoded_json_bytes)
        print(payload)
        print(payload['iss'])
        kk = psk_table[payload['iss']]   

    except binascii.Error as e:
        print(f"Base64 Decoding Error: {e}")
        return None
        
    except TypeError as e:
        print(f"Type Error: {e}")
        return None

    except KeyError:
        print("The requested key was not found.")
        return None

    
    signature_bytes = hmac.digest(kk, identity.encode('utf-8'), hashlib.sha256)
    print(f"PSK: {signature_bytes.hex()}")

    return signature_bytes

context.set_psk_server_callback(callback)


app = Flask(__name__)

@app.route('/')
def index():
    return 'ok'

if __name__ == '__main__':
    app.run(debug=True, ssl_context=context, port=8081)