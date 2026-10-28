import ssl
import http.client
import uuid
import base64
import json

from tpm2_pytss import *
from tpm2_pytss.utils import *
from tpm2_pytss import *
from tpm2_pytss.tsskey import TSSPrivKey
from cryptography.hazmat.backends import default_backend

from datetime import datetime, timedelta, timezone

_parent_ecc_template = TPMT_PUBLIC(
    type=TPM2_ALG.ECC,
    nameAlg=TPM2_ALG.SHA256,
    objectAttributes=TPMA_OBJECT.USERWITHAUTH
    | TPMA_OBJECT.RESTRICTED
    | TPMA_OBJECT.DECRYPT
    | TPMA_OBJECT.NODA
    | TPMA_OBJECT.FIXEDTPM
    | TPMA_OBJECT.FIXEDPARENT
    | TPMA_OBJECT.SENSITIVEDATAORIGIN,
    authPolicy=b"",
    parameters=TPMU_PUBLIC_PARMS(
        eccDetail=TPMS_ECC_PARMS(
            symmetric=TPMT_SYM_DEF_OBJECT(
                algorithm=TPM2_ALG.AES,
                keyBits=TPMU_SYM_KEY_BITS(aes=128),
                mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
            ),
            scheme=TPMT_ECC_SCHEME(scheme=TPM2_ALG.NULL),
            curveID=TPM2_ECC.NIST_P256,
            kdf=TPMT_KDF_SCHEME(scheme=TPM2_ALG.NULL),
        ),
    ),
)



ectx = ESAPI(tcti="swtpm:port=2321")
ectx.startup(TPM2_SU.CLEAR)

inSensitive = TPM2B_SENSITIVE_CREATE()
primary1, parent, _, _, _ = ectx.create_primary(inSensitive,  TPM2B_PUBLIC(publicArea=_parent_ecc_template))

f = open("tpm-key.pem", "r")
k = TSSPrivKey.from_pem(f.read().encode("utf-8"))

hmacKeyHandle = ectx.load(primary1, k.private, k.public)
ectx.flush_context(primary1)

clientID = 'client1'

payload = {
        "iss": clientID,                                 
        "iat": int(datetime.now(timezone.utc).timestamp()),
        "exp": int((datetime.now(timezone.utc) + timedelta(seconds=3)).timestamp()), 
        "aud": "https://server.domain",
        "jti": str(uuid.uuid4())
}

payload_bytes = json.dumps(payload).encode("utf-8")
encoded_payload = base64.b64encode(payload_bytes)

psk_hmac = ectx.hmac(hmacKeyHandle, encoded_payload , TPM2_ALG.SHA256)
ectx.flush_context(hmacKeyHandle)

print(f"Identity: {encoded_payload.decode()}")
print(f"PSK: {psk_hmac.buffer.tobytes().hex()}")

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
context.maximum_version = ssl.TLSVersion.TLSv1_3
context.set_ciphers('PSK')

def callback(hint):
    return encoded_payload, psk_hmac.buffer.tobytes()

context.set_psk_client_callback(callback)
context.keylog_filename = "/tmp/client_keylog.log"

connection = http.client.HTTPSConnection('127.0.0.1', 8081, context = context)
headers = {}
connection.request('GET', '/', None, headers)
response = connection.getresponse()
print(response.read().decode())