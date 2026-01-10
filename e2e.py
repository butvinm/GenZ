import base64
import requests

API_URL = "http://localhost:6969/api"

print("[create session]")
res = requests.post(f"{API_URL}/v0.1.0/register")
res.raise_for_status()
session_id = res.json()["sessionId"]
print(f"{session_id=}")

print("[get crypto context]")
res = requests.post(f"{API_URL}/v0.1.0/getCryptoContext", headers={"X-Session-Id": session_id})
res.raise_for_status()
print(res.json())
# cc_encoded = res.json()["cryptoContext"]
# cc_ser = base64.b64decode(cc_encoded)
# print(cc_ser)
