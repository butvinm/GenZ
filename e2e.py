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
print(res)
print(res.json())
crypto_context = res.json()["cryptoContext"]
print(f"{crypto_context=}")
