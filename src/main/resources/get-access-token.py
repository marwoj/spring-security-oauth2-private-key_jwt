from datetime import datetime
import jwt
import time
import requests

print('Loading private key...')
with open('private.key') as pk:
    private_key = pk.read()

print('Generating signed JWT assertion...')
claim = {
    'iss': 'client1',
    'exp': int(time.time()) + 1000,
    'aud': 'http://localhost:8080/oauth2'
}
assertion = jwt.encode(claim, private_key, algorithm='RS256', headers={'alg':'RS256'}).decode('utf8')
print(assertion)
print('Making OAuth request...')
r = requests.post('http://localhost:8080/oauth2/token', data = {
    'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    'assertion': assertion
})

print('Status:', r.status_code)
print(r.json())
