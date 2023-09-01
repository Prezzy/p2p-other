import os
from jwcrypto import jwk
import json


idxs = ['1', '2']

def main():

    token_key = jwk.JWK.generate(kty='RSA', size=2048)

    with open("token_key.txt", "w") as file:
        file.write(token_key.export())

    with open("token_public_key.txt", "w") as file:
        file.write(token_key.export_public())


    user_key = jwk.JWK.generate(kty='RSA', size=2048)

    with open("user_key.txt", "w") as file:
        file.write(user_key.export())

    with open("user_public_key.txt", "w") as file:
        file.write(user_key.export_public())

main()
