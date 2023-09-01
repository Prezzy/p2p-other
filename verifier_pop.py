import os
import json
import time
from hashlib import sha256
from p2pnetwork.node import Node
from db import Database, User

from jwcrypto import jwk, jws
from jwcrypto.common import json_encode

#compression_algo = 'bzip2'


class Verifier (Node):

    def __init__(self, host, port, id=None, callback=None, max_connections=4):
        super(Verifier, self).__init__(host, port, id, callback, max_connections)

        self.db = Database()
        self.key = None
        self.token_pubkey = None
        self.neighbours = None

        self.total_bytes_recieved = 0

        self.time = {"auth-init":0,"auth-final":0}

        #load keys from file
        self.load_keys()

    def node_message(self, connected_node, message):
        
        #print("node " + self.id + " node_message from " + connected_node.id + ": " + str(message))

        if('_type' in message):
            if (message['_type'] == 'auth-init'):
                self.total_bytes_recieved += len(json.dumps(message).encode('utf-8'))
                self.received_auth_init(connected_node, message)

            if (message['_type'] == 'auth-tokens'):
                self.total_bytes_recieved += len(json.dumps(message).encode('utf-8'))
                self.received_token_auth(connected_node, message)

    def load_keys(self):
        with open("token_public_key.txt".format()) as file:
            key_dict = file.read()
            self.token_pubkey = jwk.JWK.from_json(key_dict)

    def unwrap_token(self, token, key):
        Token = jws.JWS()
        Token.deserialize(token, key=key)
        payload = json.loads(Token.payload.decode('utf-8'))

        return payload

    def hash_token(self, token):

        return sha256(token.encode('utf-8')).hexdigest()

    def received_auth_init(self, node, data):
        #Start verifier time
        tick = time.perf_counter()
        nonce = os.urandom(8).hex()
        self.db.create_context(data['ssid'])
        self.db.store_challenge(data['ssid'], self.id, nonce)
        message = {'_type': 'challenge', 'ssid':data['ssid'], 'nonce':nonce}
        toc = time.perf_counter()
        self.time["auth-init"] = toc - tick
        self.send_to_nodes(message)
        

    def received_token_auth(self, node, data):
        tick = time.perf_counter()
        ssid = data['ssid']
        dpop = data['dpop']
        token = data['token']

        if self.db.has_key(ssid):

            token_payload = self.unwrap_token(token, self.token_pubkey)

            user_key_dic = token_payload['pub-key']
            user_key = jwk.JWK.from_json(json.loads(user_key_dic))

            dpop_payload = self.unwrap_token(dpop, user_key)
            if not dpop_payload['ath'] == self.hash_token(token):
                print("hash does not match")

            challenge = self.db.get_challenge(ssid)

            if not dpop_payload['jti'] == challenge:
                print("nonce does not match")

            if not dpop_payload['htu'] == "127.0.0.1:8001":
                print("intended audience not correct")


            message = {"_type": "auth-response", "ssid": ssid, "result": "Accept"}
            toc = time.perf_counter()

            self.send_to_nodes(message)

            self.time['auth-final'] = toc-tick
            with open("verifier_time_pop", "a+") as file:
                file.write("{}\n".format(self.time['auth-init'] + self.time['auth-final']))
                file.write("total bytes recieved {}\n".format(self.total_bytes_recieved))

            self.stop()

