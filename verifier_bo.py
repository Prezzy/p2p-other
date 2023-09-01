import json
import time
import os
from p2pnetwork.node import Node
from jwcrypto import jwk, jws
from db import Database, User


class Verifier (Node):

    def __init__(self, host, port, id=None, callback=None, max_connections=4):
        super(Verifier, self).__init__(host, port, id, callback, max_connections)

        self.db = Database()
        self.token_pubkey = None
        self.neighbours = None

        self.total_bytes_recieved = 0

        self.load_keys()

    def node_message(self, connected_node, message):
        
        #print("node " + self.id + " node_message from " + connected_node.id + ": " + str(message))

        if('_type' in message):
            if (message['_type'] == 'auth-token'):
                self.total_bytes_recieved += len(json.dumps(message).encode('utf-8'))
                self.received_token_auth(connected_node, message)

    def load_keys(self):
        with open("token_key.txt".format()) as file:
            key_dict = file.read()
            self.token_pubkey = jwk.JWK.from_json(key_dict)

    def unwrap_token(self, token):
        Token = jws.JWS()
        Token.deserialize(token, key=self.token_pubkey)
        payload = json.loads(Token.payload.decode('utf-8'))

        return payload

    def received_token_auth(self, node, data):
        tick = time.perf_counter()
        nonce = os.urandom(8).hex()
        self.db.create_context(data['ssid'])
        payload = self.unwrap_token(data['token'])
        message = {"_type": "auth-response", "result": "Accept"}
        toc = time.perf_counter()
        self.send_to_nodes(message)
        with open("verifier_time_bo", "a+") as file:
            file.write("{}\n".format(toc-tick))
            file.write("{}\n".format(self.total_bytes_recieved))

        self.stop()
