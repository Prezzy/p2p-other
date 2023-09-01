import os
import json
import time
from hashlib import sha256
from p2pnetwork.node import Node
from db import Database, User
from jwcrypto import jwk, jws
from jwcrypto.common import json_encode 


compression_algo = 'bzip2'

class Client(Node):

    def __init__(self, host, port, id=None, callback=None, max_connections=4):
        super(Client, self).__init__(host, port, id, callback, max_connections)
        self.db = {}
        self.result = {}
        self.user_key = None
        self.token = None
        self.token_key = None
        self.start_time = None
        self.end_local_comp_time = None
        self.end_time = None
        self.local_time = 0
        self.total_time = 0

        self.total_bytes_recieved = 0

        self.fetch_keys()
        self.make_token()


    def node_message(self, connected_node, message):

        #print("node_message from " + connected_node.id + ": " + str(message))

        if('_type' in message):
            if (message['_type'] == 'challenge'):
                self.total_bytes_recieved += len(json.dumps(message).encode('utf-8'))
                self.received_challenge(connected_node, message)

            if (message['_type'] == 'auth-response'):
                self.total_bytes_recieved += len(json.dumps(message).encode('utf-8'))
                self.received_result(connected_node, message)


    def fetch_keys(self):
        '''This function is called as part of the init
        for user node. read key files and create the key
        objects'''
        with open("token_key.txt", "r") as file:
            key_dict = file.read()
            self.token_key = jwk.JWK.from_json(key_dict)

        with open("user_key.txt") as file:
            user_key_dict = file.read()
            self.user_key = jwk.JWK.from_json(user_key_dict)

    def make_token(self):
        payload = {'username': "John", 'pub-key': json_encode(self.user_key.export_public())}
        payload = json.dumps(payload)
        Token = jws.JWS(payload.encode('utf-8'))
        Token.add_signature(self.token_key, None, json_encode({"alg": "RS256"}))
        token = Token.serialize()
        self.token = token

    def hash_token(self, token):
        return sha256(token.encode('utf-8')).hexdigest()

    def create_dpop(self, token, challenge):
        token_hash = self.hash_token(token)
        payload = {"jti":challenge, "htu":"127.0.0.1:8001", "iat": str(time.time()), "ath":token_hash}
        payload = json.dumps(payload)
        Dpop = jws.JWS(payload.encode('utf-8'))
        Dpop.add_signature(self.user_key, None, json_encode({"alg": "RS256"}))
        dpop = Dpop.serialize()

        return dpop


    def initiate_auth(self):
        self.start_time = time.perf_counter()
        ssid = os.urandom(8).hex()
        self.db[ssid] = {'started': 1, 'challenge': -1,'end-state': -1}
        message = {"_type": "auth-init", "ssid": ssid}
        self.local_time += time.perf_counter() - self.start_time
        self.send_to_nodes(message)
        

    def received_challenge(self, node, data):
        tic = time.perf_counter()
        idx = node.id
        ssid = data['ssid']
        nonce = data['nonce']
        self.db[ssid]['challenge'] = nonce
        dpop = self.create_dpop(self.token, nonce)
        message = {'_type': 'auth-tokens', 'ssid': ssid, 'token': self.token, 'dpop': dpop}
        self.local_time += time.perf_counter() - tic
        self.send_to_nodes(message)


    def received_result(self, node, data):
        ssid = data['ssid']
        result = data['result']
        self.db[ssid]['end-state'] = result
        self.end_time = time.perf_counter()
        print(result)
        with open("total_run_time_pop", "a+") as file:
            file.write("{}\n".format(self.end_time - self.start_time))
        with open("client_time_pop", "a+") as file:
            file.write("{}\n".format(self.local_time))
            file.write("total bytes recieved {}\n".format(self.total_bytes_recieved))
        self.stop()




        


