import os
import json
import time
from p2pnetwork.node import Node
from jwcrypto import jwk, jws
from jwcrypto.common import json_encode


compression_algo = None
username = "John"
class Client(Node):

    def __init__(self, host, port, id=None, callback=None, max_connections=4):
        super(Client, self).__init__(host, port, id, callback, max_connections)
        self.db = {}
        self.result = {}
        self.key = None
        self.token = None
        self.token_key = None
        self.neighbours = None
        self.start_time = None
        self.end_local_time = None
        self.end_time = None

        self.fetch_keys()
        self.make_token()
        self.total_bytes_recieved = 0


    def node_message(self, connected_node, message):

        #print("node_message from " + connected_node.id + ": " + str(message))

        if('_type' in message):
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

    def make_token(self):
        nonce = os.urandom(8).hex()
        payload = {'username':username, 'nonce': nonce}
        payload = json.dumps(payload)
        Token = jws.JWS(payload.encode('utf-8'))
        Token.add_signature(self.token_key, None, json_encode({"alg": "RS256"}))
        self.token = Token.serialize()

    def initiate_auth(self):
        self.start_time = time.perf_counter()
        ssid = os.urandom(8).hex()
        message = {"_type": "auth-token", "ssid":ssid, "token": self.token}

        #start user timing
        self.end_local_time = time.perf_counter()
        self.send_to_nodes(message)


    def received_result(self, node, data):
        print(data['result'])
        self.end_time = time.perf_counter()
        with open("client_time_bo", "a+") as file:
            file.write("{}\n".format(self.end_local_time - self.start_time))
        with open("total_run_time_bo", "a+") as file:
            file.write("{}\n".format((self.end_time - self.start_time), self.end_local_time - self.start_time))
            file.write("total bytes recieved: {}".format(self.total_bytes_recieved))

        self.stop()




        


