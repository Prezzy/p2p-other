from threading import Lock

class User:

    def __init__(self, ssid=None):
        self.ssid = ssid
        self.challenge = None
        self.token = None
        self.dpop = None
        self.state = None

class Database:

    def __init__(self):
        self.database = {}
        self.lock = Lock()

    def has_key(self, key):
        '''Takes a key to the dictionary and returns True if the 
        key exits'''
        with self.lock:
            return key in self.database

    def create_context(self, ssid):
        with self.lock:
            #server_set = server_set.split(',')
            if ssid in self.database:
                pass
            else:
                self.database[ssid] = User(ssid)
                self.database[ssid]


    def store_challenge(self, ssid, idx, challenge):
        '''Takes in the ssid of user, idx of verifier, and string 
        representation of verifier nonce for the session. Stores
        a tuple with verifier id as int, and the nonce value'''

        with self.lock:
            if ssid in self.database:
                self.database[ssid].challenge = challenge
            else:
                print("User not in database")


    def get_challenge(self, ssid):
        with self.lock:
            try:
                return self.database[ssid].challenge
            except:
                print("unable to get challenge for {}".format(ssid))
