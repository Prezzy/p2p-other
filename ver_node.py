import time
from verifier_bo import Verifier

PORT = 8001
ID = 1

verifier = Verifier("127.0.0.1", PORT, ID)

verifier.start()
