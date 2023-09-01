import time
from client_bo import Client


client = Client("127.0.0.1", 8000, 0)


print("client starting...")
client.start()
print("client started")


print("client connecting")
client.connect_with_node('127.0.0.1',8001)
print("client connected")

print("client authenticating")
client.initiate_auth()
print("client authenticated")
