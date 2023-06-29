import requests
import json
import base64
import pickle

# Adapter for the Angr docker
class Angr:
    def __init__(self, port=8080):
        self.port = port
        self.timeout = 10

    # Get FCG for a binary
    def FCG(self, payload):
        # Build url for the detection request 
        url = "http://127.0.0.1:%d/fcg" % self.port
        encoded_binary = base64.encodebytes(payload).decode('ascii')
        payload_to_send = json.dumps({'binary' : encoded_binary})
        # Query the docker
        res = requests.post(url, json=payload_to_send)
        # Response must be interpreted as JSON
        res = json.loads(res.content)
        # If valid response
        if res['result']:
            # decode content from base64 back to bytes
            payload_pkl = base64.decodebytes(res['cg'].encode('ascii'))
            payload = pickle.loads(payload_pkl)
            # return the bytes (should be a PE)
            return payload
        # If invalid, return no payload
        return None
