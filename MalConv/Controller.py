import requests
import json
import base64

# Adapter for the MalConv docker
class MalConv:
    def __init__(self, port=8080):
        self.port = port
        self.timeout = 10

    # Train the model
    def train(self, payload):
        # Build url for the train request
        url = "http://127.0.0.1:%d/train" % self.port
        # Query the docker
        res = requests.post(url, data=payload, headers={'Content-Type': 'application/octet-stream'}, timeout=self.timeout)

    # Check model prediction for the payload
    def Detect(self, payload):
        # Build url for the detection request 
        url = "http://127.0.0.1:%d/detect" % self.port
        # Query the docker
        res = requests.post(url, data=payload, headers={'Content-Type': 'application/octet-stream'}, timeout=self.timeout)
        # Response must be interpreted as JSON
        res = json.loads(res.content)
        # If valid response
        if res['result']:
            # use label to index goodware or malware
            det = ["Goodware","Malware"][res['detection']]
            # get confidence
            confidence = res['confidence']
            # return label and confidence
            return det, confidence
        # If invalid, return no confidence
        return "Goodware", 0

    # Perform the ContentShift attack
    def ContentShift(self, payload, extension=512, random_init=False,iterations=50, threshold=0.5, chunk=256):
        # Build url for the attack request 
        url = "http://127.0.0.1:%d/shift" % self.port
        encoded_binary = base64.encodebytes(payload).decode('ascii')
        payload_to_send = json.dumps({'binary' : encoded_binary, 'extension':extension,'random_init':random_init,'iterations':iterations,'threshold':threshold,'chunk':chunk})
        # Query the docker
        res = requests.post(url, json=payload_to_send)
        # Response must be interpreted as JSON
        res = json.loads(res.content)
        # If valid response
        if res['result']:
            # decode content from base64 back to bytes
            payload = base64.decodebytes(res['content'].encode('ascii'))
            # return the bytes (should be a PE)
            return payload
        # If invalid, return no payload
        return None

    def PaddingEvasion(self, payload, random_init=False,iterations=100, threshold=0, how_many=100, penalty_regularizer = 0):
        # Build url for the attack request 
        url = "http://127.0.0.1:%d/padding" % self.port
        encoded_binary = base64.encodebytes(payload).decode('ascii')
        payload_to_send = json.dumps({'binary' : encoded_binary,'how_many':how_many,'random_init':random_init,'iterations':iterations,'threshold':threshold, 'penalty_regularizer':penalty_regularizer})
        # Query the docker
        res = requests.post(url, json=payload_to_send)
        # Response must be interpreted as JSON
        res = json.loads(res.content)
        # If valid response
        if res['result']:
            # decode content from base64 back to bytes
            payload = base64.decodebytes(res['content'].encode('ascii'))
            # return the bytes (should be a PE)
            return payload
        # If invalid, return no payload
        return None
 
    # Perform the ExtendDOSHeader attack
    def ExtendDOSHeader(self, payload, extension=512, random_init=False,iterations=50, threshold=0.5, chunk=None):
        # Build url for the attack request 
        url = "http://127.0.0.1:%d/extend" % self.port
        encoded_binary = base64.encodebytes(payload).decode('ascii')
        payload_to_send = json.dumps({'binary' : encoded_binary, 'extension':extension,'random_init':random_init,'iterations':iterations,'threshold':threshold,'chunk':chunk})
        # Query the docker
        res = requests.post(url, json=payload_to_send)
        # Response must be interpreted as JSON
        res = json.loads(res.content)
        # If valid response
        if res['result']:
            # decode content from base64 back to bytes
            payload = base64.decodebytes(res['content'].encode('ascii'))
            # return the bytes (should be a PE)
            return payload
        # If invalid, return no payload
        return None
 
    # Perform the Kreuk attack
    def Kreuk(self, payload,padding_bytes=512,epsilon=0.1, iterations=1, threshold=0.5,slack=False):
        # Build url for the attack request 
        url = "http://127.0.0.1:%d/kreuk" % self.port
        encoded_binary = base64.encodebytes(payload).decode('ascii')
        payload_to_send = json.dumps({'binary' : encoded_binary, 'padding_bytes':padding_bytes,'epsilon':epsilon,'iterations':iterations,'threshold':threshold,'slack':slack})
        # Query the docker
        res = requests.post(url, json=payload_to_send)
        # Response must be interpreted as JSON
        res = json.loads(res.content)
        # If valid response
        if res['result']:
            # decode content from base64 back to bytes
            payload = base64.decodebytes(res['content'].encode('ascii'))
            # return the bytes (should be a PE)
            return payload
        # If invalid, return no payload
        return None
    
    # FullDos and Partial DOS are basically the same, just different parameters
    def FullDOS(self, payload, random_init=False, iterations=50, all_dos=True, threshold=0.5):
        return self.PartialDOS(payload,random_init,iterations,all_dos,threshold)

    # Perform the Partial DOS attack
    def PartialDOS(self, payload, random_init=False, iterations=50, all_dos=False, threshold=0.5):
        # Build url for the attack request 
        url = "http://127.0.0.1:%d/partialdos" % self.port
        encoded_binary = base64.encodebytes(payload).decode('ascii')
        payload_to_send = json.dumps({'binary' : encoded_binary, 'random_init' : random_init, 'iterations' : iterations, 'all_dos': all_dos, 'threshold': threshold})
        # Query the docker
        res = requests.post(url, json=payload_to_send)
        # Response must be interpreted as JSON
        res = json.loads(res.content)
        # If valid response
        if res['result']:
            # decode content from base64 back to bytes
            payload = base64.decodebytes(res['content'].encode('ascii'))
            # return the bytes (should be a PE)
            return payload
        # If invalid, return no payload
        return None

