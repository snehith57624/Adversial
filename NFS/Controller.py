import requests
import json
import base64

# Adapter for the MalConv docker
class NFSbase:
    def __init__(self, port=8080):
        self.port = port
        self.timeout = 10

    # Trin the model
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


