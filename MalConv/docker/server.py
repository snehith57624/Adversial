from flask import Flask, jsonify, request
import os
import base64
import json
from secml_malware.models.malconv import MalConv
from secml_malware.models.c_classifier_end2end_malware import CClassifierEnd2EndMalware, End2EndModel
from adapters import cheaderevasion as che
from adapters import ckreukevasion as cke
from adapters import detector as det
from adapters import cextenddosevasion as cede
from adapters import ccontentshift as cse
from adapters import cpaddingevasion as pde
from factory import MalconvFactory


# Model is global
# If we retrain, we update the global variable with the new model
net = []

# Flask App Creation
def create_app():
    app = Flask(__name__)
    global net
    # At startup we always instantiate the base model
    net = MalConv()
    net = CClassifierEnd2EndMalware(net)
    net.load_pretrained_model() 
 
    # Detection Request handling
    @app.route('/detect', methods=['POST'])
    def detect():
        # global model
        global net

        # Check for errors
        if request.headers['Content-Type'] != 'application/octet-stream':
            resp = jsonify({'error': 'expecting application/octet-stream'})
            resp.status_code = 400  # Bad Request
            return resp

        # Get the content of the HTTP request
        # the content is supposed to be a PE file
        bytez = request.data

        # Lets try to classify it
        try:
            result = 1
            # Instantiate an adapter for the classifier
            # Pass the network each time
            # It is important because we might update the network between two requests
            _det = det.DetectorAdapter(net)
            # Get detection label (0,1) and confidence (0..1)
            detection, confidence = _det.detect(bytez)
        except:
            # Error cases
            result = 0
            detection = 0
            confidence = 0

        # Return of the HTTP Request
        # Results encoded as JSON
        resp = jsonify({'result':result, 'detection':detection, 'confidence':confidence})
        resp.status_code = 200
        return resp

    # Handle ContentShift Attack Request
    @app.route('/shift', methods=['POST'])
    def contentshift():
        global net

        # Check errors
        if request.headers['Content-Type'] != 'application/json':
            resp = jsonify({'error': 'expecting application/json'})
            resp.status_code = 400  # Bad Request
            return resp
    
        # Get Payload
        bytez = request.json

        # Try to perform the attack
        try:
            # result = 1 means operation was OK
            result = 1
            res = json.loads(bytez)
            binary = base64.decodebytes(res['binary'].encode('ascii'))
            # Instantiate an adapter for the attack class
            # once again, pass the network at every time
            extension = res['extension']
            random_init = res['random_init']
            iterations = res['iterations']
            threshold = res['threshold']
            chunk = res['chunk']
            CCSEvd = cse.CContentShiftEvasionAdapter(net,extension=extension, random_init=random_init,iterations=iterations, threshold=threshold, chunk=chunk)
            # generate the attack
            content = CCSEvd.generate_attack(binary)
            # if success, encode in base64
            # we cannot just return bytes, we need to encode as string
            # then we decode in the client side
            content = base64.encodebytes(content).decode('ascii')
        except:
            # Handle Errors
            result = 0
            content = ""

        # Returns
        resp = jsonify({'result':result, 'content':content})
        resp.status_code = 200
        return resp

    # Handle CPaddingEvasion Attack Request
    @app.route('/padding', methods=['POST'])
    def paddingevasion():
        global net

        # Check errors
        if request.headers['Content-Type'] != 'application/json':
            resp = jsonify({'error': 'expecting application/json'})
            resp.status_code = 400  # Bad Request
            return resp
    
        # Get Payload
        bytez = request.json

        # Try to perform the attack
        try:
            # result = 1 means operation was OK
            result = 1
            res = json.loads(bytez)
            binary = base64.decodebytes(res['binary'].encode('ascii'))
            # Instantiate an adapter for the attack class
            # once again, pass the network at every time
            #extension = res['extension']
            random_init = res['random_init']
            iterations = res['iterations']
            threshold = res['threshold']
            how_many = res['how_many']
            penalty_regularizer = res['penalty_regularizer']
            #import IPytnon
            #IPython.embed()
            CPed = pde.CPaddingEvasionAdapter(net, random_init=random_init,iterations=iterations, threshold=threshold, how_many=how_many, penalty_regularizer=penalty_regularizer)
            # generate the attack
            content = CPed.generate_attack(binary)
            # if success, encode in base64
            # we cannot just return bytes, we need to encode as string
            # then we decode in the client side
            content = base64.encodebytes(content).decode('ascii')
        except:
            # Handle Errors
            result = 0
            content = ""

        # Returns
        resp = jsonify({'result':result, 'content':content})
        resp.status_code = 200
        return resp



    # Handle ExtendDOSHeader Attack Request
    @app.route('/extend', methods=['POST'])
    def extenddos():
        global net

        # Check errors
        if request.headers['Content-Type'] != 'application/json':
            resp = jsonify({'error': 'expecting application/json'})
            resp.status_code = 400  # Bad Request
            return resp
    
        # Get Payload
        bytez = request.json

        # Try to perform the attack
        try:
            # result = 1 means operation was OK
            result = 1
            res = json.loads(bytez)
            binary = base64.decodebytes(res['binary'].encode('ascii'))
            # Instantiate an adapter for the attack class
            # once again, pass the network at every time
            extension = res['extension']
            random_init = res['random_init']
            iterations = res['iterations']
            threshold = res['threshold']
            chunk = res['chunk']
            CEDHEvd = cede.CExtendDOSHeaderEvasionAdapter(net,extension=extension, random_init=random_init,iterations=iterations, threshold=threshold, chunk=chunk)
            # generate the attack
            content = CEDHEvd.generate_attack(binary)
            # if success, encode in base64
            # we cannot just return bytes, we need to encode as string
            # then we decode in the client side
            content = base64.encodebytes(content).decode('ascii')
        except:
            # Handle Errors
            result = 0
            content = ""

        # Returns
        resp = jsonify({'result':result, 'content':content})
        resp.status_code = 200
        return resp



    # Handle Kreuk Attack Request
    @app.route('/kreuk', methods=['POST'])
    def kreuk():
        global net

        # Check errors
        if request.headers['Content-Type'] != 'application/json':
            resp = jsonify({'error': 'expecting application/json'})
            resp.status_code = 400  # Bad Request
            return resp
    
        # Get Payload
        bytez = request.json

        # Try to perform the attack
        try:
            # result = 1 means operation was OK
            result = 1
            res = json.loads(bytez)
            binary = base64.decodebytes(res['binary'].encode('ascii'))
            # Instantiate an adapter for the attack class
            # once again, pass the network at every time
            padding_bytes = res['padding_bytes']
            epsilon = res['epsilon']
            iterations = res['iterations']
            threshold = res['threshold']
            slack = res['slack']
            CKEvd = cke.CKreukEvasionAdapter(net,padding_bytes,epsilon,iterations,threshold,slack)

            # generate the attack
            content = CKEvd.generate_attack(binary)
            # if success, encode in base64
            # we cannot just return bytes, we need to encode as string
            # then we decode in the client side
            content = base64.encodebytes(content).decode('ascii')
        except:
            # Handle Errors
            result = 0
            content = ""

        # Returns
        resp = jsonify({'result':result, 'content':content})
        resp.status_code = 200
        return resp

    # Handle Partial DOS Attack Request
    @app.route('/partialdos', methods=['POST'])
    def partial_dos():
        global net

        # Check errors
        if request.headers['Content-Type'] != 'application/json':
            resp = jsonify({'error': 'expecting application/json'})
            resp.status_code = 400  # Bad Request
            return resp
    
        # Get Payload
        bytez = request.json

        # Try to perform the attack
        try:
            # result = 1 means operation was OK
            result = 1
            # Instantiate an adapter for the attack class
            # once again, pass the network at every time
            res = json.loads(bytez)
            binary = base64.decodebytes(res['binary'].encode('ascii'))
            random_init = res['random_init']
            iterations = res['iterations']
            all_dos = res['all_dos']
            threshold = res['threshold']
            CHEvd = che.CHeaderEvasionAdapter(net,random_init,iterations,all_dos,threshold)
            # generate the attack
            content = CHEvd.generate_attack(binary)
            # if success, encode in base64
            # we cannot just return bytes, we need to encode as string
            # then we decode in the client side
            content = base64.encodebytes(content).decode('ascii')
        except:
            # Handle Errors
            result = 0
            content = ""

        # Returns
        resp = jsonify({'result':result, 'content':content})
        resp.status_code = 200
        return resp

    # Request to train a new MalConv model
    @app.route('/train', methods=['POST'])
    def train_model():
        global net
        # Error checking
        if 'file' not in request.files:
            resp = jsonify({'error': 'No file attached'})
            resp.status_code = 400  # Bad Request
            return resp

            # Not implemented yet
            bytez = request.data

            mw_files, gw_files = unzip(bytez)
            malconvfactory = MalconvFactory()
            net = malconvfactory.train_classifier(mw_files, gw_files)

            # Just return
            resp = jsonify({'message': 'Model trained successfully'})
            resp.status_code = 200
            return resp

    # Method to test if the docker is operating
    @app.route('/test', methods=['GET'])
    def test_model():
        # Only return that it is working
        # Useful to test the network connectivity
        resp = jsonify({"result":"Working"})
        resp.status_code = 200
        return resp

    return app

# Create the App
app = create_app()
# Server startup
from gevent.pywsgi import WSGIServer
http_server = WSGIServer(('', 8080), app)
http_server.serve_forever()
