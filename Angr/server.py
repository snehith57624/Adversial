from flask import Flask, jsonify, request
import os
import base64
import json
import pickle
from adapters.cfg import *

# Flask App Creation
def create_app():
    app = Flask(__name__)

    # Detection Request handling
    @app.route('/fcg', methods=['POST'])
    def cfg_request():

        # Check for errors
        if request.headers['Content-Type'] != 'application/json':
            esp = jsonify({'error': 'expecting application/json'})
            resp.status_code = 400  # Bad Request
            return resp

        # Get the content of the HTTP request
        # the content is supposed to be a PE file
        bytez = request.json

        # Lets try to classify it
        try:
            result = 1
            res = json.loads(bytez)
            binary = base64.decodebytes(res['binary'].encode('ascii'))
            tmp_file_path = "/tmp/bin"
            f = open(tmp_file_path,"wb").write(binary)
            cg_obj = get_func_list(tmp_file_path)
            cg_pkl = pickle.dumps(cg_obj)
            cg = base64.encodebytes(cg_pkl).decode('ascii')
        except:
            result = 0
            cg = None

        # Return of the HTTP Request
        # Results encoded as JSON
        resp = jsonify({'result':result, 'cg':cg})
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
