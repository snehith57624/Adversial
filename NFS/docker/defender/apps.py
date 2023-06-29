import lief
import pandas as pd
from flask import Flask, jsonify, request
from defender.models.attribute_extractor import PEAttributeExtractor
import zipfile
import os
from defender.train_classifier import JSONAttributeExtractor, NeedForSpeedModel
from sklearn.ensemble import RandomForestClassifier
import _pickle as cPickle
import gzip
import tempfile
from defender.zipper import *

THRESHOLD = 0.75

def create_app(model, threshold):
    app = Flask(__name__)
    app.config['model'] = model

    # Try to detect a sample
    @app.route('/detect', methods=['POST'])
    def post():
        # Error checking
        if request.headers['Content-Type'] != 'application/octet-stream':
            resp = jsonify({'error': 'expecting application/octet-stream'})
            resp.status_code = 400  # Bad Request
            return resp
        # Get the content
        bytez = request.data
        # Try to detect
        try:
            # initialize feature extractor with bytez
            pe_att_ext = PEAttributeExtractor(bytez)
            # extract PE attributes
            atts = pe_att_ext.extract()
            # transform into a dataframe
            atts = pd.DataFrame([atts])
            model = app.config['model']
            # query the model
            detection = model.predict_threshold(atts, threshold)[0]
            confidence = model.predict_proba(atts)[0][detection]
            result = 1
        except (lief.bad_format, lief.read_out_of_bound) as e:
            # Error cases
            result = 0
            detection = 0
            confidence = 0

        # Error
        if not isinstance(result, int) or result not in {0, 1}:
            result = 0
            detection = 0
            confidence = 0

        # Return of the HTTP Request
        # Results encoded as JSON
        resp = jsonify({'result':result, 'detection':detection, 'confidence':confidence})
        resp.status_code = 200
        return resp

    @app.route('/train', methods=['POST'])
    def train_model():
        # Error checking
        if request.headers['Content-Type'] != 'application/octet-stream':
            resp = jsonify({'error': 'expecting application/octet-stream'})
            resp.status_code = 400  # Bad Request
            return resp
        # Get the content
        bytez = request.data

        print("Received %d bytes" % len(bytez))

        train_data = []
        mw_files, gw_files = unzip(bytez)
        for _file in mw_files:
            try:
                f = open(_file,'rb').read()
                pe_att_ext = PEAttributeExtractor(f)
                atts = pe_att_ext.extract()
                atts['label'] = 1
                train_data.append(atts)
            except:
                pass
        for _file in gw_files:
            try:
                f = open(_file,'rb').read()
                pe_att_ext = PEAttributeExtractor(f)
                atts = pe_att_ext.extract()
                atts['label'] = 0
                train_data.append(atts)
            except:
                pass

        training_data = pd.DataFrame(train_data)
        clf = NeedForSpeedModel(classifier=RandomForestClassifier(n_jobs=-1))
        clf.fit(training_data)

        # Here we can save the model if we want

        # Update model 
        app.config['model'] = clf

        resp = jsonify({'message': 'Model trained successfully'})
        resp.status_code = 200
        return resp

    # Get model information
    @app.route('/model', methods=['GET'])
    def get_model():
        # curl -XGET http://127.0.0.1:8080/model
        resp = jsonify(app.config['model'].model_info())
        resp.status_code = 200
        return resp

    return app
