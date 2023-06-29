import os
import sys
from secml.array import CArray
from secml_malware.attack.whitebox.c_header_evasion import CHeaderEvasion
from secml_malware.models.c_classifier_end2end_malware import CClassifierEnd2EndMalware, End2EndModel

# Adapter for the Model
class DetectorAdapter:
    def __init__(self, net):
        self.net = net

    # Try to detect if buffer content is malware or not
    def detect(self, buffer_content):
        # Classifier
        sample = End2EndModel.bytes_to_numpy(buffer_content, self.net.get_input_max_length(), 256, False)
        # Prediction
        label, confidence = self.net.predict(CArray(sample), True)
        # From CArray to int
        label = label.tolist()[0]
        # Confidence of the predicted class
        # Predicted class is indexed by label (0,1)
        conf = confidence[label][0].item()
        return label, conf
