import os
import sys
from secml.array import CArray
from secml_malware.attack.whitebox.c_extend_dos_evasion import CExtendDOSEvasion
from secml_malware.models.c_classifier_end2end_malware import CClassifierEnd2EndMalware, End2EndModel

# Adapter for the attack'
class CExtendDOSHeaderEvasionAdapter:
    def __init__(self, net, extension=512, random_init=False,iterations=50, threshold=0.5, chunk=None):
        self.net = net
        self.extend_dos =  CExtendDOSEvasion(net,
                        pe_header_extension=extension,
                        iterations=iterations,
                        is_debug=False,
                        threshold=threshold,
                        random_init=random_init,
                        chunk_hyper_parameter=int(chunk) if chunk else None
                        )

    # Run the attack itself
    def generate_attack(self, buffer_content):
        # Classifier
        sample = End2EndModel.bytes_to_numpy(buffer_content, self.net.get_input_max_length(), 256, False)
        # Original Prediction
        _, confidence = self.net.predict(CArray(sample), True)
        conf = confidence[1][0].item()
        # Actual Attack
        y_pred, adv_score, adv_ds, f_obj = self.extend_dos.run(CArray(sample), CArray(conf))
        adv_x = adv_ds.X[0, :]
        # We have to dump the memory content to a file to run the next method
        # We could modify it to run from memory, but ...
        tmp_file_path = "/tmp/dump"
        f = open(tmp_file_path,"wb")
        f.write(buffer_content)
        f.close()
        # Generate modified binary from file
        real_adv_x = self.extend_dos.create_real_sample_from_adv(tmp_file_path, adv_x)
        # return modified (attack) file
        return real_adv_x
