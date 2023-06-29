# Adjust Path
import sys
# We need that because the modules are in the upper directory
sys.path.append("..") 
import time

# Import Utils
from Utils.binaries import *
from Utils.zipper import *

# Import model controller
from NFS.Controller import *
nfs = NFSbase()

malware_dir = sys.argv[1]
goodware_dir = sys.argv[2]

# Test files with original NFS
for _file in os.listdir(malware_dir):
    original_payload = open(os.path.join(malware_dir,_file),'rb').read()
    md5 = get_md5_string(original_payload)
    valid = is_valid_pe(original_payload)
    # Check detection
    detection, confidence = nfs.Detect(original_payload)
    # Print all info
    print("Before:  [%s] [%d bytes] [Valid = %d] | %s  (%f)" % (md5,len(original_payload),valid,detection,confidence))

# Train
train_set = build_zip(malware_dir,goodware_dir) 

try:
    nfs.train(open(train_set,'rb').read())
except:
    print("Training slowing down...")

time.sleep(30)

# Test files with original NFS
for _file in os.listdir(malware_dir):
    original_payload = open(os.path.join(malware_dir,_file),'rb').read()
    md5 = get_md5_string(original_payload)
    valid = is_valid_pe(original_payload)
    # Check detection
    detection, confidence = nfs.Detect(original_payload)
    # Print all info
    print("After:  [%s] [%d bytes] [Valid = %d] | %s  (%f)" % (md5,len(original_payload),valid,detection,confidence))
