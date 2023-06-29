# Adjust Path
import sys
# We need that because the modules are in the upper directory
sys.path.append("..") 

# Import Utils
from Utils.binaries import *

# Import model controller
from NFS.Controller import *
nfs = NFSbase()

# Read Input File
original_payload = open(sys.argv[1],'rb').read()
# Compute MD5
md5 = get_md5_string(original_payload)
# Check valid PE
valid = is_valid_pe(original_payload)
# Check detection
detection, confidence = nfs.Detect(original_payload)
# Print all info
print("Input:  [%s] [%d bytes] [Valid = %d] | %s  (%f)" % (md5,len(original_payload),valid,detection,confidence))
