# Adjust Path
import sys
# We need that because the modules are in the upper directory
sys.path.append("..") 

# Import Utils
from Utils.binaries import *

# Import model controller
from MalConv.Controller import *
malconv = MalConv()
# Import model controller
from NFS.Controller import *
nfs = NFSbase(8081)

# Read Input File
original_payload = open(sys.argv[1],'rb').read()
# Compute MD5
md5 = get_md5_string(original_payload)
# Check valid PE
valid = is_valid_pe(original_payload)
# Check detection
detection, confidence = malconv.Detect(original_payload)
# Print all info
print("MalConv: [%s] [%d bytes] [Valid = %d] | %s  (%f)" % (md5,len(original_payload),valid,detection,confidence))
# Check detection
detection, confidence = nfs.Detect(original_payload)
print("NFS:     [%s] [%d bytes] [Valid = %d] | %s  (%f)" % (md5,len(original_payload),valid,detection,confidence))
# Attack
attack_payload = malconv.PartialDOS(original_payload)
# Compute MD5
md5 = get_md5_string(attack_payload)
# Check valid PE
valid = is_valid_pe(attack_payload)
# Check detection
detection, confidence = malconv.Detect(attack_payload)
# Print all info
print("MalConv: [%s] [%d bytes] [Valid = %d] | %s (%f)" % (md5,len(attack_payload),valid,detection,confidence))
# Check detection
detection, confidence = nfs.Detect(attack_payload)
print("NFS:     [%s] [%d bytes] [Valid = %d] | %s  (%f)" % (md5,len(original_payload),valid,detection,confidence))
