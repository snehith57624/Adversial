# Adjust Path
import sys
# We need that because the modules are in the upper directory
sys.path.append("..") 

# Import Utils
from Utils.binaries import *

# Import model controller
from MalConv.Controller import *
malconv = MalConv()

# Read Input File
original_payload = open(sys.argv[1],'rb').read()
# Compute MD5
md5 = get_md5_string(original_payload)
# Check valid PE
valid = is_valid_pe(original_payload)
# Check detection
detection, confidence = malconv.Detect(original_payload)
# Print all info
print("Input:  [%s] [%d bytes] [Valid = %d] | %s  (%f)" % (md5,len(original_payload),valid,detection,confidence))
# Attack
attack_payload = malconv.Kreuk(original_payload, iterations=3)
# Compute MD5
md5 = get_md5_string(attack_payload)
# Check valid PE
valid = is_valid_pe(attack_payload)
# Check detection
detection, confidence = malconv.Detect(attack_payload)
# Print all info
print("Output: [%s] [%d bytes] [Valid = %d] | %s (%f)" % (md5,len(attack_payload),valid,detection,confidence))
