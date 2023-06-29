# Adjust Path
import sys
# We need that because the modules are in the upper directory
sys.path.append("..") 

# Import Utils
from Utils.binaries import *
from Utils.zipper import *

# Import model controller
from NFS.Controller import *
nfs = NFSbase()

malware_dir = sys.argv[1]
goodware_dir = sys.argv[2]

train_set = build_zip(malware_dir,goodware_dir) 

try:
    nfs.train(open(train_set,'rb').read())
except:
    print("Training slowing down...")
