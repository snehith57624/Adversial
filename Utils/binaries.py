import hashlib
import pefile

# Get MD5 of the payload (binary)
def get_md5_string(payload):
    # Compute MD5 (bytes)
    _md5 = hashlib.md5(payload)
    # return the ascii representation of the bytes (digest)
    return _md5.hexdigest()

# Check if buffer has a valid PE
def is_valid_pe(payload):
    # Try to parse
    try:
        # If parse, then valid
        pefile.PE(data=payload)
        return 1
    except:
        # If not parsed, invalid
        return 0
