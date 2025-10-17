import struct
import sys
import getpass
import hmac
from hashlib import sha1

KDF_ID = 11
KDBX_SIG1 = 0x9AA2D903
KDBX_SIG2 = 0xB54BFB67
MAX_SECRET_LENGTH = 64
SALT_LENGTH = 32
MIN_KDBX_VERSION = 4
ARGON2_SALT_KEY = "S"
KEYFILE = "restored.key"

def parse_kdf(kdf, key):
    """Parse KDF parameters from variant dictionary.
    
    Args:
        kdf (bytes): KDF parameters as variant dictionary
        key (str): Key to look for in dictionary
        
    Returns:
        bytes: Value associated with key or None if not found
    """
    pos = 2 # skip first two bytes    
                            
    while pos < len(kdf):     
          
        t = int.from_bytes(kdf[pos:pos+1], byteorder='little')
        pos += 1
        r = int.from_bytes(kdf[pos:pos+4], byteorder='little')
        pos += 4
        try: # skip if decoding fails
            U = kdf[pos:pos+r].decode('ascii')
            pos += r
        except UnicodeDecodeError:
            pos += r
            continue
        s = int.from_bytes(kdf[pos:pos+4], byteorder='little')
        pos += 4
        V = kdf[pos:pos+s]
        pos += s        
        if U == key:
            return V
        
    return None
def read_xkdb_header(filename):
    """Read KeePass database header and extract Argon2 salt from KDF parameters.
    
    Specification: https://keepass.info/help/kb/kdbx.html
    
    Args:
        filename (str): Path to KeePass database file
        
    Returns:
        bytes: Argon2 salt from KDF parameters
        
    Raises:
        ValueError: If database signature is invalid, version unsupported, or salt not found
        FileNotFoundError: If database file cannot be read
    """
    try: 
        with open(filename, 'rb') as dbfile:
            # Read signature blocks of four bytes each
            sig1, sig2 = struct.unpack('<II', dbfile.read(8))
            
            if sig1 != KDBX_SIG1 or sig2 != KDBX_SIG2:
                raise ValueError("Invalid KeePass database signature.")
            
            dbfile.read(2)
            major = int.from_bytes(dbfile.read(2), byteorder='little')
            print(f"KeePass DB Version: {major}")
            
            if major < MIN_KDBX_VERSION:
                raise ValueError(f"Unsupported KeePass version: {major}")
            else:
                print("Compatible: ✅")
                
            # Read header fields until we find KDF params
            while True:
                t = int.from_bytes(dbfile.read(1), byteorder='little')
                s = int.from_bytes(dbfile.read(4), byteorder='little')
                v = dbfile.read(s)
            
                if t == KDF_ID:  # KDF Variant Map
                   salt = parse_kdf(v, ARGON2_SALT_KEY) 
                   if salt != None:
                       return salt
                   else:         
                       raise ValueError("Argon2 salt not found in KDF parameters")
                
    except Exception as e:
        raise FileNotFoundError(f"KeePass database file not readable. Error {e}.")
def get_secret():
    """Get secret used to set up YK from user input, supporting both ASCII and hex formats.
    
    Returns:
        tuple: Format ('ascii' or 'hex') and secret as hex string
        None: If input is invalid or exceeds length limit
    """
    secret_input = getpass.getpass("Provide the secret used for setting up the YubiKey C/R as plain text or base16 encoded (no delimiters): ")
    # Try hex decode first
    try:
        # Convert hex string to bytes and check length
        hex_bytes = bytes.fromhex(secret_input)
        if len(hex_bytes) <= MAX_SECRET_LENGTH:
            return ('hex', secret_input)
        else:
            print(f"Hex input exceeds {MAX_SECRET_LENGTH} bytes")
            return None
    except ValueError:
        # If not hex, treat as ASCII and convert to hex
        try:
            ascii_bytes = secret_input.encode('ascii', errors='strict')
            if len(ascii_bytes) <= MAX_SECRET_LENGTH:
                # Convert ASCII bytes to hex string
                hex_value = ascii_bytes.hex()
                return ('ascii', hex_value)
            else:
                print(f"ASCII input exceeds {MAX_SECRET_LENGTH} bytes")
                return None
        except UnicodeEncodeError:
            print("Invalid ASCII input")
            return None
def generate_hash(secret, salt):
    """Generate HMAC-SHA1 hash using secret and salt.
    
    Args:
        secret (bytes): Secret key used for HMAC
        salt (bytes): Salt value from KeePass database
        
    Returns:
        HMAC: Computed HMAC object or None if operation fails
        
    Notes:
        Salt is padded to SALT_LENGTH bytes if necessary
    """
    try:
        # Argon2 salt min 8 max 32 (https://keepass.info/help/kb/kdbx.html), pad to specified length
        if len(salt) != SALT_LENGTH:
            pad_length = SALT_LENGTH - len(salt)
            padding = bytes([pad_length] * pad_length)
            salt = salt + padding 
        hmac_hash = hmac.new(secret, salt, sha1)
        return hmac_hash   
    except Exception as e:
        print(f"Failed to compute hash. Error: {e}.")
        return None

if __name__ == "__main__":

    db = sys.argv[1]
    print(f"Attempting to read {db}.")
    
    salt = read_xkdb_header(db)
    if salt is None:
        print("Failed to retrieve salt from database")
        sys.exit(1)
    print(f"Salt of length {len(salt)} retrieved from header.")
    
    # Retrieve user secret used to set up YK / OK
    while True:
        result = get_secret()
        if result is None:
            print("Please provide input of 64 bytes or less.")
            continue
            
        input_type, secret = result
        print(f"Secret provided in {input_type} format.")
        
        # Convert to bytes
        try:
            secret_bytes = bytes.fromhex(secret)
            print(f"Secret converted to {len(secret_bytes)} bytes.")
            break
        except Exception as e:
            raise ValueError(f"Failed to convert secret to bytes. Error {e}.")
        
    try:
        hmac_hash = generate_hash(secret_bytes, salt)
        hash_bytes = hmac_hash.digest()
        with open(KEYFILE, 'wb') as f:
            f.write(hash_bytes)
        print(f"🔑 HMAC-SHA1 digest written to keyfile {KEYFILE}")
    except Exception as e:
        print(f"Failed to save keyfile: {e}")