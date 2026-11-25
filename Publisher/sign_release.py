from pathlib import Path

import sys
import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

# Personalized seed to generate keypair
SEED = f"ITIS-3200-Seed-{12 % 10}"

# Performs SHA-256 function on the seed to get exactly 32 bytes for the private key
digest = hashlib.sha256(SEED.encode()).digest()

# Accesses the Keys folder
KEYS_DIRECTORY = Path(__file__).resolve().parent.parent / "Keys"

# Path to the file where the public and private keys are to be stored (respectively)
PRIVATE_KEY_PATH = KEYS_DIRECTORY / "private_key.pem"
PUBLIC_KEY_PATH = KEYS_DIRECTORY / "public_key.pem"

def keygen():
    if PRIVATE_KEY_PATH.exists():
        print(f"Private key already exists! Unable to overwrite the existing key: {PRIVATE_KEY_PATH}")
        sys.exit(1)
    
    # Creates a "Keys" folder if one doesn't already exist
    KEYS_DIRECTORY.mkdir(exist_ok=True)

    # Generates the private key using hashed seed
    private_key = Ed25519PrivateKey.from_private_bytes(digest)

    # Creates corresponding public key for private_key
    public_key = private_key.public_key()

    # Serializes keys into bytes using Standard PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Stores the serialized key bytes to their respective files
    PRIVATE_KEY_PATH.write_bytes(private_pem)
    PUBLIC_KEY_PATH.write_bytes(public_pem)

    print(f"Private key is written to {PRIVATE_KEY_PATH}. THIS FILE IS TO BE KEPT SECRET!")
    print(f"Public key is written to {PUBLIC_KEY_PATH}. THIS FILE IS SAFE TO COMMIT!")

def sign(file_path):

    # Creates a Path object of the argument (passed as a string)
    file = Path(file_path)

    # Checks to see if the path points to an actual file
    if not file.is_file():
        print(f"Path: {file} is not a valid file path!")
        sys.exit(1)

    if not PRIVATE_KEY_PATH.is_file():
        print("No private key has been found. Key must be generated to proceed")
        sys.exit(1)

    # Reads the private key from its designated file
    private_key = serialization.load_pem_private_key(PRIVATE_KEY_PATH.read_bytes(), password=None)

    # Reads the file as bytes and signs it
    signature = private_key.sign(file.read_bytes())

    # Extracts the file's name (with extension) and adds the ".sig" extension, creating a new file path for the signature
    signature_path = file.with_name(file.name + ".sig")

    # Writes the signature into its newly created file path
    signature_path.write_bytes(signature)

    print(f"File signed {file} successfully to {signature_path}!")
    
def main():
    # Reads the command or argument typed in the terminal and calls the corresponding function
    if len(sys.argv) < 2:
        print("*** FILE RAN WITHOUT COMMAND-LINE ARGUMENTS ***")
        print("MUST TYPE EITHER: python Publisher/sign_release.py keygen OR python Publisher/sign_release.py sign [some_file]")
        sys.exit(1)
    elif sys.argv[1] == "keygen":
        keygen()
    elif len(sys.argv) == 3 and sys.argv[1] == "sign":
        sign(sys.argv[2]) 
    else:
        print("UNKNOWN COMMAND")
        print("MUST TYPE EITHER: python Publisher/sign_release.py keygen OR python Publisher/sign_release.py sign [some_file]")
        sys.exit(1)

if __name__ == "__main__":
    main()