from pathlib import Path
import sys
import urllib.request

from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

# Path to the trusted publisher public key
KEYS_DIRECTORY = Path(__file__).resolve().parent.parent / "Keys"
PUBLIC_KEY_PATH = KEYS_DIRECTORY / "public_key.pem"


# Downloads a file from the server
def download_file(url, file_path):
    try:
        urllib.request.urlretrieve(url, file_path)
    except OSError:
        print("Update rejected: Download failed.")
        sys.exit(1)


# Downloads the update and its signature
def download_update(url, file_path):
    download_file(url, file_path)
    download_file(url + ".sig", file_path + ".sig")


def verify(file_path):
    # Gets the update file and its signature file
    file = Path(file_path)
    signature_path = file.with_name(file.name + ".sig")

    # Checks if the update file exists
    if not file.is_file():
        print("Update rejected: File not found.")
        sys.exit(1)

    # Checks if the signature file exists
    if not signature_path.is_file():
        print("Update rejected: Signature not found.")
        sys.exit(1)

    # Checks if the trusted public key exists
    if not PUBLIC_KEY_PATH.is_file():
        print("Update rejected: Public key not found.")
        sys.exit(1)

    # Loads the trusted publisher public key
    public_key = serialization.load_pem_public_key(
        PUBLIC_KEY_PATH.read_bytes()
    )

    # Reads the update and its signature
    update = file.read_bytes()
    signature = signature_path.read_bytes()

    # Verifies the digital signature
    try:
        public_key.verify(signature, update)
        print("Signature verified successfully.")
        return update
    except InvalidSignature:
        print("Update rejected: Invalid signature.")
        sys.exit(1)


def main():
    # Checks if the user provided an update file
    if len(sys.argv) != 2:
        print("Usage: python Updater/secure_updater.py [file]")
        sys.exit(1)

    # Gets the update file or URL
    file = sys.argv[1]

    # Downloads the update if a URL is provided
    if file.startswith("http://") or file.startswith("https://"):
        download_update(file, "downloaded_update.py")
        file = "downloaded_update.py"

    # Verifies the update file
    update = verify(file)

    # Executes verified local updates
    if not sys.argv[1].startswith(("http://", "https://")):
        print("Executing verified update...")
        exec(update)


if __name__ == "__main__":
    main()
