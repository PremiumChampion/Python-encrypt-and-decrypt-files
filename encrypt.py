import os
import sys
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from pathlib import Path
from cryptography.fernet import Fernet


def get_commandline_arguments(argument: str):
    for i, arg in enumerate(sys.argv):
        if arg == argument:
            if len(sys.argv) > i + 1:
                return sys.argv[i + 1]
    return None


def dump_pfx_certificate(pfx_path: str, pfx_password: str):
    try:
        pfx = open(pfx_path, 'rb').read()

        private_key, _certificate, additional_certificates = pkcs12.load_key_and_certificates(pfx, pfx_password.encode(
            "utf-8"))

        return {"private_key": private_key, "public_key": _certificate.public_key()}
    except Exception:
        raise Exception


certificate_filename = get_commandline_arguments("--cert")
password = get_commandline_arguments("--cert-passwd")
path_to_encrypt = get_commandline_arguments("--path")

if certificate_filename is None:
    certificate_filename = input("Please enter the path of the .pfx certificate file: ")

if password is None:
    password = input("Certificate password: ")

if path_to_encrypt is None:
    path_to_encrypt = input("Please specify directory/file to encrypt (Leave blank for the current directory): ")

if path_to_encrypt == "":
    path_to_encrypt = "."

try:
    certificate = dump_pfx_certificate(certificate_filename, password)


    def encrypt_file(path: str):
        if os.path.samefile(certificate_filename, path):
            print("Skipping certificate file: " + path)
        else:
            try:
                print("Encrypting file: " + path)
                file_key = Fernet.generate_key()

                with open(path, "rb") as file_to_encrypt:
                    encrypted = Fernet(file_key).encrypt(file_to_encrypt.read())

                encrypted_key = certificate["public_key"].encrypt(
                    file_key,
                    padding.OAEP(
                        padding.MGF1(algorithm=hashes.SHA512()),
                        algorithm=hashes.SHA512(),
                        label=None
                    )
                )

                with open(path, "wb") as encrypted_file:
                    encrypted_file.write(encrypted)

                os.replace(path, path + ".crypt")

                with open(path + ".crypt.key", "wb") as encrypted_file_key:
                    encrypted_file_key.write(encrypted_key)
            except PermissionError:
                pass


    if os.path.isdir(path_to_encrypt):
        for file_path in Path(path_to_encrypt).rglob("*.*"):
            encrypt_file(str(file_path.resolve()))

    if os.path.isfile(path_to_encrypt):
        encrypt_file(path_to_encrypt)

except Exception:
    print("Something went wrong")
    raise Exception
