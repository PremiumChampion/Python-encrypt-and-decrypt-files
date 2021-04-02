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


def rreplace(s, old, new, count):
    return (s[::-1].replace(old[::-1], new[::-1], count))[::-1]


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
path_to_decrypt = get_commandline_arguments("--path")


if certificate_filename is None:
    certificate_filename = input("Please enter the path of the .pfx certificate file: ")

if password is None:
    password = input("Certificate password: ")

if path_to_decrypt is None:
    path_to_decrypt = input("Please specify directory/file to decrypt (Leave blank for the current directory): ")

if path_to_decrypt == "":
    path_to_decrypt = "."

try:

    certificate = dump_pfx_certificate(certificate_filename, password)


    def decrypt_file(path):
        try:
            print("Decrypting file: " + str(path))
            with open(str(path) + ".key", "rb") as encryption_key_file:
                decryption_key = certificate.get("private_key").decrypt(
                    encryption_key_file.read(),
                    padding.OAEP(
                        padding.MGF1(algorithm=hashes.SHA512()),
                        algorithm=hashes.SHA512(),
                        label=None
                    )
                )

            with open(path, "rb") as encrypted_file:
                decrypted = Fernet(decryption_key).decrypt(encrypted_file.read())

            os.remove(path)
            os.remove(str(path) + ".key")

            with open(rreplace(str(path), ".crypt", "", 1), "wb") as decrypted_file:
                decrypted_file.write(decrypted)
        except PermissionError:
            pass


    if os.path.isdir(path_to_decrypt):
        for file in Path(path_to_decrypt).rglob("*.[cC][rR][yY][pP][tT]"):
            decrypt_file(file)

    if os.path.isfile(path_to_decrypt):
        decrypt_file(path_to_decrypt)


except Exception:
    print("Something went wrong")
    raise Exception
