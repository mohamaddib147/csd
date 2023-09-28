import sys
import interfaces_pb2
import requests
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes


class VPKIClient:
     def __init__(self, pca_url, pca_method,client_cert_path, client_key_path,validate_certificate=False,):
        self.pca_url = pca_url
        self.pca_method = pca_method
        self.client_cert_path = client_cert_path
        self.client_key_path = client_key_path
        self.validate_certificate = validate_certificate
      
     def obtain_pseudonym(self):
        try:
            # Read the client certificate and key from files
            with open(self.client_cert_path, 'rb') as cert_file:
                client_cert = cert_file.read()

            with open(self.client_key_path, 'rb') as key_file:
                client_key = key_file.read()

            # Create the pseudonym request
            pseudonym_request = interfaces_pb2.PseudonymRequest()
            pseudonym_request.client_certificate = client_cert
            signature = self.sign_request(client_cert, client_key)
            pseudonym_request.signature = signature

            # Serialize the pseudonym request to a string.
            pseudonym_request_string = pseudonym_request.SerializeToString()

            # Send the pseudonym request to the PCA server
            response = requests.post(self.pca_url, data=pseudonym_request_string, verify=self.validate_certificate)

            if response.status_code == 200:
                # Parse the response from the PCA server.
                pseudonym_response = interfaces_pb2.PseudonymResponse()
                pseudonym_response.ParseFromString(response.content)

                # Return the pseudonym certificate.
                return pseudonym_response.pseudonym_certificate
            else:
                raise Exception(f"Error: {response.status_code} - {response.text}")

        except InvalidSignature as e:
            raise Exception("Invalid signature")
        except Exception as e:
            raise Exception(f"Error: {str(e)}")

     def sign_request(self, data, private_key):
        private_key = serialization.load_pem_private_key(private_key, password=None)
        signature = private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
        return signature
# Example usage:
if __name__ == "__main__":
    pca_url = "https://nss-core.ddns.net:30931/cgi-bin/pca"
    pca_method = "pca.operate"

    # Update the client_cert_path and client_key_path variables to match the paths to your client certificate and key files.
    client_cert_path = "/home/kali/Desktop/CSD/2-vcs-vpki-main/client_cer.crt"
    client_key_path = "/home/kali/Desktop/CSD/2-vcs-vpki-main/client_key.key"

    vpkiclient = VPKIClient(pca_url, pca_method, validate_certificate=False, client_cert_path=client_cert_path, client_key_path=client_key_path)

    try:
        pseudonym = vpkiclient.obtain_pseudonym()
        print(f"Obtained pseudonym: {pseudonym}")
    except Exception as e:
        print(f"Error: {str(e)}")