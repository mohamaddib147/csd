import sys
import time
import interfaces_pb2
import requests
import json
from cryptography.hazmat.primitives import serialization, padding, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from interfaces_pb2 import msgPsnymCertReq_V2PCA 






class VPKIClient:
     def __init__(self, pca_url,client_cert_path, client_key_path,validate_certificate=False,):
        self.pca_url = pca_url
        self.client_cert_path = client_cert_path
        self.client_key_path = client_key_path
        self.validate_certificate = validate_certificate
      
     def obtain_pseudonym(self):
        try:
            # Read the client certificate and key from files
            with open(self.client_cert_path, 'rb') as csr_file:
                client_cert = csr_file.read()

            with open(self.client_key_path, 'rb') as key_file:
                client_key = key_file.read()
           
            
            
            # Create the pseudonym request
            pseudonym_request = msgPsnymCertReq_V2PCA()
            pseudonym_request.iReqType = -1  
            pseudonym_request.uiPsnymCertNo = 0  
            pseudonym_request.strTicket = "" 
            pseudonym_request.iLTCAIdRange = -1  
            pseudonym_request.iPCAIdRange = -1  
            pseudonym_request.iLocation = -1  
            pseudonym_request.iTicketSize = 0 
            pseudonym_request.iNonce = 0  
            pseudonym_request.tTimeStamp = int(time.time())  
            
             # Create an empty PsnymCertRequest message
            psnym_cert_req = pseudonym_request.pstPsnymCertReq.add()

            # Use the builder method to set the unsignedCsr field (replace 'your_unsigned_csr_data' with actual CSR data)
            psnym_cert_req.client_cert = client_cert

            # Sign the request
            signature = self.sign_request(pseudonym_request.SerializeToString(), client_key)
            pseudonym_request.stSign.signature = signature
          
            # Serialize the pseudonym request to a string.
            pseudonym_request_string = pseudonym_request.SerializeToString()


            # Send the pseudonym request to the PCA server
            response = requests.post(self.pca_url, data=pseudonym_request_string, verify=self.validate_certificate)

            if response.status_code == 200:
                # Parse the response from the PCA server.
                pseudonym_response = interfaces_pb2.msgPsnymCertRes_PCA2V()
                pseudonym_response.ParseFromString(response.content)

                # Return  pseudonym certificate.
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
    client_cert_path = "/home/kali/Desktop/CSD/2-vcs-vpki-main/client_csr.pem"
    client_key_path = "/home/kali/Desktop/CSD/2-vcs-vpki-main/client_private_key.key"

    vpkiclient = VPKIClient(pca_url, client_cert_path, client_key_path, validate_certificate=False)


    try:
        pseudonym = vpkiclient.obtain_pseudonym()
        print(f"Obtained pseudonym: {pseudonym}")
    except Exception as e:
        print(f"Error: {str(e)}")
