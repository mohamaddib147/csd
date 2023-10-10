import base64
import ssl
import sys
import time
from oscrypto import backend
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context
import xml.etree.ElementTree as ET
import json
import random
from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
import xml
from interfaces_pb2 import msgX509CertReq_V2LTCA, msgTicketReq, msgPsnymCertReq_V2PCA
from interfaces_pb2 import msgX509CertRes_LTCA2V

class VPKIClient:

    LTCA_METHOD_NAME = "ltca.operate"
    PCA_METHOD_NAME = "pca.operate"
    def __init__(self, ltca_url, pca_url, csr_file_path, client_key_path, validate_certificate=False):
        self.ltca_url = ltca_url
        self.pca_url = pca_url
        self.csr_file_path = csr_file_path
        self.client_key_path = client_key_path
        self.validate_certificate = validate_certificate

    def sign_request(self, data, private_key_path):
        with open(private_key_path, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None)
        signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        return signature
   
    def send_request(self, url, data, method_name):
            headers = {
                "Content-Type": "text/xml"if xml else "application/octet-stream" ,
                "METHOD_NAME": method_name,
            }
            response = requests.post(url, data=data, headers=headers, verify=self.validate_certificate)

            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', '')
                if 'application/json' in content_type:
                    return response.json()  # Parse JSON response
                else:
                    return response.text  # Return plain text response
            else:
                raise Exception(f"Error: {response.status_code} - {response.text}")


    


    def validate_nonce_and_timestamp(self, nonce, timestamp):
        """Validates the nonce and timestamp.
        Args:
            nonce: The nonce.
            timestamp: The timestamp.
        Raises:
            Exception: If the nonce or timestamp is invalid.
        """

        if not isinstance(nonce, int) or not isinstance(timestamp, int):
            raise Exception("Invalid nonce or timestamp type")

        if nonce < 0 or nonce > 65535:
            raise Exception("Invalid nonce value")

        # Check that the nonce is unique for the given timestamp.

        # Check that the timestamp is within a reasonable range of the current time.

        current_time = int(time.time())
        max_time_delta = 60 * 60  # 60 minutes

        if timestamp < current_time - max_time_delta or timestamp > current_time + max_time_delta:
            raise Exception("Invalid timestamp value")
    def __generate_x509_req(self, x509_csr):
        x509_req = msgX509CertReq_V2LTCA()
        x509_req.iReqType = 122
        x509_req.iLTCAIdRange = 1002
        x509_req.strProofOfPossessionVoucher = ""
        x509_req.strX509CertReq = x509_csr
        x509_req.iNonce = random.randint(0, 65535)
        x509_req.tTimeStamp = int(time.time())
        x509_req.strDNSExtension = ""

        serialized_to_string = x509_req.SerializeToString()
        encoded_req = base64.b64encode(serialized_to_string)
        return encoded_req.decode('UTF-8')



    def obtain_ltca(self):
        try:
            # Read the CSR from the CSR file
            with open(self.csr_file_path, 'rb') as csr_file:
                csr_data = csr_file.read()
            csr_base64 = base64.b64encode(csr_data).decode('utf-8')
            # Generate the X.509 certificate request using the provided API
            x509_cert_req = self.__generate_x509_req(csr_base64)

            ltca_request = msgX509CertReq_V2LTCA()
            ltca_request.iReqType = 122
            ltca_request.iLTCAIdRange = 1002
            ltca_request.strProofOfPossessionVoucher = ""
            ltca_request.strDNSExtension = ""
            ltca_request.strKeyUsage = ""
            ltca_request.strExtendedKeyUsage = "clientAuth"
            ltca_request.strX509CertReq = x509_cert_req  # Include the CSR data
            ltca_request.iNonce = random.randint(0, 65535)
            ltca_request.tTimeStamp = int(time.time())
            ltca_request_bytes = ltca_request.SerializeToString()
           # self.validate_nonce_and_timestamp(int(x509_cert_req["iNonce"]), int(x509_cert_req["tTimeStamp"]))

            

          
            # Send the LTCA request to the server
            ltca_response_bytes = self.send_request(self.ltca_url, ltca_request_bytes, self.LTCA_METHOD_NAME)
           
            # Ensure that ltca_response_bytes is a bytes-like object
            if isinstance(ltca_response_bytes, str):
                ltca_response_bytes = ltca_response_bytes.encode('utf-8')

            # Deserialize the received bytes into a protobuf message 
            ltca_response_message = msgX509CertRes_LTCA2V()
            #ltca_response_message= base64.b64decode(ltca_response_message)

            try:
                ltca_response_message.ParseFromString(ltca_response_message)
                
                # Extract the LTCA certificate from the protobuf message
                ltca_certificate = ltca_response_message.strX509Cert
                print("Obtained LTCA Certificate:", ltca_certificate)
                return ltca_certificate
            except Exception as e:
                print("Error parsing LTCA response:", str(e))
                # Print the raw response data for debugging purposes
                print("Raw response data:", ltca_response_bytes)
                raise e


        except InvalidSignature as e:
            raise Exception("Invalid signature")
        except Exception as e:
            raise Exception(f"Error: {str(e)}")


    def obtain_ticket(self, ltca_certificate):
        try:
            # Create a ticket request
            ticket_request = msgTicketReq()
            ticket_request.iReqType = 126  
            ticket_request.uiServices = 123  
            ticket_request.iLTCAIdRange = 1002
            ticket_request.iPCAIdRange = -1  
            ticket_request.iNonce = random.randint(0, 65535)  
            ticket_request.tTimeStamp = int(time.time())  
            ticket_request.strX509Cert = ltca_certificate   
            ticket_request.uiPsnymCertNoRequest = 1  # Request one pseudonym certificate
            ticket_request.tPsnymStartTime = int(time.time())  # Set the pseudonym start time to the current system time
            ticket_request.tPsnymEndTime = int(time.time()) + 60 * 60  # Set the pseudonym end time to one hour from the current system time 
            self.validate_nonce_and_timestamp(ticket_request.iNonce, ticket_request.tTimeStamp)
            # Serialize the ticket request to a string
            ticket_request_string = ticket_request.SerializeToString()

            # Send the ticket request to the LTCA server
            ticket_response = msgTicketReq()
            ticket_response.ParseFromString(self.send_request(self.ltca_url, ticket_request_string, self.LTCA_METHOD_NAME))
            # Handle the response from the LTCA server
            ticket = ticket_response.strTicket  # Extract the ticket

            return ticket

        except Exception as e:
            raise Exception(f"Error: {str(e)}")

    def obtain_pseudonym(self, ticket):
        try:
            # Create a pseudonym request
            pseudonym_request = msgPsnymCertReq_V2PCA()
            pseudonym_request.iReqType = 220  
            pseudonym_request.iTicketSize = len(ticket)  
            pseudonym_request.strTicket = ticket  
            pseudonym_request.iLTCAIdRange = 1002
            pseudonym_request.iPCAIdRange = -1  
            pseudonym_request.uiPsnymCertNo = 0  
            pseudonym_request.iNonce = random.randint(0, 65535)  # Generate a random nonce
            pseudonym_request.tTimeStamp = int(time.time())  # Set to the current system time
            self.validate_nonce_and_timestamp(pseudonym_request.iNonce, pseudonym_request.tTimeStamp)
            # Serialize the pseudonym request to a string
            pseudonym_request_string = pseudonym_request.SerializeToString()

            # Send the pseudonym request to the PCA server
            pseudonym_response = msgPsnymCertReq_V2PCA()
            pseudonym_response.ParseFromString(self.send_request(self.pca_url, pseudonym_request_string,self.PCA_METHOD_NAME))

            # Handle the response from the PCA server
            pseudonym_certificate = pseudonym_response.stPsnymCert  # Extract the pseudonym certificate

            return pseudonym_certificate

        except Exception as e:
            raise Exception(f"Error: {str(e)}")
 
    
if __name__ == "__main__":
    ltca_url = "http://nss-core.ddns.net:30930/cgi-bin/ltca"
    pca_url = "http://nss-core.ddns.net:30931/cgi-bin/pca"

    # Update the csr_file_path and client_key_path variables to match the paths to your client certificate and key files.
    
    client_key_path = "/home/kali/Desktop/CSD/2-vcs-vpki-main/client_key.pem"
    csr_file_path = "/home/kali/Desktop/CSD/2-vcs-vpki-main/client_csr.pem"
    vpkiclient = VPKIClient(ltca_url, pca_url, csr_file_path, client_key_path, validate_certificate=False)

    try:
        ltca_certificate = vpkiclient.obtain_ltca()
        ticket = vpkiclient.obtain_ticket(ltca_certificate)
        pseudonym_certificate = vpkiclient.obtain_pseudonym(ticket)

        print(f"Obtained LTCA Certificate: {ltca_certificate}")
        print(f"Obtained Ticket: {ticket}")
        print(f"Obtained Pseudonym Certificate: {pseudonym_certificate}")
    except Exception as e:
        print(f"Error: {str(e)}")
