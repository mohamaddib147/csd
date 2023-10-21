#this class is mainley for testing 


import base64
import ssl
import sys
import time
import logging
from xmlrpc.server import XMLRPCDocGenerator
from oscrypto import backend
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context
import xml.etree.ElementTree as ET
import json
import xmlrpc.client
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



    def obtain_ltca(self):
        LTCA_METHOD_NAME = "ltca.operate"
        try:
            # Read the CSR from the CSR file
            with open(csr_file_path, 'rb') as csr_file:
                csr_data = csr_file.read()

            # Create an LTCA request
            ltca_request = msgX509CertReq_V2LTCA()
            ltca_request.iReqType = 122
            ltca_request.iLTCAIdRange = 1002
            ltca_request.strProofOfPossessionVoucher = ""
            ltca_request.strDNSExtension = ""
            ltca_request.strKeyUsage = ""
            ltca_request.strExtendedKeyUsage = "clientAuth"
            ltca_request.strX509CertReq = csr_data  # Include the CSR data
            ltca_request.iNonce = random.randint(0, 65535)
            ltca_request.tTimeStamp = int(time.time())
            self.validate_nonce_and_timestamp(ltca_request.iNonce, ltca_request.tTimeStamp)
            print("LTCA Request Data:")
            print(ltca_request.SerializeToString())
            
            # Sign the LTCA request 
            #signature = self.sign_request(ltca_request.SerializeToString(), self.client_key_path)
           # ltca_request.stSign.signature = signature

            # Serialize the LTCA request to a string
            # Connect to the LTCA server using XML-RPC
            ltca_server = XMLRPCDocGenerator.client.ServerProxy(self.ltca_url)

            # Call the LTCA method with the certificate request
            ltca_response = ltca_server.ltca.operate(ltca_request.SerializeToString())

            # Parse the LTCA response
            ltca_cert_response = msgX509CertRes_LTCA2V()
            ltca_cert_response.ParseFromString(base64.b64decode(ltca_response))

            if ltca_cert_response.strX509Cert:
                # LTCA certificate obtained successfully
                return ltca_cert_response.strX509Cert
            else:
                raise Exception("Error: LTCA certificate not received")

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
    ltca_url = "https://nss-core.ddns.net:30930/cgi-bin/ltca"
    pca_url = "https://nss-core.ddns.net:30931/cgi-bin/pca"
    LTCA_METHOD_NAME = "ltca.operate"
    PCA_METHOD_NAME = "pca.operate"
    # Update the csr_file_path and client_key_path variables to match the paths to your client certificate and key files.
    
    client_key_path = "/home/kali/Desktop/CSD/2-vcs-vpki-main/client_key.pem"
    csr_file_path = "/home/kali/Desktop/CSD/2-vcs-vpki-main/csr123.pem"
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