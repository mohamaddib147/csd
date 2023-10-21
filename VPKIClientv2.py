import base64
import crypt
import datetime
import socket
import time
import traceback
import Cryptodome
import cryptography
from networkx import symmetric_difference
import requests
import xmlrpc.client
import random
from OpenSSL import crypto
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
import xml
import base64
import cryptography.hazmat.primitives.asymmetric.ec as ec
from sympy import SymmetricDifference, symmetric_poly
from interfaces_pb2 import msgX509CertReq_V2LTCA, msgTicketReq, msgPsnymCertReq_V2PCA,msgTicketRes
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
 
    

    

    def validate_nonce_and_timestamp(self, request_nonce, request_timestamp, response_nonce, response_timestamp):
        #Validates the nonce and timestamp for both request and response.
      
      
        if not isinstance(request_nonce, int) or not isinstance(request_timestamp, int):
            raise Exception("Invalid request nonce or timestamp type")

        if request_nonce < 0 or request_nonce > 65535:
            raise Exception("Invalid request nonce value")

        if not isinstance(response_nonce, int) or not isinstance(response_timestamp, int):
            raise Exception("Invalid response nonce or timestamp type")

        if response_nonce < 0 or response_nonce > 65535:
            raise Exception("Invalid response nonce value")

        # Check that the nonce is unique for the given timestamp.
        if request_nonce == response_nonce:
            raise Exception("Nonce in the response must be different from the request nonce")

        # Convert timestamps to datetime objects for month comparison
        request_time = datetime.fromtimestamp(request_timestamp)
        response_time = datetime.fromtimestamp(response_timestamp)

        # Compare months and timestamps
        if request_time.month != response_time.month or request_time.year != response_time.year:
            raise Exception("Request and response timestamps must be in the same month and year")

        # Check that the timestamp is within a reasonable range of the current time.
        current_time = datetime.now()
        max_time_delta = 60 * 60  # 60 minutes
        if request_time < current_time - timedelta(seconds=max_time_delta) or request_time > current_time + timedelta(seconds=max_time_delta):
            raise Exception("Invalid request timestamp value")
        if response_time < current_time - timedelta(seconds=max_time_delta) or response_time > current_time + timedelta(seconds=max_time_delta):
            raise Exception("Invalid response timestamp value")
        

    def generate_x509_req(self, x509_csr):
        x509_req = msgX509CertReq_V2LTCA()
        x509_req.iReqType = int(122)
        x509_req.iLTCAIdRange = int(1002)
        x509_req.strX509CertReq = x509_csr
        x509_req.strDNSExtension = ""
        x509_req.strProofOfPossessionVoucher = ""
        x509_req.strKeyUsage = ""
        x509_req.strExtendedKeyUsage = "clientAuth"
        x509_req.iNonce = int(random.randint(0, 65535))
        x509_req.tTimeStamp = int(time.time())

        # Serialize the x509_req message to a string
        x509_req_string = x509_req.SerializeToString()

        # Encode the request in base64
        encoded_req = base64.b64encode(x509_req_string).decode('utf-8')

        return encoded_req
    #make the key and the csr in the class 
    
    def generate_signed_csr(self):
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

        # Extract the public key
        public_key = private_key.public_key()

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Create a CSR
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u'vpki.example.com'),
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'SE'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Stockholm'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u'kista'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'kth'),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, u'mdeeb@kth.se')
        ])).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"vpki.example.com")]),
            critical=False,
        ).sign(private_key, hashes.SHA256(), default_backend())
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        return csr_pem
    


    def obtain_ltca(self):
        try:
            csr_pem = self.generate_signed_csr()   
            print(csr_pem)

            # Generate the X.509 certificate request using the provided API
            x509_cert_req = self.generate_x509_req(csr_pem)
            ltca_request = msgX509CertReq_V2LTCA()
            ltca_request.iReqType = int(122)
            ltca_request.iLTCAIdRange = int(1002)
            ltca_request.strProofOfPossessionVoucher = ""
            ltca_request.strDNSExtension = ""
            ltca_request.strKeyUsage = ""
            ltca_request.strExtendedKeyUsage = "clientAuth"
            ltca_request.strX509CertReq = csr_pem  # Include the CSR data
            ltca_request.iNonce = int(random.randint(0, 65535))
            ltca_request.tTimeStamp = int(time.time())
            ltca_request_string = ltca_request.SerializeToString()
            socket.setdefaulttimeout(10)
            
            # Connect to the LTCA server using XML-RPC
            ltca_server = xmlrpc.client.ServerProxy(self.ltca_url, allow_none=True, verbose=False, use_builtin_types=True)

            # Call the LTCA method with the certificate request
            try:
                ltca_response = ltca_server.ltca.operate(ltca_request.iReqType, base64.b64encode(ltca_request_string).decode('utf-8'))
            except Exception as e:
                print(f"Error obtaining LTCA certificate: {e}")
            socket.setdefaulttimeout(None)
            # Parse the LTCA response
            ltca_cert_response = msgX509CertRes_LTCA2V()
            ltca_cert_response.ParseFromString(base64.b64decode(ltca_response))
            print(ltca_cert_response)
            self.validate_nonce_and_timestamp(
            ltca_request.iNonce,
            ltca_request.tTimeStamp,
            ltca_cert_response.iNonce,
            ltca_cert_response.tTimeStamp
            )
            print(ltca_cert_response.strX509Cert)
            if ltca_cert_response.strX509Cert:
                # LTCA certificate obtained successfully
                return ltca_cert_response.strX509Cert
            else:
                raise Exception("Error: LTCA certificate not received")

        except Exception as e:
            raise Exception(f"Error obtaining LTCA certificate: {str(e)}")




    



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
           
            # Serialize the ticket request to a string
            ticket_request_string = ticket_request.SerializeToString()

            # Connect to the LTCA server using XML-RPC
            ltca_server = xmlrpc.client.ServerProxy(self.ltca_url, allow_none=True, verbose=False, use_builtin_types=True)
        
            # Send the ticket request to the LTCA server using the `ltca.operate` method
            ticket_response_string = ltca_server.ltca.operate(ticket_request.iReqType, base64.b64encode(ticket_request_string).decode('utf-8'))
            
            # Deserialize the ticket response from a string
            ticket_response = msgTicketRes()
            ticket_response.ParseFromString(base64.b64decode(ticket_response_string))

            # Validate the nonce and timestamp
            self.validate_nonce_and_timestamp(
            ticket_request.iNonce,
            ticket_request.tTimeStamp,
            ticket_response.iNonce,
            ticket_response.tTimeStamp
            )
            
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
    ltca_url = "http://nsscore.ict.kth.se:30930/cgi-bin/ltca"
    pca_url = "http://nss-core.ddns.net:30931/cgi-bin/pca"

    # Update the csr_file_path and client_key_path variables to match the paths to your client certificate and key files.
    
    client_key_path = "/home/kali/Desktop/CSD/2-vcs-vpki-main/ecdsa_private_key.pem"
    csr_file_path = "/home/kali/Desktop/CSD/2-vcs-vpki-main/ecdsa_csr.pem"
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