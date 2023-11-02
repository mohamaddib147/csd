import base64
import datetime
import time
import xmlrpc.client
import random
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
import base64
import cryptography.hazmat.primitives.asymmetric.ec as ec
from interfaces_pb2 import msgX509CertReq_V2LTCA, msgTicketReq,msgToBeSignedCSR, msgPsnymCertReq_V2PCA, msgTicketRes,msgPsnymCertRes_PCA2V,msgWAVECertificateRequest  
from interfaces_pb2 import msgX509CertRes_LTCA2V,msgSubType,msgRequestScopeType,msgECPublicKey,msgSignature,msgSignerInfo,msgSignerIdentifierType


class VPKIClient:
    LTCA_METHOD_NAME = "ltca.operate"
    PCA_METHOD_NAME = "pca.operate"

    def __init__(self, ltca_url, pca_url, csr_file_path, client_key_path, validate_certificate=False):
        self.ltca_url = ltca_url
        self.pca_url = pca_url
        self.csr_file_path = csr_file_path
        self.client_key_path = client_key_path
        self.validate_certificate = validate_certificate

    

    def validate_nonce_and_timestamp(self, request_nonce, request_timestamp, response_nonce, response_timestamp):
        # Validates the nonce and timestamp for both request and response.

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
        if request_time < current_time - timedelta(seconds=max_time_delta) or request_time > current_time + timedelta(
                seconds=max_time_delta):
            raise Exception("Invalid request timestamp value")
        if response_time < current_time - timedelta(seconds=max_time_delta) or response_time > current_time + timedelta(
                seconds=max_time_delta):
            raise Exception("Invalid response timestamp value")


    # make the key and the csr in the class

    def generate_signed_csr(self):
        # Generate a private key
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

        # Extract the public key
        public_key = private_key.public_key()

        # Create a dictionary to store the key, CSR, and public key
        key_info = {
            'private_key': private_key,
            'public_key': public_key,
            'csr': None,  # Placeholder for the CSR
            'csr_pem': None,  # Placeholder for the CSR in PEM format
        }

        # Define CSR subject attributes
        csr_subject = [
            x509.NameAttribute(NameOID.COMMON_NAME, u'vpki.example.com'),
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'SE'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Stockholm'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u'kista'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'kth'),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, u'mdeeb@kth.se')
        ]

        # Create a CSR
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(csr_subject)).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"vpki.example.com")]),
            critical=False,
        ).sign(private_key, hashes.SHA256(), default_backend())

        # Store the CSR and CSR in PEM format in the dictionary
        key_info['csr'] = csr
        key_info['csr_pem'] = csr.public_bytes(serialization.Encoding.PEM)

        # save the private key to a file 
        with open('private_key.pem', 'wb') as private_key_file:
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            private_key_file.write(private_key_pem)

        public_key_path = "public_key.pem"
        with open(public_key_path, 'wb') as public_key_file:
            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            public_key_file.write(public_key_bytes)

        # Return the key information
        return key_info

    def obtain_ltca(self):
        try:
            key_info = self.generate_signed_csr()  # Generate key info

            # Access the key, CSR, and public key from the dictionary
            private_key = key_info['private_key']
            public_key = key_info['public_key']
            csr = key_info['csr']
            csr_pem = key_info['csr_pem']

            
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
            # socket.setdefaulttimeout(10)

            # Connect to the LTCA server using XML-RPC
            ltca_server = xmlrpc.client.ServerProxy(self.ltca_url, allow_none=True, verbose=False,
                                                    use_builtin_types=True)

            # Call the LTCA method with the certificate request
            try:
                # ltca_response = ""
                ltca_response = ltca_server.ltca.operate(ltca_request.iReqType,
                                                         base64.b64encode(ltca_request_string).decode('utf-8'))
            except Exception as e:
                print(f"Error obtaining LTCA certificate: {e}")
            # socket.setdefaulttimeout(None)
            # Parse the LTCA response
            ltca_cert_response = msgX509CertRes_LTCA2V()
            ltca_cert_response.ParseFromString(base64.b64decode(ltca_response))

            self.validate_nonce_and_timestamp(
                ltca_request.iNonce,
                ltca_request.tTimeStamp,
                ltca_cert_response.iNonce,
                ltca_cert_response.tTimeStamp
            )
            #print(ltca_cert_response.strX509Cert)
            if ltca_cert_response.strX509Cert:
                # LTCA certificate obtained successfully
                return ltca_cert_response
            else:
                raise Exception("Error: LTCA certificate not received")

        except Exception as e:
            raise Exception(f"Error obtaining LTCA certificate: {str(e)}")

    def obtain_ticket(self, ltca_response):
        try:
            # Create a ticket request
            ticket_request = msgTicketReq()
            ticket_request.iReqType = 126
            ticket_request.uiServices = 0
            ticket_request.iLTCAIdRange = 1002
            ticket_request.iPCAIdRange = 1001
            ticket_request.iNonce = random.randint(0, 65535)
            ticket_request.tTimeStamp = int(time.time())
            ticket_request.strX509Cert = ltca_response.strX509Cert
            ticket_request.uiPsnymCertNoRequest = 1  # Request one pseudonym certificate
            ticket_request.tPsnymStartTime = int(time.time())  # Set the pseudonym start time to the current system time
            ticket_request.tPsnymEndTime = int(
                time.time()) + 60 * 60  # Set the pseudonym end time to one hour from the current system time
            ticket_request.stSign.CopyFrom(ltca_response.stSign)
            ticket_request.stSigner.CopyFrom(ltca_response.stSigner)

            # Serialize the ticket request to a string
            ticket_request_string = ticket_request.SerializeToString()

            # Connect to the LTCA server using XML-RPC
            ltca_server = xmlrpc.client.ServerProxy(self.ltca_url, allow_none=True, verbose=False,
                                                    use_builtin_types=True)

            # Send the ticket request to the LTCA server using the `ltca.operate` method
            ticket_response_string = ltca_server.ltca.operate(ticket_request.iReqType,
                                                              base64.b64encode(ticket_request_string).decode('utf-8'))

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

            return ticket_response

        except Exception as e:
            raise Exception(f"Error: {str(e)}")

   
    def obtain_pseudonym(self, ticket):
        try:
           # Generate a new key pair for the pseudonym request
            private_key = ec.generate_private_key(ec.SECP256R1())
            public_key = private_key.public_key()

            # Create a pseudonym request
            pseudonym_request = msgPsnymCertReq_V2PCA()
            pseudonym_request.iReqType = 220
            pseudonym_request.iTicketSize = len(ticket.strTicket)  # Use the length of the ticket
            pseudonym_request.strTicket = ticket.strTicket
            pseudonym_request.iLTCAIdRange = 1002
            pseudonym_request.iPCAIdRange = 1001
            pseudonym_request.uiPsnymCertNo = 1
            pseudonym_request.iLocation = 6  # Adjust the location as needed
            pseudonym_request.iNonce = random.randint(0, 65535)  # Generate a random nonce
            pseudonym_request.tTimeStamp = int(time.time())  # Set to the current system time

            
            # Create an EC public key message using the public key
            ec_public_key = msgECPublicKey()
            public_key_data = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            ec_public_key.uiPsnymPublicKeyLen = len(public_key_data)
            ec_public_key.strPsnymPublicKey = public_key_data

            # Create a ToBeSignedCSR message with the EC public key
            csr = msgToBeSignedCSR()
            csr.csrVersion = 0  # Update with the appropriate value
            csr.subjectType = msgSubType.wsa_ca1  # Set subjectType to the appropriate enum value
            csr.requestType = msgRequestScopeType.specifiedInRequest  # Set requestType to the appropriate enum value
            csr.stECPsnymPublicKey.CopyFrom(ec_public_key)

            # Create a WAVECertificateRequest message
            wave_cert_request = msgWAVECertificateRequest()
            wave_cert_request.unsignedCsr.CopyFrom(csr)  # Assign the ToBeSignedCSR to unsignedCsr
            hash_algorithm = hashes.SHA256()

          
            csr_bytes = csr.SerializeToString()

            # Sign the CSR with the private key 
            signature = private_key.sign(
                csr_bytes,
                ec.ECDSA(hash_algorithm)
            )
            signature_str = base64.b64encode(signature).decode('utf-8')
            

            # Create a msgSignerInfo object for the public key
            signer_info = msgSignerInfo()
            #signer_info.type = msgSignerIdentifierType.SignerIdentifierType.self
           # signer_info.strCertificate = public_key_data
            signer_info.type = msgSignerIdentifierType.SignerIdentifierType.self
            signer_info.strCertificate = public_key_data  
            signer_info.strDigest = public_key_data  
            signer_info.strCertificatesChain = public_key_data
            # Assign the signer_info object to public_key_data.stSigner
            wave_cert_request.stSigner.CopyFrom(signer_info)

             # Create a msgSignature object
            signature = msgSignature()
            signature.strSignature = signature_str
            signature.uiSignLen = len(signature_str)
            #wave_cert_request.stSign.strSignature = signature_str
            # Assign the signature to wave_cert_request.stSign
            wave_cert_request.stSign.CopyFrom(signature)
            
            # Add the wave_cert_request to the pseudonym request
            pseudonym_request.pstPsnymCertReq.add().CopyFrom(wave_cert_request)


            # Serialize the pseudonym request to a string
            pseudonym_request_string = pseudonym_request.SerializeToString()

            # Send the pseudonym request to the PCA server
            pca_server = xmlrpc.client.ServerProxy(self.pca_url, allow_none=True)
            pseudonym_response_string = pca_server.pca.operate(pseudonym_request.iReqType, base64.b64encode(pseudonym_request_string).decode('utf-8'))

            # Parse the pseudonym response
            pseudonym_response = msgPsnymCertRes_PCA2V()
            pseudonym_response.ParseFromString(base64.b64decode(pseudonym_response_string))
            print(pseudonym_response)

            # Validate the nonce and timestamp
            self.validate_nonce_and_timestamp(
                pseudonym_request.iNonce,
                pseudonym_request.tTimeStamp,
                pseudonym_response.iNonce,
                pseudonym_response.tTimeStamp
            )

            # Return the pseudonym certificate
            pseudonym_certificate = pseudonym_response.stPsnymCert

            return pseudonym_certificate

        except Exception as e:
            print(f"Error obtaining pseudonym certificate: {str(e)}")
            return None




if __name__ == "__main__":
    ltca_url = "http://nsscore.ict.kth.se:30930/cgi-bin/ltca"
    pca_url = "http://nsscore.ict.kth.se:30931/cgi-bin/pca"

    # Update the csr_file_path and client_key_path variables to match the paths to your client certificate and key files.

    client_key_path = "ecdsa_private_key.pem"
    csr_file_path = "ecdsa_csr.pem"
    vpkiclient = VPKIClient(ltca_url, pca_url, csr_file_path, client_key_path, validate_certificate=False)

    try:
        ltca_certificate = vpkiclient.obtain_ltca()
        print(f"Obtained LTCA Certificate: {ltca_certificate}")
        ticket = vpkiclient.obtain_ticket(ltca_certificate)
        print(f"Obtained Ticket: {ticket}")
        pseudonym_certificate = vpkiclient.obtain_pseudonym(ticket)
        print(f"Obtained Pseudonym Certificate: {pseudonym_certificate}")        
    except Exception as e:
        print(f"Error: {str(e)}")
