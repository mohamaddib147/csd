import argparse
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
import cryptography.hazmat.primitives.asymmetric.ec as ec
from interfaces_pb2 import (
    msgX509CertReq_V2LTCA, msgTicketReq, msgToBeSignedCSR, msgPsnymCertReq_V2PCA,
    msgTicketRes, msgPsnymCertRes_PCA2V, msgWAVECertificateRequest
)
from interfaces_pb2 import (
    msgX509CertRes_LTCA2V, msgSubType, msgRequestScopeType, msgECPublicKey,
    msgSignature, msgSignerInfo, msgSignerIdentifierType
)



class VPKIClient:
    LTCA_METHOD_NAME = "ltca.operate"
    PCA_METHOD_NAME = "pca.operate"

    def __init__(self, ltca_url, pca_url, csr_file_path, client_key_path,mail, validate_certificate=False):
        """
        Initialize the VPKIClient.

        Args:
            ltca_url (str): URL of the LTCA server.
            pca_url (str): URL of the PCA server.
            csr_file_path (str): Path to save the CSR file.
            client_key_path (str): Path to save the client private key file.
            mail (str): Email address of the OBU (On-Board Unit).
            validate_certificate (bool): Whether to validate certificates (default is False).
        """
        self.ltca_url = ltca_url
        self.pca_url = pca_url
        self.csr_file_path = csr_file_path
        self.client_key_path = client_key_path
        self.validate_certificate = validate_certificate
        self.mail = mail

    

    def validate_nonce_and_timestamp(self, request_nonce, request_timestamp, response_nonce, response_timestamp):
        """
        Validates the nonce and timestamp for both request and response.

        Args:
            request_nonce (int): Nonce in the request.
            request_timestamp (int): Timestamp in the request.
            response_nonce (int): Nonce in the response.
            response_timestamp (int): Timestamp in the response.

        Raises:
            Exception: If validation fails.
        """
        

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


  

    def generate_signed_csr(self):
        """
          Generate a signed Certificate Signing Request (CSR) and associated key pair.

        This method creates a private key, a public key, and a CSR based on predefined
        subject attributes. The CSR is signed with the private key, and both the private
        and public keys are saved to files.

        Returns:
            dict: A dictionary containing the generated private key, public key, CSR, and
            CSR in PEM format.
                """
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
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, self.mail)
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
        """
        Obtain an LTCA (Long-Term Credential Activation) certificate from a remote server.
        This method sends a request for an LTCA certificate to an LTCA server using XML-RPC,
        receives and parses the response, and validates nonces and timestamps for integrity.

        Returns:
            msgX509CertRes_LTCA2V: An LTCA certificate response message.
        """
         
        try:
            key_info = self.generate_signed_csr()  # Generate key info
            # Access the key, CSR, and public key from the dictionary
            private_key = key_info['private_key']
            public_key = key_info['public_key']
            csr = key_info['csr']
            csr_pem = key_info['csr_pem']
           
            # Create a new LTCA request object.
            ltca_request = msgX509CertReq_V2LTCA()
            # **iReqType:** This field represents the request type. It is an integer value that specifies the type of certificate request being made. In this case, we are setting it to 122, which indicates that this is a request for a LTCA certificate.
            ltca_request.iReqType = int(122)
            # **iLTCAIdRange:** This field specifies the range of LTCA IDs that the client is willing to be assigned. In this case, we are setting it to 1002-1023.
            ltca_request.iLTCAIdRange = int(1002)
            # **strProofOfPossessionVoucher:** This field is used to provide proof of possession of the private key associated with the CSR. It is not required for LTCA requests, so we are leaving it empty.
            ltca_request.strProofOfPossessionVoucher = ""
            # **strDNSExtension:** This field is used to specify the DNS extensions that the client would like to be included in the certificate. It is not required for LTCA requests, so we are leaving it empty.
            ltca_request.strDNSExtension = ""
            # **strKeyUsage:** This field specifies the intended use of the certificate. In this case, we are setting it to "clientAuth", which indicates that the certificate will be used for client authentication.
            ltca_request.strKeyUsage = ""
            # **strExtendedKeyUsage:** This field specifies additional key usages that the client would like to be included in the certificate. In this case, we are also setting it to "clientAuth", which reinforces the fact that the certificate will only be used for client authentication.
            ltca_request.strExtendedKeyUsage = "clientAuth"
            # **strX509CertReq:** This field contains the CSR data in PEM format. The CSR data is generated by the client and contains information about the public key and the intended use of the certificate.
            ltca_request.strX509CertReq = csr_pem
            # **iNonce:** This field contains a random integer value that is used to prevent replay attacks.
            ltca_request.iNonce = int(random.randint(0, 65535))
            # **tTimeStamp:** This field contains the current time in Unix epoch seconds. It is used to ensure that the request is fresh.
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
        """    Obtain a ticket using an LTCA certificate.

        This method creates a ticket request, sends it to a service, and receives a
        response. It validates nonces and timestamps to ensure the response's integrity.

        Args:
            ltca_response (msgX509CertRes_LTCA2V): LTCA certificate response message.

        Returns:
            msgTicketRes: A ticket response message."""
        try:
            # Create a ticket request
            ticket_request = msgTicketReq()
            # **iReqType:** This field represents the request type. It is an integer value that specifies the type of ticket request being made. In this case, we are setting it to 126, which indicates that this is a request for a ticket certificate.
            ticket_request.iReqType = 126
            # **uiServices:** This field specifies the services that the ticket will be used for. In this case, we are setting it to 0, which indicates that the ticket will be used for all services.
            ticket_request.uiServices = 0
            # **iLTCAIdRange:** This field specifies the range of LTCA IDs that the client is willing to be assigned. In this case, we are setting it to 1002, which indicates that the client is willing to accept a LTCA ID in the range of 1002-1023.
            ticket_request.iLTCAIdRange = 1002
            # **iPCAIdRange:** This field specifies the range of PCA IDs that the client is willing to be assigned. In this case, we are setting it to 1001, which indicates that the client is willing to accept a PCA ID in the range of 1001-1002.
            ticket_request.iPCAIdRange = 1001
            # **iNonce:** This field contains a random integer value that is used to prevent replay attacks.
            ticket_request.iNonce = random.randint(0, 65535)
            # **tTimeStamp:** This field contains the current time in Unix epoch seconds. It is used to ensure that the request is fresh.
            ticket_request.tTimeStamp = int(time.time())
            # **strX509Cert:** This field contains the LTCA certificate that was received in response to the previous LTCA request.
            ticket_request.strX509Cert = ltca_response.strX509Cert
            # **uiPsnymCertNoRequest:** This field specifies the number of pseudonym certificates that the client is requesting. In this case, we are setting it to 1, which indicates that the client is requesting one pseudonym certificate.
            ticket_request.uiPsnymCertNoRequest = 1
            # **tPsnymStartTime:** This field specifies the start time for the pseudonym certificate. In this case, we are setting it to the current system time.
            ticket_request.tPsnymStartTime = int(time.time())
            # **tPsnymEndTime:** This field specifies the end time for the pseudonym certificate. In this case, we are setting it to one hour from the current system time.
            ticket_request.tPsnymEndTime = int(time.time()) + 60 * 60
            # **stSign:** This field contains the signature that was generated by the LTCA server in response to the previous LTCA request.
            ticket_request.stSign.CopyFrom(ltca_response.stSign)
            # **stSigner:** This field contains the signer information that was generated by the LTCA server in response to the previous LTCA request.
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
        """ 
        Obtain a pseudonym certificate.

        This method generates a new private key, creates a pseudonym certificate request,
        sends the request to a PCA (Pseudonym Certificate Authority) server, and parses
        the response. It also validates nonces and timestamps to ensure the integrity of
        the response.

        Args:
            ticket (msgTicketRes): A ticket response message.

        Returns:
            msgPsnymCertRes_PCA2V: A pseudonym certificate response message.
        """
        try:
           # Generate a new key pair for the pseudonym request
            private_key = ec.generate_private_key(ec.SECP256R1())
            public_key = private_key.public_key()

            # Create a pseudonym request
            pseudonym_request = msgPsnymCertReq_V2PCA()
            # **iReqType:** This field represents the request type. It is an integer value that specifies the type of pseudonym certificate request being made. In this case, we are setting it to 220, which indicates that this is a request for a pseudonym certificate from a PCA server.
            pseudonym_request.iReqType = 220
            # **iTicketSize:** This field specifies the size of the ticket in bytes. In this case, we are setting it to the length of the ticket string.
            pseudonym_request.iTicketSize = len(ticket.strTicket)
            # **strTicket:** This field contains the ticket that was received from the LTCA server.
            pseudonym_request.strTicket = ticket.strTicket
            # **iLTCAIdRange:** This field specifies the range of LTCA IDs that the client is willing to accept. In this case, we are setting it to 1002, which indicates that the client is willing to accept a LTCA ID in the range of 1002-1023.
            pseudonym_request.iLTCAIdRange = 1002
            # **iPCAIdRange:** This field specifies the range of PCA IDs that the client is willing to accept. In this case, we are setting it to 1001, which indicates that the client is willing to accept a PCA ID in the range of 1001-1002.
            pseudonym_request.iPCAIdRange = 1001
            # **uiPsnymCertNo:** This field specifies the number of pseudonym certificates that the client is requesting. In this case, we are setting it to 1, which indicates that the client is requesting one pseudonym certificate.
            pseudonym_request.uiPsnymCertNo = 1
            # **iLocation:** This field specifies the location of the client. This is used to determine which PCA server to send the request to. In this case, we are setting it to 6.
            pseudonym_request.iLocation = 6
            # **iNonce:** This field contains a random integer value that is used to prevent replay attacks.
            pseudonym_request.iNonce = random.randint(0, 65535)
            # **tTimeStamp:** This field contains the current time in Unix epoch seconds. It is used to ensure that the request is fresh.
            pseudonym_request.tTimeStamp = int(time.time())


            # Create a WAVECertificateRequest message
            wave_cert_request = msgWAVECertificateRequest()
            
            # Create an EC public key message using the public key
            ec_public_key, public_key_data = self._create_ec_public_key(public_key)

            # Create a ToBeSignedCSR message with the EC public key
            csr = self._create_to_be_signed_csr(ec_public_key)

            wave_cert_request.unsignedCsr.CopyFrom(csr)  # Assign the ToBeSignedCSR to unsignedCsr
            
            # Create a msgSignerInfo object for the public key
            signer_info = self.create_SignerInfo(public_key_data)
            # Assign the signer_info object to public_key_data.stSigner
            wave_cert_request.stSigner.CopyFrom(signer_info)

            # Sign the CSR with the private key 
            signature_str = self.serialize_and_sign(private_key, csr)
             # Create a msgSignature object
            signature = msgSignature()
            signature.strSignature = signature_str
            signature.uiSignLen = len(signature_str)
            
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

    def serialize_and_sign(self, private_key, csr):
        """ Serializes the CSR message and signs it with the provided private key.

        Args:
            private_key (object): The private key used for signing the CSR.
            csr (msgToBeSignedCSR): The CSR message to be signed.

        Returns:
            str: The base64 encoded signature string."""
     
        csr_bytes = csr.SerializeToString()
        hash_algorithm = hashes.SHA256()
            # Sign the CSR with the private key 
        signature = private_key.sign(
                csr_bytes,
                ec.ECDSA(hash_algorithm)
            )
        signature_str = base64.b64encode(signature).decode('utf-8')
        return signature_str

    def create_SignerInfo(self, public_key_data):
        """
        Creates a SignerInfo message for the given public key data.

        Args:
            public_key_data (str): The public key data used in the SignerInfo message.

        Returns:
            msgSignerInfo: The created SignerInfo messag
        """
        signer_info = msgSignerInfo()  
        signer_info.type = msgSignerIdentifierType.SignerIdentifierType.self
        signer_info.strCertificate = public_key_data  
        signer_info.strDigest = public_key_data  
        signer_info.strCertificatesChain = public_key_data
        return signer_info

    def _create_to_be_signed_csr(self, ec_public_key):
        """
        Creates a ToBeSignedCSR message with the provided EC public key.

        Args:
            ec_public_key (msgECPublicKey): The EC public key message.

        Returns:
            msgToBeSignedCSR: The created ToBeSignedCSR message.
        """
        csr = msgToBeSignedCSR()
        csr.csrVersion = 0  
        csr.subjectType = msgSubType.wsa_ca1  
        csr.requestType = msgRequestScopeType.specifiedInRequest  
        csr.stECPsnymPublicKey.CopyFrom(ec_public_key)
        return csr

    def _create_ec_public_key(self, public_key):
        """ 
        Creates an EC public key message and public key data string from the provided public key.

        Args:
            public_key (object): The public key object.

        Returns:
            msgECPublicKey: The EC public key message.
            str: The public key data string.
            """
        ec_public_key = msgECPublicKey()
        public_key_data = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        ec_public_key.uiPsnymPublicKeyLen = len(public_key_data)
        ec_public_key.strPsnymPublicKey = public_key_data
        return ec_public_key,public_key_data




if __name__ == "__main__":
    ltca_url = "http://nsscore.ict.kth.se:30930/cgi-bin/ltca"
    pca_url = "http://nsscore.ict.kth.se:30931/cgi-bin/pca"

    
    client_key_path = "ecdsa_private_key.pem"
    csr_file_path = "ecdsa_csr.pem"

    parser = argparse.ArgumentParser()
    parser.add_argument('--mail', help='mail address of obu')
    args = parser.parse_args()
    # Pass the email address from the command line argument
    vpkiclient = VPKIClient(ltca_url, pca_url, csr_file_path, client_key_path, args.mail, validate_certificate=False)
    try:
        ltca_certificate = vpkiclient.obtain_ltca()
        print(f"Obtained LTCA Certificate: {ltca_certificate}")
        ticket = vpkiclient.obtain_ticket(ltca_certificate)
        print(f"Obtained Ticket: {ticket}")
        pseudonym_certificate = vpkiclient.obtain_pseudonym(ticket)
        print(f"Obtained Pseudonym Certificate: {pseudonym_certificate}")        
    except Exception as e:
        print(f"Error: {str(e)}")
