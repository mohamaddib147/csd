                                        VPKI Client for Self-Signed Certificates
  Overview
 This repository contains a Python-based VPKI (Vehicular Public-Key Infrastructure) client designed to obtain pseudonyms from self-signed certificates. The client utilizes Protocol Buffers version 2 and integrates with the VPKI system as per the specifications provided.
Features
Obtain pseudonyms from self-signed certificates via a secure connection.
Support for Protocol Buffers version 2.
Error handling and graceful failure modes.
Configurable options for PCA URL and certificate validation.
Prerequisites
Before using the VPKI client, ensure you have the following prerequisites in place:

Python 3.x installed on your system.
Required Python packages installed (e.g., cryptography, grpcio, protobuf).
A self-signed client certificate and private key available.

Before using the VPKI client, MAKE sure to Update the configuration
Specify the paths to your client certificate and private key files using client_cert_path and client_key_path.
Optionally, configure certificate validation by setting validate_certificate to True or False as needed.
Usage
The VPKI client will send a request to the PCA server to obtain a pseudonym based on your client certificate. The obtained pseudonym will be displayed in the console.

Certificate 
To add the LTCA server's certificate to your trusted root certificate store on Kali Linux, you can use the update-ca-certificates command. Here are the steps to do it:
1:Copy the Certificate Files:
First, ensure that you have the LTCA server's certificate file (ltca_x509_cert.crt) and PCA server's certificate file (pca_x509_cert.crt) in a directory.
2:Move Certificate Files to the Appropriate Directory:
By convention, you can move these certificate files to the /usr/local/share/ca-certificates/ directory, which is a common location for CA certificates.
sudo mv ltca_x509_cert.crt pca_x509_cert.crt rca_x509_cert.pem /usr/local/share/ca-certificates/
3:Update the Certificate Store:
After moving the certificate files, run the update-ca-certificates command to update the CA certificate store. This command will automatically scan the /usr/local/share/ca-certificates/ directory for certificates and add them to the trusted root certificate store.
sudo update-ca-certificates
This command should output information about how many certificates were added or removed.
4:Verify the Update:
You can verify that the certificates have been successfully added to the trusted store by checking the contents of the /etc/ssl/certs/ directory:
ls -l /etc/ssl/certs/
