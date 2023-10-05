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
