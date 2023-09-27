import interfaces_pb2
import requests
import json

class VPKIClient:
     def __init__(self, pca_url, pca_method,client_cer,client_key):
        self.pca_url = pca_url
        self.pca_method = pca_method
        self.clientkey=client_key
        self.clientcer=client_cer

       # This method is used to obtain a pseudonym from the PCA server.   
     def obtain_pseudonym(self):
        # Create  pseudonym request.
        pseudonym_request = interfaces_pb2.PseudonymRequest()
        pseudonym_request.client_cer = self.clientcer

        # Sign the pseudonym requaset with the key 
        signature = self.client_key.sign(pseudonym_request.SerializeToString())
        pseudonym_request.signature = signature

        # Send  pseudonym request to the PCA server.
        response = interfaces_pb2.sendRequest(self.pca_url, self.pca_method, pseudonym_request.SerializeToString())

        # Parse the response.
        pseudonym_response = interfaces_pb2.PseudonymResponse()
        pseudonym_response.ParseFromString(response)

        # Return a pseudonym certificate.
        return pseudonym_response.pseudonym_certificate
     
   