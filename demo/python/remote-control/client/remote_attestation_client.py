"""The Python implementation of the GRPC Remote Attestation client."""

from __future__ import print_function
import logging

import grpc
import base64

import remote_attestation_pb2
import remote_attestation_pb2_grpc

import securexgboost as xgb
import argparse
import os
from rpc_utils import *

def run(channel_addr, key_path, keypair):
    """
    The client will make 4 calls to the server that will run computation
    1. A call to retrieve the attestation report from the server. The client will use this report
    to verify that the it can trust the server.
    2. A call to send the symmetric key used to encrypt the data to the server.
    3. A call to commence computation.
    """
    # Get remote report from enclave
    with grpc.insecure_channel(channel_addr) as channel:
        stub = remote_attestation_pb2_grpc.RemoteAttestationStub(channel)
        response = stub.GetAttestation(remote_attestation_pb2.Status(status=1))

    pem_key = response.pem_key
    key_size = response.key_size
    remote_report = response.remote_report
    remote_report_size = response.remote_report_size
    print("Report received from remote enclave")

    # Verify report
    enclave_reference = xgb.Enclave(create_enclave=False)
    enclave_reference.set_report_attrs(pem_key, key_size, remote_report, remote_report_size)
    enclave_reference.verify_remote_report_and_set_pubkey()
    print("Report successfully verified")

    # Encrypt and sign symmetric key used to encrypt data
    key_file = open(key_path, 'rb')
    sym_key = key_file.read() # The key will be type bytes
    key_file.close()

    crypto_utils = xgb.CryptoUtils()

    # Encrypt symmetric key
    enc_sym_key, enc_sym_key_size = crypto_utils.encrypt_data_with_pk(sym_key, len(sym_key), pem_key, key_size)
    print("Encrypted symmetric key")

    # Sign encrypted symmetric key
    sig, sig_len = crypto_utils.sign_data(keypair, enc_sym_key, enc_sym_key_size) 
    print("Signed ciphertext")

    # Send data key to the server
    with grpc.insecure_channel(channel_addr) as channel:
        stub = remote_attestation_pb2_grpc.RemoteAttestationStub(channel)

        response = stub.SendKey(remote_attestation_pb2.DataMetadata(enc_sym_key=enc_sym_key, key_size=enc_sym_key_size, signature=sig, sig_len=sig_len))
        print("Symmetric key for data sent to server")

    # Signal start
    with grpc.insecure_channel(channel_addr) as channel:
        stub = remote_attestation_pb2_grpc.RemoteAttestationStub(channel)
        print("Waiting for training to finish...")
        response = stub.SignalStart(remote_attestation_pb2.Status(status=1))

        if response.status == 1:
            print("Training succeeded! Decrypting predictions...")
           
            enc_preds_serialized = response.predictions
            num_preds = response.num_preds

            enc_preds = proto_to_pointer(enc_preds_serialized)
            preds = crypto_utils.decrypt_predictions(sym_key, enc_preds, num_preds)

            print("Predictions: ", preds)
        else:
            print("Training failed")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip-addr", help="server IP address", required=True)
    parser.add_argument("--key", help="path to key used to encrypt data on client", required=True)
    parser.add_argument("--keypair", help="path to keypair for signing data", required=True)

    args = parser.parse_args()

    channel_addr = str(args.ip_addr) + ":50051" 

    logging.basicConfig()
    run(channel_addr, str(args.key), str(args.keypair))
