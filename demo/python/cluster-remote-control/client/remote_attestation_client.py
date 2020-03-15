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
import time
from rpc_utils import *

def run(channel_addrs, key_path, keypair):
    """
    The client will make 4 calls to the server that will run computation
    1. A call to retrieve the attestation report from the server. The client will use this report
    to verify that the it can trust the server.
    2. A call to send the symmetric key used to encrypt the data to the server.
    3. A call to commence computation.
    """
    # Perform attestation and send the client key to each node in the enclave cluster
    for channel_addr in channel_addrs:
        print("Connecting to", channel_addr)
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

            print("Sending key...")
            response = stub.SendKey(remote_attestation_pb2.DataMetadata(enc_sym_key=enc_sym_key, key_size=enc_sym_key_size, signature=sig, sig_len=sig_len))
            print("Symmetric key for data sent to server")

    print("Waiting for training to finish...")
    # Open up a channel to each node to signal start
    channels = []   
    for channel_addr in channel_addrs:
        # Signal start
        channels.append(grpc.insecure_channel(channel_addr))

    # Store futures in a list
    # Futures hold the result of asynchronous calls to each gRPC server
    futures = []

    for channel in channels:
        stub = remote_attestation_pb2_grpc.RemoteAttestationStub(channel)

        # Asynchronous calls to start job on each node
        response_future = stub.SignalStartCluster.future(remote_attestation_pb2.ClusterParams(num_workers=2))
        futures.append(response_future)

    results = []
    for future in futures:
        results.append(future.result().status)
      
    # If any node returned a non zero exit status
    if sum(results) == 0:
        print("Training succeeded! Encrypted model has been saved.")
    else:
        print("Training failed")
        

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip-addrs", nargs="+", help="server IP address", required=True)
    parser.add_argument("--key", help="path to key used to encrypt data on client", required=True)
    parser.add_argument("--keypair", help="path to keypair for signing data", required=True)

    args = parser.parse_args()

    ip_addrs = args.ip_addrs
    print(ip_addrs)
    channel_addrs = [str(ip_addr) + ":50051" for ip_addr in ip_addrs]

    logging.basicConfig()
    run(channel_addrs, str(args.key), str(args.keypair))
