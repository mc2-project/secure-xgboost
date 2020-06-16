import numpy as np
import securexgboost as xgb
import unittest
import os
import json
import pytest
import locale
from sklearn.datasets import dump_svmlight_file
import subprocess
import time

username = "user1"
HOME_DIR = os.path.dirname(os.path.realpath(__file__)) + "/../../"
sym_key_file = HOME_DIR + "demo/data/key_zeros.txt"
priv_key_file = HOME_DIR + "config/user1.pem"
cert_file = HOME_DIR + "config/user1.crt"


temp_name = HOME_DIR + "demo/data/temp_file.txt"
temp_enc_name = HOME_DIR + "demo/data/temp_file.txt.enc"

dpath = HOME_DIR + 'demo/data/'

class TestRPC(unittest.TestCase):
    def setUp(self):
        # Initialize server
        subprocess.Popen(["python3", HOME_DIR + "demo/python/remote-control/server/enclave_serve.py"], stdout=subprocess.PIPE)

        # Start orchestrator
        subprocess.Popen(["python3", HOME_DIR + "demo/python/remote-control/orchestrator/start_orchestrator.py"], stdout=subprocess.PIPE)

        # Give some time for server and orchestrator to start
        time.sleep(5)

    def test_basic_rpc(self):
        channel_addr = "127.0.0.1:50052"
        xgb.init_client(user_name=username, sym_key_file=sym_key_file, priv_key_file=priv_key_file, cert_file=cert_file, remote_addr=channel_addr)
        xgb.attest(verify=False)

        dtrain = xgb.DMatrix({username: dpath + 'agaricus.txt.train.enc'})
        dtest = xgb.DMatrix({username: dpath + 'agaricus.txt.test.enc'})

        # Set training parameters
        params = {
                "tree_method": "hist",
                "n_gpus": "0",
                "objective": "binary:logistic",
                "min_child_weight": "1",
                "gamma": "0.1",
                "max_depth": "5",
                "verbosity": "0" 
        }

        num_rounds = 2
        booster = xgb.train(params, dtrain, num_rounds)

        predictions, num_preds = booster.predict(dtest, decrypt=False)

        preds = booster.decrypt_predictions(predictions, num_preds)
        ten_preds = preds[:10]
        
        labels = [0, 1, 0, 0, 0, 0, 1, 0, 1, 0]
        err = sum(1 for i in range(len(ten_preds))
                  if int(ten_preds[i] > 0.5) != labels[i]) / float(len(ten_preds))

        # error must be smaller than 10%
        assert err < 0.1

    def tearDown(self):
        # FIXME: more graceful shut down
        # Kill server
        subprocess.Popen(["pkill", "-f", "enclave_serve.py"], stdout=subprocess.PIPE)

        # Kill orchestrator
        subprocess.Popen(["pkill", "-f", "start_orchestrator.py"], stdout=subprocess.PIPE)


                

