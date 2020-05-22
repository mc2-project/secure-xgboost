import pickle
import numpy as np
import os
import unittest

import securexgboost as xgb
import os
from sklearn.datasets import dump_svmlight_file


username = "user1"
HOME_DIR = os.path.dirname(os.path.realpath(__file__)) + "/../../"
sym_key_file = HOME_DIR + "demo/data/key_zeros.txt"
pub_key_file = HOME_DIR + "demo/data/userkeys/private_user_1.pem"
cert_file = HOME_DIR + "demo/data/usercrts/{0}.crt".format(username)

temp_name = HOME_DIR + "demo/data/temp_file.txt"
temp_enc_name = HOME_DIR + "demo/data/temp_file.txt.enc"

print("Init user parameters")
xgb.init_user(username, sym_key_file, pub_key_file, cert_file)

print("Creating enclave")
enclave = xgb.Enclave(HOME_DIR + "build/enclave/xgboost_enclave.signed")

# Remote Attestation
print("Remote attestation")

# Note: Simulation mode does not support attestation
# pass in `verify=False` to attest()
enclave.attest(verify=False)

print("Send private key to enclave")
enclave.add_key()


kRows = 100
kCols = 10


def generate_data():
    X = np.random.randn(kRows, kCols)
    y = np.random.randn(kRows)
    return X, y


class TestPickling(unittest.TestCase):
    def run_model_pickling(self, xgb_params):
        X, y = generate_data()

        dump_svmlight_file(X, y, temp_name) 
        xgb.encrypt_file(temp_name, temp_enc_name, sym_key_file)
        
        dtrain = xgb.DMatrix({username: temp_enc_name})
        bst = xgb.train(xgb_params, dtrain)

        dump_0 = bst.get_dump(dump_format='json')
        assert dump_0

        filename = 'model.pkl'

        #TODO: support pickling
        """

        with open(filename, 'wb') as fd:
            pickle.dump(bst, fd)

        with open(filename, 'rb') as fd:
            bst = pickle.load(fd)

        with open(filename, 'wb') as fd:
            pickle.dump(bst, fd)

        with open(filename, 'rb') as fd:
            bst = pickle.load(fd)

        assert bst.get_dump(dump_format='json') == dump_0

        if os.path.exists(filename):
            os.remove(filename)
        """

    def test_model_pickling_binary(self):
        params = {
            'nthread': 1,
            'tree_method': 'hist'
        }
        self.run_model_pickling(params)

    def test_model_pickling_json(self):
        params = {
            'nthread': 1,
            'tree_method': 'hist',
            'enable_experimental_json_serialization': True
        }
        self.run_model_pickling(params)
