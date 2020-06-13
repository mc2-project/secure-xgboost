import pickle
import numpy as np
import os
import unittest

import securexgboost as xgb
import os
from sklearn.datasets import dump_svmlight_file
from paths import sym_key_file, priv_key_file, cert_file

username = "user1"
HOME_DIR = os.path.dirname(os.path.realpath(__file__)) + "/../../"

temp_name = HOME_DIR + "demo/data/temp_file.txt"
temp_enc_name = HOME_DIR + "demo/data/temp_file.txt.enc"

#  xgb.init_client(user_name=username, sym_key_file=sym_key_file, priv_key_file=priv_key_file, cert_file=cert_file)
#  xgb.init_server(enclave_image=HOME_DIR + "build/enclave/xgboost_enclave.signed")
#  xgb.attest(verify=False)


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
