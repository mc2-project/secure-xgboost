import numpy as np
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

from numpy.testing import assert_approx_equal

X = np.array([[1]])
y = np.array([1])

dump_svmlight_file(X, y, temp_name) 
xgb.encrypt_file(temp_name, temp_enc_name, sym_key_file)
 
train_data = xgb.DMatrix({username: temp_enc_name})


class TestTreeRegularization(unittest.TestCase):
    def test_alpha(self):
        params = {
            'tree_method': 'exact', 'verbosity': 0,
            'objective': 'reg:squarederror',
            'eta': 1,
            'lambda': 0,
            'alpha': 0.1
        }

        model = xgb.train(params, train_data, 1)
        preds = model.predict(train_data)

        # Default prediction (with no trees) is 0.5
        # sum_grad = (0.5 - 1.0)
        # sum_hess = 1.0
        # 0.9 = 0.5 - (sum_grad - alpha * sgn(sum_grad)) / sum_hess
        assert_approx_equal(preds[0], 0.9)

    def test_lambda(self):
        params = {
            'tree_method': 'exact', 'verbosity': 0,
            'objective': 'reg:squarederror',
            'eta': 1,
            'lambda': 1,
            'alpha': 0
        }

        model = xgb.train(params, train_data, 1)
        preds = model.predict(train_data)

        # Default prediction (with no trees) is 0.5
        # sum_grad = (0.5 - 1.0)
        # sum_hess = 1.0
        # 0.75 = 0.5 - sum_grad / (sum_hess + lambda)
        assert_approx_equal(preds[0], 0.75)

    def test_alpha_and_lambda(self):
        params = {
            'tree_method': 'exact', 'verbosity': 1,
            'objective': 'reg:squarederror',
            'eta': 1,
            'lambda': 1,
            'alpha': 0.1
        }

        model = xgb.train(params, train_data, 1)
        preds = model.predict(train_data)

        # Default prediction (with no trees) is 0.5
        # sum_grad = (0.5 - 1.0)
        # sum_hess = 1.0
        # 0.7 = 0.5 - (sum_grad - alpha * sgn(sum_grad)) / (sum_hess + lambda)
        assert_approx_equal(preds[0], 0.7)
