import numpy as np
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

from numpy.testing import assert_approx_equal

X = np.array([[1]])
y = np.array([1])

dump_svmlight_file(X, y, temp_name) 
xgb.encrypt_file(temp_name, temp_enc_name, sym_key_file)
 
train_data = xgb.DMatrix({username: temp_enc_name})


class TestTreeRegularization(unittest.TestCase):
    def test_alpha(self):
        #  train_data = xgb.DMatrix({username: temp_enc_name})
        params = {
            'tree_method': 'exact', 'verbosity': 0,
            'objective': 'reg:squarederror',
            'eta': 1,
            'lambda': 0,
            'alpha': 0.1
        }

        model = xgb.train(params, train_data, 1)
        preds = model.predict(train_data)[0]
        print(preds[0])

        # Default prediction (with no trees) is 0.5
        # sum_grad = (0.5 - 1.0)
        # sum_hess = 1.0
        # 0.9 = 0.5 - (sum_grad - alpha * sgn(sum_grad)) / sum_hess
        assert_approx_equal(preds[0], 0.9)

    def test_lambda(self):
        #  train_data = xgb.DMatrix({username: temp_enc_name})
        params = {
            'tree_method': 'exact', 'verbosity': 0,
            'objective': 'reg:squarederror',
            'eta': 1,
            'lambda': 1,
            'alpha': 0
        }

        model = xgb.train(params, train_data, 1)
        preds = model.predict(train_data)[0]
        print(preds)

        # Default prediction (with no trees) is 0.5
        # sum_grad = (0.5 - 1.0)
        # sum_hess = 1.0
        # 0.75 = 0.5 - sum_grad / (sum_hess + lambda)
        assert_approx_equal(preds[0], 0.75)

    def test_alpha_and_lambda(self):
        #  train_data = xgb.DMatrix({username: temp_enc_name})
        params = {
            'tree_method': 'exact', 'verbosity': 1,
            'objective': 'reg:squarederror',
            'eta': 1,
            'lambda': 1,
            'alpha': 0.1
        }

        model = xgb.train(params, train_data, 1)
        preds = model.predict(train_data)[0]
        print(preds)

        # Default prediction (with no trees) is 0.5
        # sum_grad = (0.5 - 1.0)
        # sum_hess = 1.0
        # 0.7 = 0.5 - (sum_grad - alpha * sgn(sum_grad)) / (sum_hess + lambda)
        assert_approx_equal(preds[0], 0.7)
