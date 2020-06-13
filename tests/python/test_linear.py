import numpy as np
import testing as tm
import unittest
import pytest

import securexgboost as xgb
import os
from sklearn.datasets import dump_svmlight_file

try:
    from sklearn.linear_model import ElasticNet
    from sklearn.preprocessing import scale
    from regression_test_utilities import run_suite, parameter_combinations
except ImportError:
    None

from paths import sym_key_file, priv_key_file, cert_file

username = "user1"
HOME_DIR = os.path.dirname(os.path.realpath(__file__)) + "/../../"

temp_name = HOME_DIR + "demo/data/temp_file.txt"
temp_enc_name = HOME_DIR + "demo/data/temp_file.txt.enc"

#  xgb.init_client(user_name=username, sym_key_file=sym_key_file, priv_key_file=priv_key_file, cert_file=cert_file)
#  xgb.init_server(enclave_image=HOME_DIR + "build/enclave/xgboost_enclave.signed")
#  xgb.attest(verify=False)


def is_float(s):
    try:
        float(s)
        return 1
    except ValueError:
        return 0


def xgb_get_weights(bst):
    return np.array([float(s) for s in bst.get_dump()[0].split() if
                     is_float(s)])


def assert_regression_result(results, tol):
    regression_results = [r for r in results if
                          r["param"]["objective"] == "reg:squarederror"]
    for res in regression_results:
        X = scale(res["dataset"].X,
                  with_mean=isinstance(res["dataset"].X, np.ndarray))
        y = res["dataset"].y

        dump_svmlight_file(X, y, temp_name) 
        xgb.encrypt_file(temp_name, temp_enc_name, sym_key_file)

        reg_alpha = res["param"]["alpha"]
        reg_lambda = res["param"]["lambda"]
        pred = res["bst"].predict(xgb.DMatrix({username: temp_enc_name}))
        weights = xgb_get_weights(res["bst"])[1:]
        enet = ElasticNet(alpha=reg_alpha + reg_lambda,
                          l1_ratio=reg_alpha / (reg_alpha + reg_lambda))
        enet.fit(X, y)
        enet_pred = enet.predict(X)
        assert np.isclose(weights, enet.coef_, rtol=tol,
                          atol=tol).all(), (weights, enet.coef_)
        assert np.isclose(enet_pred, pred, rtol=tol, atol=tol).all(), (
            res["dataset"].name, enet_pred[:5], pred[:5])


# TODO: More robust classification tests
def assert_classification_result(results):
    classification_results = [r for r in results if
                              r["param"]["objective"] != "reg:squarederror"]
    for res in classification_results:
        # Check accuracy  is reasonable
        assert res["eval"][-1] < 2.0, (res["dataset"].name, res["eval"][-1])


class TestLinear(unittest.TestCase):

    datasets = ["Boston", "Digits", "Cancer", "Sparse regression",
                "Boston External Memory"]

    @pytest.mark.skipif(**tm.no_sklearn())
    def test_coordinate(self):
        variable_param = {'booster': ['gblinear'], 'updater':
                          ['coord_descent'], 'eta': [0.5], 'top_k':
                          [10], 'tolerance': [1e-5], 'nthread': [2],
                          'alpha': [.005, .1], 'lambda': [.005],
                          'feature_selector': ['cyclic', 'shuffle',
                                               'greedy', 'thrifty']}
        #TODO: implement features required by regression_test_utilities.py
        """
        for param in parameter_combinations(variable_param):
            results = run_suite(param, 150, self.datasets, scale_features=True)
            assert_regression_result(results, 1e-2)
            assert_classification_result(results)
        """

    @pytest.mark.skipif(**tm.no_sklearn())
    def test_shotgun(self):
        variable_param = {'booster': ['gblinear'], 'updater':
                          ['shotgun'], 'eta': [0.5], 'top_k': [10],
                          'tolerance': [1e-5], 'nthread': [2],
                          'alpha': [.005, .1], 'lambda': [.005],
                          'feature_selector': ['cyclic', 'shuffle']}
        #TODO: implement features required by regression_test_utilities.py
        """
        for param in parameter_combinations(variable_param):
            results = run_suite(param, 200, self.datasets, True)
            assert_regression_result(results, 1e-2)
            assert_classification_result(results)
        """
