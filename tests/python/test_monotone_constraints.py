import numpy as np
import unittest
import testing as tm
import pytest

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

dpath = HOME_DIR + 'demo/data/'

number_of_dpoints = 1000
x1_positively_correlated_with_y = np.random.random(size=number_of_dpoints)
x2_negatively_correlated_with_y = np.random.random(size=number_of_dpoints)

X = np.column_stack((
    x1_positively_correlated_with_y, x2_negatively_correlated_with_y
))
zs = np.random.normal(loc=0.0, scale=0.01, size=number_of_dpoints)
y = (
    5 * x1_positively_correlated_with_y +
    np.sin(10 * np.pi * x1_positively_correlated_with_y) -
    5 * x2_negatively_correlated_with_y -
    np.cos(10 * np.pi * x2_negatively_correlated_with_y) +
    zs
)

dump_svmlight_file(X, y, temp_name) 
xgb.encrypt_file(temp_name, temp_enc_name, sym_key_file)
 
training_dset = xgb.DMatrix({username: temp_enc_name})


def is_increasing(y):
    return np.count_nonzero(np.diff(y) < 0.0) == 0


def is_decreasing(y):
    return np.count_nonzero(np.diff(y) > 0.0) == 0


def is_correctly_constrained(learner):
    n = 100
    variable_x = np.linspace(0, 1, n).reshape((n, 1))
    fixed_xs_values = np.linspace(0, 1, n)

    for i in range(1, n - 1):
        fixed_x = fixed_xs_values[i] * np.ones((n, 1))
        y_dummy = np.random.randn(n)
        monotonically_increasing_x = np.column_stack((variable_x, fixed_x))
        dump_svmlight_file(monotonically_increasing_x, y_dummy, temp_name) 
        xgb.encrypt_file(temp_name, temp_enc_name, sym_key_file)
        monotonically_increasing_dset = xgb.DMatrix({username: temp_enc_name}, feature_names=['f0', 'f1'])
        monotonically_increasing_y = learner.predict(
            monotonically_increasing_dset
        )[0]

        monotonically_decreasing_x = np.column_stack((fixed_x, variable_x))
        dump_svmlight_file(monotonically_decreasing_x, y_dummy, temp_name) 
        xgb.encrypt_file(temp_name, temp_enc_name, sym_key_file)
        monotonically_decreasing_dset = xgb.DMatrix({username: temp_enc_name})
        monotonically_decreasing_y = learner.predict(
            monotonically_decreasing_dset
        )[0]

        if not (
            is_increasing(monotonically_increasing_y) and
            is_decreasing(monotonically_decreasing_y)
        ):
            return False

    return True


class TestMonotoneConstraints(unittest.TestCase):

    def test_monotone_constraints_for_exact_tree_method(self):

        # first check monotonicity for the 'exact' tree method
        params_for_constrained_exact_method = {
            'tree_method': 'exact', 'verbosity': 1,
            'monotone_constraints': '(1, -1)'
        }
        constrained_exact_method = xgb.train(
            params_for_constrained_exact_method, training_dset
        )
        assert is_correctly_constrained(constrained_exact_method)

    def test_monotone_constraints_for_depthwise_hist_tree_method(self):

        # next check monotonicity for the 'hist' tree method
        params_for_constrained_hist_method = {
            'tree_method': 'hist', 'verbosity': 1,
            'monotone_constraints': '(1, -1)'
        }
        constrained_hist_method = xgb.train(
            params_for_constrained_hist_method, training_dset
        )

        assert is_correctly_constrained(constrained_hist_method)

    def test_monotone_constraints_for_lossguide_hist_tree_method(self):

        # next check monotonicity for the 'hist' tree method
        params_for_constrained_hist_method = {
            'tree_method': 'hist', 'verbosity': 1,
            'grow_policy': 'lossguide',
            'monotone_constraints': '(1, -1)'
        }
        constrained_hist_method = xgb.train(
            params_for_constrained_hist_method, training_dset
        )

        assert is_correctly_constrained(constrained_hist_method)

    @pytest.mark.skipif(**tm.no_sklearn())
    def test_training_accuracy(self):
        from sklearn.metrics import accuracy_score
        #TODO: implement support for ?indexing_model=1
        """
        dtrain = xgb.DMatrix({username: dpath + 'agaricus.txt.train.enc?indexing_mode=1'})
        dtest = xgb.DMatrix({username: dpath + 'agaricus.txt.test.enc?indexing_mode=1'})
        params = {'eta': 1, 'max_depth': 6, 'objective': 'binary:logistic',
                  'tree_method': 'hist', 'monotone_constraints': '(1, 0)'}
        num_boost_round = 5
        """

        #TODO(rishabh): implement get_label()
        """
        params['grow_policy'] = 'lossguide'
        bst = xgb.train(params, dtrain, num_boost_round)
        pred_dtest = (bst.predict(dtest) < 0.5)
        assert accuracy_score(dtest.get_label(), pred_dtest) < 0.1

        params['grow_policy'] = 'depthwise'
        bst = xgb.train(params, dtrain, num_boost_round)
        pred_dtest = (bst.predict(dtest) < 0.5)
        assert accuracy_score(dtest.get_label(), pred_dtest) < 0.1
        """
