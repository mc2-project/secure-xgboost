# -*- coding: utf-8 -*-
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
rng = np.random.RandomState(1994)


class TestInteractionConstraints(unittest.TestCase):
    def run_interaction_constraints(self, tree_method):
        x1 = np.random.normal(loc=1.0, scale=1.0, size=1000)
        x2 = np.random.normal(loc=1.0, scale=1.0, size=1000)
        x3 = np.random.choice([1, 2, 3], size=1000, replace=True)
        y = x1 + x2 + x3 + x1 * x2 * x3 \
            + np.random.normal(
                loc=0.001, scale=1.0, size=1000) + 3 * np.sin(x1)
        X = np.column_stack((x1, x2, x3))

        dump_svmlight_file(X, y, temp_name) 
        xgb.encrypt_file(temp_name, temp_enc_name, sym_key_file)

        dtrain = xgb.DMatrix({username: temp_enc_name})

        params = {
            'max_depth': 3,
            'eta': 0.1,
            'nthread': 2,
            'interaction_constraints': '[[0, 1]]',
            'tree_method': tree_method
        }
        num_boost_round = 12
        # Fit a model that only allows interaction between x1 and x2
        bst = xgb.train(
            params, dtrain, num_boost_round, evals=[(dtrain, 'train')])

        # Set all observations to have the same x3 values then increment
        #   by the same amount
        def f(x):
            tX = np.column_stack((x1, x2, np.repeat(x, 1000)))

            dump_svmlight_file(tX, y, temp_name) 
            xgb.encrypt_file(temp_name, temp_enc_name, sym_key_file)

            tmat = xgb.DMatrix({username: temp_enc_name})

            return bst.predict(tmat)[0]

        preds = [f(x) for x in [1, 2, 3]]

        # Check incrementing x3 has the same effect on all observations
        #   since x3 is constrained to be independent of x1 and x2
        #   and all observations start off from the same x3 value
        diff1 = preds[1] - preds[0]
        assert np.all(np.abs(diff1 - diff1[0]) < 1e-4)
        diff2 = preds[2] - preds[1]
        assert np.all(np.abs(diff2 - diff2[0]) < 1e-4)

    def test_exact_interaction_constraints(self):
        self.run_interaction_constraints(tree_method='exact')

    def test_hist_interaction_constraints(self):
        self.run_interaction_constraints(tree_method='hist')

    def test_approx_interaction_constraints(self):
        self.run_interaction_constraints(tree_method='approx')

    @pytest.mark.skipif(**tm.no_sklearn())
    def training_accuracy(self, tree_method):
        from sklearn.metrics import accuracy_score
        dtrain = xgb.DMatrix({username: dpath + 'agaricus.txt.train.enc?indexing_mode=1'})
        dtest = xgb.DMatrix({username: dpath + 'agaricus.txt.test.enc?indexing_mode=1'})
        params = {
            'eta': 1,
            'max_depth': 6,
            'objective': 'binary:logistic',
            'tree_method': tree_method,
            'interaction_constraints': '[[1,2], [2,3,4]]'
        }
        num_boost_round = 5

        #TODO(rishabh): add support for get_label()
        """
        params['grow_policy'] = 'lossguide'
        bst = xgb.train(params, dtrain, num_boost_round)
        pred_dtest = (bst.predict(dtest)[0] < 0.5)
        assert accuracy_score(dtest.get_label(), pred_dtest) < 0.1

        params['grow_policy'] = 'depthwise'
        bst = xgb.train(params, dtrain, num_boost_round)
        pred_dtest = (bst.predict(dtest)[0] < 0.5)
        assert accuracy_score(dtest.get_label(), pred_dtest) < 0.1
        """

    def test_hist_training_accuracy(self):
        self.training_accuracy(tree_method='hist')

    def test_exact_training_accuracy(self):
        self.training_accuracy(tree_method='exact')

    def test_approx_training_accuracy(self):
        self.training_accuracy(tree_method='approx')
