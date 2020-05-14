# -*- coding: utf-8 -*-
import sys
from contextlib import contextmanager
try:
    # python 2
    from StringIO import StringIO
except ImportError:
    # python 3
    from io import StringIO
import numpy as np
import unittest
import json
from pathlib import Path

import securexgboost as xgb
import os


username = "user1"
HOME_DIR = os.path.dirname(os.path.realpath(__file__)) + "/../../"
sym_key_file = HOME_DIR + "demo/data/key_zeros.txt"
pub_key_file = HOME_DIR + "demo/data/userkeys/private_user_1.pem"
cert_file = HOME_DIR + "demo/data/usercrts/{0}.crt".format(username)

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


@contextmanager
def captured_output():
    """Reassign stdout temporarily in order to test printed statements
    Taken from:
    https://stackoverflow.com/questions/4219717/how-to-assert-output-with-nosetest-unittest-in-python

    Also works for pytest.

    """
    new_out, new_err = StringIO(), StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    try:
        sys.stdout, sys.stderr = new_out, new_err
        yield sys.stdout, sys.stderr
    finally:
        sys.stdout, sys.stderr = old_out, old_err


class TestBasic(unittest.TestCase):

    def test_basic(self):
        dtrain = xgb.DMatrix({username: dpath + 'agaricus.txt.train.enc'})
        dtest = xgb.DMatrix({username: dpath + 'agaricus.txt.test.enc'})
        param = {'max_depth': 2, 'eta': 1,
                 'objective': 'binary:logistic'}
        # specify validations set to watch performance
        watchlist = [(dtrain, 'train')]
        num_round = 2
        bst = xgb.train(param, dtrain, num_round, watchlist)

        preds = bst.predict(dtrain)
        labels = dtrain.get_label()
        err = sum(1 for i in range(len(preds))
                  if int(preds[i] > 0.5) != labels[i]) / float(len(preds))
        # error must be smaller than 10%
        assert err < 0.1

        preds = bst.predict(dtest)
        labels = dtest.get_label()
        err = sum(1 for i in range(len(preds))
                  if int(preds[i] > 0.5) != labels[i]) / float(len(preds))
        # error must be smaller than 10%
        assert err < 0.1

        #TODO: implement bst.save_model
        # save model
        bst.save_model('xgb.model')
        # load model and data in
        bst2 = xgb.Booster(model_file='xgb.model')
        preds2 = bst2.predict(dtest)
        # assert they are the same
        assert np.sum(np.abs(preds2 - preds)) == 0

