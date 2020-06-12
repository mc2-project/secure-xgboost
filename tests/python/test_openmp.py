# -*- coding: utf-8 -*-
import unittest
import numpy as np


import securexgboost as xgb
import os
from sklearn.datasets import dump_svmlight_file
from paths import sym_key_file, priv_key_file, cert_file

username = "user1"
HOME_DIR = os.path.dirname(os.path.realpath(__file__)) + "/../../"

temp_name = HOME_DIR + "demo/data/temp_file.txt"
temp_enc_name = HOME_DIR + "demo/data/temp_file.txt.enc"

xgb.init_client(user_name=username, sym_key_file=sym_key_file, priv_key_file=priv_key_file, cert_file=cert_file)
xgb.init_server(enclave_image=HOME_DIR + "build/enclave/xgboost_enclave.signed")
xgb.attest(verify=False)


class TestOMP(unittest.TestCase):
    def test_omp(self):
        dpath = HOME_DIR + 'demo/data/'
        dtrain = xgb.DMatrix({username: dpath + 'agaricus.txt.train.enc'})
        dtest = xgb.DMatrix({username: dpath + 'agaricus.txt.test.enc'})

        param = {'booster': 'gbtree',
                 'objective': 'binary:logistic',
                 'grow_policy': 'depthwise',
                 'tree_method': 'hist',
                 'eval_metric': 'error',
                 'max_depth': 5,
                 'min_child_weight': 0}

        watchlist = [(dtest, 'eval'), (dtrain, 'train')]
        num_round = 5

        #TODO(rishabh): implement evals_result in xgb.train()
        """
        def run_trial():
            res = {}
            bst = xgb.train(param, dtrain, num_round, watchlist, evals_result=res)
            metrics = [res['train']['error'][-1], res['eval']['error'][-1]]
            preds = bst.predict(dtest)
            return metrics, preds

        def consist_test(title, n):
            auc, pred = run_trial()
            for i in range(n-1):
                auc2, pred2 = run_trial()
                try:
                    assert auc == auc2
                    assert np.array_equal(pred, pred2)
                except Exception as e:
                    print('-------test %s failed, num_trial: %d-------' % (title, i))
                    raise e
                auc, pred = auc2, pred2
            return auc, pred

        print('test approx ...')
        param['tree_method'] = 'approx'

        param['nthread'] = 1
        auc_1, pred_1 = consist_test('approx_thread_1', 100)

        param['nthread'] = 2
        auc_2, pred_2 = consist_test('approx_thread_2', 100)

        param['nthread'] = 3
        auc_3, pred_3 = consist_test('approx_thread_3', 100)

        assert auc_1 == auc_2 == auc_3
        assert np.array_equal(auc_1, auc_2)
        assert np.array_equal(auc_1, auc_3)

        print('test hist ...')
        param['tree_method'] = 'hist'

        param['nthread'] = 1
        auc_1, pred_1 = consist_test('hist_thread_1', 100)

        param['nthread'] = 2
        auc_2, pred_2 = consist_test('hist_thread_2', 100)

        param['nthread'] = 3
        auc_3, pred_3 = consist_test('hist_thread_3', 100)

        assert auc_1 == auc_2 == auc_3
        assert np.array_equal(auc_1, auc_2)
        assert np.array_equal(auc_1, auc_3)
        """
