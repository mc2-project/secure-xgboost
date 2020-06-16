import testing as tm
import unittest
import pytest
import numpy as np
from regression_test_utilities import run_suite, parameter_combinations, \
    assert_results_non_increasing

import securexgboost as xgb
import os
from sklearn.datasets import dump_svmlight_file
from config import sym_key_file, priv_key_file, cert_file

username = "user1"
HOME_DIR = os.path.dirname(os.path.realpath(__file__)) + "/../../"

temp_name = HOME_DIR + "demo/data/temp_file.txt"
temp_enc_name = HOME_DIR + "demo/data/temp_file.txt.enc"


class TestUpdaters(unittest.TestCase):
    @pytest.mark.skipif(**tm.no_sklearn())
    def test_histmaker(self):
        variable_param = {'updater': ['grow_histmaker'], 'max_depth': [2, 8]}
        for param in parameter_combinations(variable_param):
            result = run_suite(param)
            assert_results_non_increasing(result, 1e-2)

    @pytest.mark.skipif(**tm.no_sklearn())
    def test_colmaker(self):
        variable_param = {'updater': ['grow_colmaker'], 'max_depth': [2, 8]}
        for param in parameter_combinations(variable_param):
            result = run_suite(param)
            assert_results_non_increasing(result, 1e-2)

    @pytest.mark.skipif(**tm.no_sklearn())
    def test_pruner(self):
        import sklearn
        params = {'tree_method': 'exact'}
        cancer = sklearn.datasets.load_breast_cancer()
        X = cancer['data']
        y = cancer["target"]

        dump_svmlight_file(X, y, temp_name) 
        xgb.encrypt_file(temp_name, temp_enc_name, sym_key_file)
 
        dtrain = xgb.DMatrix({username: temp_enc_name})
        booster = xgb.train(params, dtrain=dtrain, num_boost_round=10)
        grown = str(booster.get_dump())

        params = {'updater': 'prune', 'process_type': 'update', 'gamma': '0.2'}
        #TODO(rishabh): add support for xgb_model
        """
        booster = xgb.train(params, dtrain=dtrain, num_boost_round=10,
                            xgb_model=booster)
        after_prune = str(booster.get_dump())
        assert grown != after_prune

        booster = xgb.train(params, dtrain=dtrain, num_boost_round=10,
                            xgb_model=booster)
        second_prune = str(booster.get_dump())
        # Second prune should not change the tree
        assert after_prune == second_prune
        """

    @pytest.mark.skipif(**tm.no_sklearn())
    def test_fast_histmaker(self):
        variable_param = {'tree_method': ['hist'],
                          'max_depth': [2, 8],
                          'max_bin': [2, 256],
                          'grow_policy': ['depthwise', 'lossguide'],
                          'max_leaves': [64, 0],
                          'verbosity': [0]}
        for param in parameter_combinations(variable_param):
            result = run_suite(param)
            assert_results_non_increasing(result, 1e-2)

        # hist must be same as exact on all-categorial data
        dpath = HOME_DIR + 'demo/data/'
        ag_dtrain = xgb.DMatrix({username: dpath + 'agaricus.txt.train.enc'})
        ag_dtest = xgb.DMatrix({username: dpath + 'agaricus.txt.test.enc'})
        ag_param = {'max_depth': 2,
                    'tree_method': 'hist',
                    'eta': 1,
                    'verbosity': 0,
                    'objective': 'binary:logistic',
                    'eval_metric': 'auc'}
        hist_res = {}
        exact_res = {}

        #TODO(rishabh): support for evals_result
        """
        xgb.train(ag_param, ag_dtrain, 10,
                  [(ag_dtrain, 'train'), (ag_dtest, 'test')],
                  evals_result=hist_res)
        ag_param["tree_method"] = "exact"
        xgb.train(ag_param, ag_dtrain, 10,
                  [(ag_dtrain, 'train'), (ag_dtest, 'test')],
                  evals_result=exact_res)
        assert hist_res['train']['auc'] == exact_res['train']['auc']
        assert hist_res['test']['auc'] == exact_res['test']['auc']
        """

