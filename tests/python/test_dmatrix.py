# -*- coding: utf-8 -*-
import numpy as np
import unittest
import scipy.sparse
from scipy.sparse import rand

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

dpath = HOME_DIR + 'demo/data/'
rng = np.random.RandomState(1994)


class TestDMatrix(unittest.TestCase):
    def test_dmatrix_dimensions(self):
        data = np.random.randn(5, 5)
        target = np.random.randn(5)
        dump_svmlight_file(data, target, temp_name) 
        xgb.encrypt_file(temp_name, temp_enc_name, sym_key_file)
        dm = xgb.DMatrix({username: temp_enc_name})
        assert dm.num_row() == 5
        assert dm.num_col() == 5

        data = np.random.randn(2, 2)
        target = np.random.randn(2)
        dump_svmlight_file(data, target, temp_name) 
        xgb.encrypt_file(temp_name, temp_enc_name, sym_key_file)
        dm = xgb.DMatrix({username: temp_enc_name})
        assert dm.num_row() == 2
        assert dm.num_col() == 2

    def test_slice(self):
        X = rng.randn(100, 100)
        y = rng.randint(low=0, high=3, size=100)
        dump_svmlight_file(X, y, temp_name) 
        xgb.encrypt_file(temp_name, temp_enc_name, sym_key_file)
        d = xgb.DMatrix({username: temp_enc_name})
        eval_res_0 = {}
        #TODO(rishabh): implement evals_result()
        """
        booster = xgb.train(
            {'num_class': 3, 'objective': 'multi:softprob'}, d,
            num_boost_round=2, evals=[(d, 'd')], evals_result=eval_res_0)

        predt = booster.predict(d)[0]
        predt = predt.reshape(100 * 3, 1)
        d.set_base_margin(predt)
        """

        #TODO(rishabh): implement slice()
        """
        ridxs = [1, 2, 3, 4, 5, 6]
        d = d.slice(ridxs)
        sliced_margin = d.get_float_info('base_margin')
        assert sliced_margin.shape[0] == len(ridxs) * 3

        eval_res_1 = {}
        xgb.train({'num_class': 3, 'objective': 'multi:softprob'}, d,
                  num_boost_round=2, evals=[(d, 'd')], evals_result=eval_res_1)

        eval_res_0 = eval_res_0['d']['merror']
        eval_res_1 = eval_res_1['d']['merror']
        for i in range(len(eval_res_0)):
            assert abs(eval_res_0[i] - eval_res_1[i]) < 0.02
        """

    def test_feature_names_slice(self):
        data = np.random.randn(5, 5)
        target = np.random.randn(5)
        dump_svmlight_file(data, target, temp_name) 
        xgb.encrypt_file(temp_name, temp_enc_name, sym_key_file)
 
        # different length
        self.assertRaises(ValueError, xgb.DMatrix, {username: temp_enc_name},
                          feature_names=list('abcdef'))
        # contains duplicates
        self.assertRaises(ValueError, xgb.DMatrix, {username: temp_enc_name},
                          feature_names=['a', 'b', 'c', 'd', 'd'])
        # contains symbol
        self.assertRaises(ValueError, xgb.DMatrix, {username: temp_enc_name},
                          feature_names=['a', 'b', 'c', 'd', 'e<1'])

        dm = xgb.DMatrix({username: temp_enc_name})
        dm.feature_names = list('abcde')
        assert dm.feature_names == list('abcde')

        #TODO(rishabh): implement slice()
        """
        assert dm.slice([0, 1]).feature_names == dm.feature_names

        dm.feature_types = 'q'
        assert dm.feature_types == list('qqqqq')

        dm.feature_types = list('qiqiq')
        assert dm.feature_types == list('qiqiq')

        def incorrect_type_set():
            dm.feature_types = list('abcde')

        self.assertRaises(ValueError, incorrect_type_set)

        # reset
        dm.feature_names = None
        self.assertEqual(dm.feature_names, ['f0', 'f1', 'f2', 'f3', 'f4'])
        assert dm.feature_types is None
        """

    def test_feature_names(self):
        data = np.random.randn(100, 5)
        target = np.array([0, 1] * 50)

        dump_svmlight_file(data, target, temp_name) 
        xgb.encrypt_file(temp_name, temp_enc_name, sym_key_file)
 
        features = ['Feature1', 'Feature2', 'Feature3', 'Feature4', 'Feature5']

        dm = xgb.DMatrix({username: temp_enc_name}, feature_names=features)
        assert dm.feature_names == features
        assert dm.num_row() == 100
        assert dm.num_col() == 5

        params = {'objective': 'multi:softprob',
                  'eval_metric': 'mlogloss',
                  'eta': 0.3,
                  'num_class': 3}

        bst = xgb.train(params, dm, num_boost_round=10)
        scores = bst.get_fscore()
        assert list(sorted(k for k in scores)) == features

        dummy_X = np.random.randn(5, 5)
        dummy_Y = np.random.randn(5)

        dump_svmlight_file(dummy_X, dummy_Y, temp_name) 
        xgb.encrypt_file(temp_name, temp_enc_name, sym_key_file)

        dm = xgb.DMatrix({username: temp_enc_name}, feature_names=features)
        bst.predict(dm)[0]

        # different feature name must raises error
        dm = xgb.DMatrix({username: temp_enc_name}, feature_names=list('abcde'))
        self.assertRaises(ValueError, bst.predict, dm)

    def test_get_info(self):
        dtrain = xgb.DMatrix({username: dpath + 'agaricus.txt.train.enc'})
        #TODO(rishabh): implement get_float_info(), get_uint_info()
        """
        dtrain.get_float_info('label')
        dtrain.get_float_info('weight')
        dtrain.get_float_info('base_margin')
        dtrain.get_uint_info('group_ptr')
        """

