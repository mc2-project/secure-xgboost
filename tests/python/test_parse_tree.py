import unittest
import numpy as np
import pytest
import testing as tm


pytestmark = pytest.mark.skipif(**tm.no_pandas())


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


class TestTreesToDataFrame(unittest.TestCase):

    def build_model(self, max_depth, num_round):
        dtrain = xgb.DMatrix({username: dpath + 'agaricus.txt.train.enc'})
        param = {'max_depth': max_depth, 'objective': 'binary:logistic',
                 'verbosity': 1}
        num_round = num_round
        bst = xgb.train(param, dtrain, num_round)
        return bst

    def parse_dumped_model(self, booster, item_to_get, splitter):
        item_to_get += '='
        txt_dump = booster.get_dump(with_stats=True)
        tree_list = [tree.split('/n') for tree in txt_dump]
        split_trees = [tree[0].split(item_to_get)[1:] for tree in tree_list]
        res = sum([float(line.split(splitter)[0])
                   for tree in split_trees for line in tree])
        return res

    def test_trees_to_dataframe(self):
        bst = self.build_model(max_depth=5, num_round=10)
        gain_from_dump = self.parse_dumped_model(booster=bst,
                                                 item_to_get='gain',
                                                 splitter=',')
        cover_from_dump = self.parse_dumped_model(booster=bst,
                                                  item_to_get='cover',
                                                  splitter='\n')
        # method being tested
        #TODO: implement trees_to_dataframe()
        """
        df = bst.trees_to_dataframe()

        # test for equality of gains
        gain_from_df = df[df.Feature != 'Leaf'][['Gain']].sum()
        assert np.allclose(gain_from_dump, gain_from_df)

        # test for equality of covers
        cover_from_df = df.Cover.sum()
        assert np.allclose(cover_from_dump, cover_from_df)
        """

