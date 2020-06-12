import numpy as np
from scipy.sparse import csr_matrix
import os
import unittest
import itertools
import shutil
import urllib.request
import zipfile

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


def test_ranking_with_unweighted_data():
    Xrow = np.array([1, 2, 6, 8, 11, 14, 16, 17])
    Xcol = np.array([0, 0, 1, 1,  2,  2,  3,  3])
    X = csr_matrix((np.ones(shape=8), (Xrow, Xcol)), shape=(20, 4)).toarray()
    y = np.array([0.0, 1.0, 1.0, 0.0, 0.0,
                  0.0, 1.0, 0.0, 1.0, 0.0,
                  0.0, 1.0, 0.0, 0.0, 1.0,
                  0.0, 1.0, 1.0, 0.0, 0.0])

    dump_svmlight_file(X, y, temp_name) 
    xgb.encrypt_file(temp_name, temp_enc_name, sym_key_file)
 
    group = np.array([5, 5, 5, 5], dtype=np.uint)
    dtrain = xgb.DMatrix({username: temp_enc_name})
    #TODO(rishabh): implement set_group()
    """
    dtrain.set_group(group)

    params = {'eta': 1, 'tree_method': 'exact',
              'objective': 'rank:pairwise', 'eval_metric': ['auc', 'aucpr'],
              'max_depth': 1}
    evals_result = {}
    bst = xgb.train(params, dtrain, 10, evals=[(dtrain, 'train')],
                        evals_result=evals_result)
    auc_rec = evals_result['train']['auc']
    assert all(p <= q for p, q in zip(auc_rec, auc_rec[1:]))
    auc_rec = evals_result['train']['aucpr']
    assert all(p <= q for p, q in zip(auc_rec, auc_rec[1:]))
    """


def test_ranking_with_weighted_data():
    Xrow = np.array([1, 2, 6, 8, 11, 14, 16, 17])
    Xcol = np.array([0, 0, 1, 1,  2,  2,  3,  3])
    X = csr_matrix((np.ones(shape=8), (Xrow, Xcol)), shape=(20, 4)).toarray()
    y = np.array([0.0, 1.0, 1.0, 0.0, 0.0,
                  0.0, 1.0, 0.0, 1.0, 0.0,
                  0.0, 1.0, 0.0, 0.0, 1.0,
                  0.0, 1.0, 1.0, 0.0, 0.0])

    dump_svmlight_file(X, y, temp_name) 
    xgb.encrypt_file(temp_name, temp_enc_name, sym_key_file)
 
    weights = np.array([1.0, 2.0, 3.0, 4.0])

    group = np.array([5, 5, 5, 5], dtype=np.uint)
    #TODO(rishabh): implement weight, set_group()
    """
    dtrain = xgb.DMatrix({username: temp_enc_name}, weight=weights)
    dtrain.set_group(group)

    params = {'eta': 1, 'tree_method': 'exact',
              'objective': 'rank:pairwise', 'eval_metric': ['auc', 'aucpr'],
              'max_depth': 1}
    evals_result = {}
    bst = xgb.train(params, dtrain, 10, evals=[(dtrain, 'train')],
                        evals_result=evals_result)
    auc_rec = evals_result['train']['auc']
    assert all(p <= q for p, q in zip(auc_rec, auc_rec[1:]))
    auc_rec = evals_result['train']['aucpr']
    assert all(p <= q for p, q in zip(auc_rec, auc_rec[1:]))

    for i in range(1, 11):
        pred = bst.predict(dtrain, ntree_limit=i)
        # is_sorted[i]: is i-th group correctly sorted by the ranking predictor?
        is_sorted = []
        for k in range(0, 20, 5):
            ind = np.argsort(-pred[k:k+5])
            z = y[ind+k]
            is_sorted.append(all(i >= j for i, j in zip(z, z[1:])))
        # Since we give weights 1, 2, 3, 4 to the four query groups,
        # the ranking predictor will first try to correctly sort the last query group
        # before correctly sorting other groups.
        assert all(p <= q for p, q in zip(is_sorted, is_sorted[1:]))
    """


class TestRanking(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """
        Download and setup the test fixtures
        """
        from sklearn.datasets import load_svmlight_files
        # download the test data
        cls.dpath = 'demo/rank/'
        src = 'https://s3-us-west-2.amazonaws.com/xgboost-examples/MQ2008.zip'
        target = cls.dpath + '/MQ2008.zip'
        urllib.request.urlretrieve(url=src, filename=target)

        with zipfile.ZipFile(target, 'r') as f:
            f.extractall(path=cls.dpath)

        (x_train, y_train, qid_train, x_test, y_test, qid_test,
         x_valid, y_valid, qid_valid) = load_svmlight_files(
            (cls.dpath + "MQ2008/Fold1/train.txt",
             cls.dpath + "MQ2008/Fold1/test.txt",
             cls.dpath + "MQ2008/Fold1/vali.txt"),
            query_id=True, zero_based=False)
        # instantiate the matrices
        dump_svmlight_file(x_train, y_train, temp_name) 
        xgb.encrypt_file(temp_name, temp_enc_name, sym_key_file)
        cls.dtrain = xgb.DMatrix({username: temp_enc_name})

        dump_svmlight_file(x_valid, y_valid, temp_name) 
        xgb.encrypt_file(temp_name, temp_enc_name, sym_key_file)
        cls.dvalid = xgb.DMatrix({username: temp_enc_name})

        dump_svmlight_file(x_test, y_test, temp_name) 
        xgb.encrypt_file(temp_name, temp_enc_name, sym_key_file)
        cls.dtest = xgb.DMatrix({username: temp_enc_name})
        #TODO(rishabh): add support for set_group()
        """
        # set the group counts from the query IDs
        cls.dtrain.set_group([len(list(items))
                              for _key, items in itertools.groupby(qid_train)])
        cls.dtest.set_group([len(list(items))
                             for _key, items in itertools.groupby(qid_test)])
        cls.dvalid.set_group([len(list(items))
                              for _key, items in itertools.groupby(qid_valid)])
        # save the query IDs for testing
        cls.qid_train = qid_train
        cls.qid_test = qid_test
        cls.qid_valid = qid_valid

        # model training parameters
        cls.params = {'objective': 'rank:pairwise',
                      'booster': 'gbtree',
                      'eval_metric': ['ndcg']
                      }
        """

    @classmethod
    def tearDownClass(cls):
        """
        Cleanup test artifacts from download and unpacking
        :return:
        """
        os.remove(cls.dpath + "MQ2008.zip")
        shutil.rmtree(cls.dpath + "MQ2008")

    def test_training(self):
        """
        Train an XGBoost ranking model
        """
        # specify validations set to watch performance
        watchlist = [(self.dtest, 'eval'), (self.dtrain, 'train')]
        #TODO(rishabh): add support for early_stopping_rounds
        """
        bst = xgb.train(self.params, self.dtrain, num_boost_round=2500,
                            early_stopping_rounds=10, evals=watchlist)
        assert bst.best_score > 0.98
        """

    def test_cv(self):
        """
        Test cross-validation with a group specified
        """
        #TODO: add support for cv()
        """
        cv = xgb.cv(self.params, self.dtrain, num_boost_round=2500,
                        early_stopping_rounds=10, nfold=10, as_pandas=False)
        assert isinstance(cv, dict)
        self.assertSetEqual(set(cv.keys()), {'test-ndcg-mean', 'train-ndcg-mean', 'test-ndcg-std', 'train-ndcg-std'},
                            "CV results dict key mismatch")
        """

    def test_cv_no_shuffle(self):
        """
        Test cross-validation with a group specified
        """
        #TODO: add support for cv()
        """
        cv = xgb.cv(self.params, self.dtrain, num_boost_round=2500,
                        early_stopping_rounds=10, shuffle=False, nfold=10,
                        as_pandas=False)
        assert isinstance(cv, dict)
        assert len(cv) == 4
        """

    def test_get_group(self):
        """
        Retrieve the group number from the dmatrix
        """
        # test the new getter
        #TODO(rishabh): implement get_uint_info()
        """
        self.dtrain.get_uint_info('group_ptr')

        for d, qid in [(self.dtrain, self.qid_train),
                       (self.dvalid, self.qid_valid),
                       (self.dtest, self.qid_test)]:
            # size of each group
            group_sizes = np.array([len(list(items))
                                    for _key, items in itertools.groupby(qid)])
            # indexes of group boundaries
            group_limits = d.get_uint_info('group_ptr')
            assert len(group_limits) == len(group_sizes)+1
            assert np.array_equal(np.diff(group_limits), group_sizes)
            assert np.array_equal(
                group_sizes, np.diff(d.get_uint_info('group_ptr')))
            assert np.array_equal(group_sizes, np.diff(d.get_uint_info('group_ptr')))
            assert np.array_equal(group_limits, d.get_uint_info('group_ptr'))
        """
