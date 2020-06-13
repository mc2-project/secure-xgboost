import testing as tm
import numpy as np
import unittest
import pytest

import securexgboost as xgb
import os
from sklearn.datasets import dump_svmlight_file
from paths import sym_key_file, priv_key_file, cert_file

username = "user1"
HOME_DIR = os.path.dirname(os.path.realpath(__file__)) + "/../../"

temp_name_t = HOME_DIR + "demo/data/temp_file_t.txt.train"
temp_enc_name_t = HOME_DIR + "demo/data/temp_file_t.txt.train.enc"
temp_name_v = HOME_DIR + "demo/data/temp_file_v.txt.train"
temp_enc_name_v = HOME_DIR + "demo/data/temp_file_v.txt.train.enc"

#  xgb.init_client(user_name=username, sym_key_file=sym_key_file, priv_key_file=priv_key_file, cert_file=cert_file)
#  xgb.init_server(enclave_image=HOME_DIR + "build/enclave/xgboost_enclave.signed")
#  xgb.attest(verify=False)

dpath = HOME_DIR + 'demo/data/'
rng = np.random.RandomState(1337)


class TestEvalMetrics(unittest.TestCase):
    xgb_params_01 = {
        'verbosity': 0,
        'nthread': 1,
        'eval_metric': 'error'
    }

    xgb_params_02 = {
        'verbosity': 0,
        'nthread': 1,
        'eval_metric': ['error']
    }

    xgb_params_03 = {
        'verbosity': 0,
        'nthread': 1,
        'eval_metric': ['rmse', 'error']
    }

    xgb_params_04 = {
        'verbosity': 0,
        'nthread': 1,
        'eval_metric': ['error', 'rmse']
    }

    def evalerror_01(self, preds, dtrain):
        labels = dtrain.get_label()
        return 'error', float(sum(labels != (preds > 0.0))) / len(labels)

    def evalerror_02(self, preds, dtrain):
        labels = dtrain.get_label()
        return [('error', float(sum(labels != (preds > 0.0))) / len(labels))]

    @pytest.mark.skipif(**tm.no_sklearn())
    def evalerror_03(self, preds, dtrain):
        from sklearn.metrics import mean_squared_error

        labels = dtrain.get_label()
        return [('rmse', mean_squared_error(labels, preds)),
                ('error', float(sum(labels != (preds > 0.0))) / len(labels))]

    @pytest.mark.skipif(**tm.no_sklearn())
    def evalerror_04(self, preds, dtrain):
        from sklearn.metrics import mean_squared_error

        labels = dtrain.get_label()
        return [('error', float(sum(labels != (preds > 0.0))) / len(labels)),
                ('rmse', mean_squared_error(labels, preds))]

    @pytest.mark.skipif(**tm.no_sklearn())
    def test_eval_metrics(self):
        try:
            from sklearn.model_selection import train_test_split
        except ImportError:
            from sklearn.cross_validation import train_test_split
        from sklearn.datasets import load_digits

        digits = load_digits(2)
        X = digits['data']
        y = digits['target']

        Xt, Xv, yt, yv = train_test_split(X, y, test_size=0.2, random_state=0)

        dump_svmlight_file(Xt, yt, temp_name_t) 
        xgb.encrypt_file(temp_name_t, temp_enc_name_t, sym_key_file)
        dump_svmlight_file(Xv, yv, temp_name_v) 
        xgb.encrypt_file(temp_name_v, temp_enc_name_v, sym_key_file)
 
        dtrain = xgb.DMatrix({username: temp_enc_name_t})
        dvalid = xgb.DMatrix({username: temp_enc_name_v})

        watchlist = [(dtrain, 'train'), (dvalid, 'val')]

        gbdt_01 = xgb.train(self.xgb_params_01, dtrain, num_boost_round=10)
        gbdt_02 = xgb.train(self.xgb_params_02, dtrain, num_boost_round=10)
        gbdt_03 = xgb.train(self.xgb_params_03, dtrain, num_boost_round=10)
        assert all(gbdt_01.predict(dvalid)[0] == gbdt_02.predict(dvalid)[0])
        assert all(gbdt_01.predict(dvalid)[0] == gbdt_03.predict(dvalid)[0])

        #TODO(rishabh): implement early_stopping_rounds
        """
        gbdt_01 = xgb.train(self.xgb_params_01, dtrain, 10, watchlist,
                            early_stopping_rounds=2)
        gbdt_02 = xgb.train(self.xgb_params_02, dtrain, 10, watchlist,
                            early_stopping_rounds=2)
        gbdt_03 = xgb.train(self.xgb_params_03, dtrain, 10, watchlist,
                            early_stopping_rounds=2)
        gbdt_04 = xgb.train(self.xgb_params_04, dtrain, 10, watchlist,
                            early_stopping_rounds=2)
        assert gbdt_01.predict(dvalid)[0] == gbdt_02.predict(dvalid)[0]
        assert gbdt_01.predict(dvalid)[0] == gbdt_03.predict(dvalid)[0]
        assert gbdt_03.predict(dvalid)[0] != gbdt_04.predict(dvalid)[0]
        """

        #TODO(rishabh): implement early_stopping_rounds and feval
        """
        gbdt_01 = xgb.train(self.xgb_params_01, dtrain, 10, watchlist,
                            early_stopping_rounds=2, feval=self.evalerror_01)
        gbdt_02 = xgb.train(self.xgb_params_02, dtrain, 10, watchlist,
                            early_stopping_rounds=2, feval=self.evalerror_02)
        gbdt_03 = xgb.train(self.xgb_params_03, dtrain, 10, watchlist,
                            early_stopping_rounds=2, feval=self.evalerror_03)
        gbdt_04 = xgb.train(self.xgb_params_04, dtrain, 10, watchlist,
                            early_stopping_rounds=2, feval=self.evalerror_04)
        assert gbdt_01.predict(dvalid)[0] == gbdt_02.predict(dvalid)[0]
        assert gbdt_01.predict(dvalid)[0] == gbdt_03.predict(dvalid)[0]
        assert gbdt_03.predict(dvalid)[0] != gbdt_04.predict(dvalid)[0]
        """
