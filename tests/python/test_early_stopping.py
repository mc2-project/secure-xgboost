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

temp_name = HOME_DIR + "demo/data/temp_file.txt"
temp_enc_name = HOME_DIR + "demo/data/temp_file.txt.enc"

xgb.init_client(user_name=username, sym_key_file=sym_key_file, priv_key_file=priv_key_file, cert_file=cert_file)
xgb.init_server(enclave_image=HOME_DIR + "build/enclave/xgboost_enclave.signed")
xgb.attest(verify=False)

rng = np.random.RandomState(1994)


class TestEarlyStopping(unittest.TestCase):

    @pytest.mark.skipif(**tm.no_sklearn())
    def evalerror(self, preds, dtrain):
        from sklearn.metrics import mean_squared_error

        labels = dtrain.get_label()
        return 'rmse', mean_squared_error(labels, preds)

    @staticmethod
    def assert_metrics_length(cv, expected_length):
        for key, value in cv.items():
          assert len(value) == expected_length

    @pytest.mark.skipif(**tm.no_sklearn())
    def test_cv_early_stopping(self):
        from sklearn.datasets import load_digits

        digits = load_digits(2)
        X = digits['data']
        y = digits['target']
        dump_svmlight_file(X, y, temp_name) 
        xgb.encrypt_file(temp_name, temp_enc_name, sym_key_file)
        dm = xgb.DMatrix({username: temp_enc_name})
        params = {'max_depth': 2, 'eta': 1, 'verbosity': 0,
                  'objective': 'binary:logistic'}

        #TODO(rishabh): implement cv()
        """
        cv = xgb.cv(params, dm, num_boost_round=10, nfold=10,
                    early_stopping_rounds=10)
        self.assert_metrics_length(cv, 10)
        cv = xgb.cv(params, dm, num_boost_round=10, nfold=10,
                    early_stopping_rounds=5)
        self.assert_metrics_length(cv, 3)
        cv = xgb.cv(params, dm, num_boost_round=10, nfold=10,
                    early_stopping_rounds=1)
        self.assert_metrics_length(cv, 1)

        cv = xgb.cv(params, dm, num_boost_round=10, nfold=10,
                    feval=self.evalerror, early_stopping_rounds=10)
        self.assert_metrics_length(cv, 10)
        cv = xgb.cv(params, dm, num_boost_round=10, nfold=10,
                    feval=self.evalerror, early_stopping_rounds=1)
        self.assert_metrics_length(cv, 5)
        cv = xgb.cv(params, dm, num_boost_round=10, nfold=10,
                    feval=self.evalerror, maximize=True,
                    early_stopping_rounds=1)
        self.assert_metrics_length(cv, 1)
        """

    @pytest.mark.skipif(**tm.no_sklearn())
    def test_cv_early_stopping_with_multiple_eval_sets_and_metrics(self):
        from sklearn.datasets import load_breast_cancer

        X, y = load_breast_cancer(return_X_y=True)
        dump_svmlight_file(X, y, temp_name) 
        xgb.encrypt_file(temp_name, temp_enc_name, sym_key_file)
        dm = xgb.DMatrix({username: temp_enc_name})
        params = {'objective':'binary:logistic'}

        metrics = [['auc'], ['error'], ['logloss'],
                   ['logloss', 'auc'], ['logloss', 'error'], ['error', 'logloss']]

        num_iteration_history = []

        # If more than one metrics is given, early stopping should use the last metric
        #TODO(rishabh): implement cv()
        """
        for i, m in enumerate(metrics):
            result = xgb.cv(params, dm, num_boost_round=1000, nfold=5, stratified=True,
                            metrics=m, early_stopping_rounds=20, seed=42)
            num_iteration_history.append(len(result))
            df = result['test-{}-mean'.format(m[-1])]
            # When early stopping is invoked, the last metric should be as best it can be.
            if m[-1] == 'auc':
                assert np.all(df <= df.iloc[-1])
            else:
                assert np.all(df >= df.iloc[-1])
        assert num_iteration_history[:3] == num_iteration_history[3:]
        """
