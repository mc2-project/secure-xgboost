########################
Get Started with Secure XGBoost
########################

This is a quick start tutorial showing snippets for you to quickly try out Secure XGBoost
on the demo dataset on a binary classification task. This sanity check ensures that setup was done properly. This quickstart uses encrypted versions of the :code:`agaricus.txt.train` and :code:`agaricus.txt.test` data files from :code:`demo/data/`.

********************************
Links to Other Helpful Resources
********************************
- See :doc:`Installation Guide </build>` on how to install Secure XGBoost.
- See :doc:`Text Input Format </tutorials/input_format>` on using text format for specifying training/testing data.

******
Python
******

Below is a snippet of the full Python demo located at :code:`secure-xgboost/demo/python/basic/secure-xgboost-demo.py`. 

Be sure that if your machine doesn't have an enclave available that you create an enclave in simulation mode. Look at lines 11-14 of ``secure-xgboost-demo.py`` for an example.

.. code-block:: python

   import securexgboost as xgb

   OE_ENCLAVE_FLAG_RELEASE = 0

   enclave = xgb.Enclave(HOME_DIR + "build/enclave/xgboost_enclave.signed", flags=(OE_ENCLAVE_FLAG_RELEASE))

   dtrain = xgb.DMatrix(HOME_DIR + "demo/data/agaricus.txt.train.enc", encrypted=True)
   dtest = xgb.DMatrix(HOME_DIR + "demo/data/agaricus.txt.test.enc", encrypted=True) 

   params = {
           "objective": "binary:logistic",
           "gamma": "0.1",
           "max_depth": "3"
   }

   num_rounds = 5 
   booster = xgb.train(params, dtrain, num_rounds, evals=[(dtrain, "train"), (dtest, "test")])

   # Get encrypted predictions
   predictions, num_preds = booster.predict(dtest)

   # Read the key used to encrypt data into memory
   key_file = open("key_zeros.txt", 'rb')
   sym_key = key_file.read() # The key will be type bytes
   key_file.close()

   # Decrypt predictions
   crypto.decrypt_predictions(sym_key, predictions, num_preds)

