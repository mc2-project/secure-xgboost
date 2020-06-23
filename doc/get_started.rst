###############################
Get Started with Secure XGBoost
###############################

This is a quick start tutorial showing snippets for you to quickly try out Secure XGBoost
on the demo dataset on a binary classification task. This sanity check ensures that setup was done properly. This quickstart uses encrypted versions of the :code:`agaricus.txt.train` and :code:`agaricus.txt.test` data files from :code:`demo/data/`.

************
Encrypt data
************

Secure XGBoost currently only supports data ingestion from text files. It supports two file formats: LibSVM and CSV files. See the original XGBoost documentation for more details on the input format for these file types, `here <https://xgboost.readthedocs.io/en/latest/tutorials/input_format.html>`_.

The following snippet shows how clients can generate a symmetric key and use it to encrypt their data files.

.. code-block:: python

   import securexgboost as xgb

   KEY_FILE = "key.txt"
   xgb.generate_client_key(KEY_FILE)
   xgb.encrypt_file("demo/data/agaricus.txt.train", "demo/data/train.enc", KEY_FILE)
   xgb.encrypt_file("demo/data/agaricus.txt.test", "demo/data/test.enc", KEY_FILE)

***********************************
Train a model on the encrypted data
***********************************

Below is a snippet of the full Python demo located at :code:`secure-xgboost/demo/python/basic/secure-xgboost-demo.py`. 
This demo runs the enclave server on the same machine as the client for simplicity.

.. note:: If you built Secure XGBoost in :ref:`simulation mode <Building the Targets>`, remote attestation will not work, as the simulated enclave will not generate a report. Consequently, report verification will not work, and you should set ``verify=False`` when calling ``attest()``.

.. code-block:: python

   import securexgboost as xgb

   # Initialize client and connect to enclave
   xgb.init_client(user_name="user1",
                   sym_key_file="demo/data/key_zeros.txt",
                   priv_key_file="config/user1.pem",
                   cert_file="config/user1.crt")
   xgb.init_server(enclave_image="build/enclave/xgboost_enclave.signed")
   # Remote Attestation
   xgb.attest()

   # Load the encrypted data remotely
   dtrain = xgb.DMatrix({"user1": "demo/data/agaricus.txt.train.enc"})
   dtest = xgb.DMatrix({"user1": "demo/data/agaricus.txt.test.enc"})

   params = {
      "objective": "binary:logistic",
      "gamma": "0.1",
      "max_depth": "3"
   }

   # Train a model remotely
   num_rounds = 5 
   booster = xgb.train(params, dtrain, num_rounds, evals=[(dtrain, "train"), (dtest, "test")])

   # Get encrypted predictions and decrypt them locally
   predictions, num_preds = booster.predict(dtest)

