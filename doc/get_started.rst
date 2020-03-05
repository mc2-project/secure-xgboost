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

Below is a snippet of the full Python demo located at :code:`mc2--xgboost/demo/python/basic/secure-xgboost-demo.py`. 

The snippet assumes that your machine supports hardware enclaves. If your machine doesn't have an enclave available, you can simulate an enclave (for development purposes) by setting the flag ``OE_ENCLAVE_FLAG_SIMULATE`` instead of ``OE_ENCLAVE_FLAG_RELEASE``. Look at lines 11-19 of ``secure-xgboost-demo.py`` for an example.

.. code-block:: python

   import securexgboost as xgb

   OE_ENCLAVE_FLAG_RELEASE = 0

   enclave = xgb.Enclave(HOME_DIR + "build/enclave/xgboost_enclave.signed", flags=(OE_ENCLAVE_FLAG_RELEASE))

   # Remote Attestation
   enclave.get_remote_report_with_pubkey()
   enclave.verify_remote_report_and_set_pubkey()

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


***************
Troubleshooting
***************

1. Remote attestation fails with error ``Failed to get quote enclave identity information. OE_QUOTE_PROVIDER_CALL_ERROR (oe_result_t=OE_QUOTE_PROVIDER_CALL_ERROR)``. 
   
   If you're using an ACC (Azure Confidential Computing) VM, this may be a sign of a ``dcap-client`` version issue. The ``dcap-client`` should be at least version 1.1. You can check your version by doing

   .. code-block:: bash

      user@accvm:~$ dpkg --list | grep dcap-client

      ii  az-dcap-client  1.1  amd64  Intel(R) SGX DCAP plugin for Azure Integration

   If the version is not at least 1.1, upgrade by doing the following.

   .. code-block:: bash

      curl https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
      sudo apt-add-repository https://packages.microsoft.com/ubuntu/18.04/prod
      sudo apt-get update
      sudo apt-get install az-dcap-client
