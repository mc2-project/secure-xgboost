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

Below is a snippet of the full Python demo located at :code:`mc2-xgboost/demo/python/basic/secure-xgboost-demo.py`. 

If your machine doesn't have hardware enclave support, then you can simulate an enclave (for development purposes) by setting the variables ``OE_DEBUG=1`` and  ``SIMULATE=ON`` while building the project (by modifying the root ``CMakeLists.txt`` file). However, note that remote attestation primitives are not supported in simulation mode, and the remote attestation APIs used below simply return dummy values instead of generating a valid attestation report. As a result, verification of the report will fail in simulation mode.

.. code-block:: python

   import securexgboost as xgb

   enclave = xgb.Enclave(HOME_DIR + "build/enclave/xgboost_enclave.signed")

   # Remote Attestation
   enclave.get_remote_report_with_pubkey()
   # Note: Verification will fail in simulation mode
   # Comment out this line if running in simulation mode
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

2. ``enclave_create with ENCLAVE_TYPE_SGX1 type failed``

   This error may be symptomatic of a machine that does not support Intel SGX. Check if your machine supports it by doing

   .. code-block:: bash

      oesgx

   If your machine doesn't support SGX, you can still use the library in simulation mode for local development and testing.

   Alternatively, this error may be symptomatic of an outdated DCAP driver. Check the version by doing

   .. code-block:: bash

      modinfo intel_sgx

   If the version is below 1.21, update the DCAP driver by following step 2 `here <https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/install_oe_sdk-Ubuntu_18.04.md>`_.
