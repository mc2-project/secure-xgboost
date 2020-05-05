###############################
Get Started with Secure XGBoost
###############################

This is a quick start tutorial showing snippets for you to quickly try out Secure XGBoost
on the demo dataset on a binary classification task. This sanity check ensures that setup was done properly. This quickstart uses encrypted versions of the :code:`agaricus.txt.train` and :code:`agaricus.txt.test` data files from :code:`demo/data/`.

********************************
Links to Other Helpful Resources
********************************
- See :doc:`Installation Guide </build>` on how to install Secure XGBoost.

******
Python
******

Below is a snippet of the full Python demo located at :code:`mc2-xgboost/demo/python/basic/secure-xgboost-demo.py`. 

Note: If you built Secure XGBoost in :ref:`simulation mode <Building the Targets>`, remote attestation will not work, as the simulated report will not generate a report. Consequently, report verification will not work, and you should ``verify=False`` when calling ``attest()``

.. code-block:: python

   import securexgboost as xgb

   xgb.init_user(username, sym_key_file, pub_key_file, cert_file)
   enclave = xgb.Enclave(HOME_DIR + "build/enclave/xgboost_enclave.signed")

   # Note: Simulation mode does not support attestation
   # pass in `verify=False` to attest()
   enclave.attest()
   enclave.add_key()

   dtrain = xgb.DMatrix({username: HOME_DIR + "demo/data/agaricus.txt.train.enc"})
   dtest = xgb.DMatrix({username: HOME_DIR + "demo/data/agaricus.txt.test.enc"})

   params = {
   "objective": "binary:logistic",
   "gamma": "0.1",
   "max_depth": "3"
   }

   num_rounds = 5 
   booster = xgb.train(params, dtrain, num_rounds, evals=[(dtrain, "train"), (dtest, "test")])

   # Get encrypted predictions
   predictions, num_preds = booster.predict(dtest)

   # Save model to a file
   booster.save_model(HOME_DIR + "/demo/python/basic/modelfile.model")

   # Get encrypted predictions
   predictions, num_preds = booster.predict(dtest, decrypt=False)

   # Decrypt predictions
   booster.decrypt_predictions(predictions, num_preds)


***************
Troubleshooting
***************

1. Remote attestation fails with error ``Failed to get quote enclave identity information.``
   ``OE_QUOTE_PROVIDER_CALL_ERROR (oe_result_t=OE_QUOTE_PROVIDER_CALL_ERROR)``. 
   
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
