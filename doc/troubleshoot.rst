
###############################
Troubleshooting
###############################

#. **Can't find** ``<openenclave/host.h>`` **(no such file or directory)**.

   Please configure environment variables for Open Enclave SDK for Linux as described in the installation step:

   .. code-block:: bash

      source /opt/openenclave/share/openenclave/openenclaverc

   Consider adding this line to your ``~/.bashrc`` to make the environment variables persist across sessions.


#. **Remote attestation fails with error**: 

   ``Failed to get quote enclave identity information.``
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

#. **Failed to create enclave:** ``enclave_create with ENCLAVE_TYPE_SGX1 type failed``

   This error may be symptomatic of a machine that does not support Intel SGX. Check if your machine supports it by doing

   .. code-block:: bash

      oesgx

   If your machine doesn't support SGX, you can still use the library in simulation mode for local development and testing.

   Alternatively, this error may be symptomatic of an outdated DCAP driver. Check the version by doing

   .. code-block:: bash

      modinfo intel_sgx

   If the version is below 1.21, update the DCAP driver by following step 2 `here <https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/install_oe_sdk-Ubuntu_18.04.md>`_.
