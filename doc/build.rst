##################
Installation Guide
##################

This page gives instructions on how to build and install Secure XGBoost from scratch. Secure XGBoost has been tested only on Ubuntu 18.04, but it should also work with Ubuntu 16.04. It consists of three steps:

1. First install the Open Enclave SDK
2. Next install the Secure XGBoost dependencies
3. Then build Secure XGBoost from source. 

.. Please refer to the :doc:`Troubleshooting <./troubleshoot.rst>` section first if you have any problem
Please refer to the :ref:`troubleshoot` section first if you have any problem
during installation. If the instructions do not work for you, please feel free
to open an issue on `GitHub <https://github.com/mc2-project/secure-xgboost/issues>`_.

**Contents**

* `Installing the Open Enclave SDK`_

* `Installing Secure XGBoost Dependencies`_

* `Building Secure XGBoost`_

  - `Building the Targets`_
  - `Python Package Installation`_

*******************************
Installing the Open Enclave SDK
*******************************

1. Install the Open Enclave SDK (v0.8.2) and the Intel SGX DCAP driver.  
   If building on an SGX-enabled machine, follow the instructions `here <https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/install_oe_sdk-Ubuntu_18.04.md>`_. 
   
   **Note**: In step 3 of the instructions, make sure that you install Open Enclave version 0.8.2 by specifying the version

   .. code-block:: bash

   sudo apt -y install clang-7 libssl-dev gdb libsgx-enclave-common libsgx-enclave-common-dev libprotobuf10 libsgx-dcap-ql libsgx-dcap-ql-dev az-dcap-client open-enclave=0.8.2   

   .. note:: You may also build the SDK in "simulation mode" on a machine without SGX support (e.g., for local development and testing). To build in simulation mode, follow the instructions `here <https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/install_oe_sdk-Simulation.md>`_ instead. Notably, these instructions require that you skip the driver installation step.


2. Configure environment variables for Open Enclave SDK for Linux:

   .. code-block:: bash

      source /opt/openenclave/share/openenclave/openenclaverc

   Consider adding this line to your ``~/.bashrc`` to make the environment variables persist across sessions.


3. Starting from version 0.8.2, the Open Enclave SDK supports mitigation against the `LVI vulnerability <https://software.intel.com/security-software-guidance/software-guidance/load-value-injection>`_ that affects SGX enclaves.

   To enable LVI mitigation, you need to additionally install LVI mitigated versions of the Open Enclave libraries. Follow the instructions for Linux prerequisites described `here <https://github.com/openenclave/openenclave/tree/0.8.2/samples/helloworld#build-and-run-with-lvi-mitigation>`_.

**************************************
Installing Secure XGBoost Dependencies 
**************************************

1. Install ``cmake >= v3.11``. E.g., the following commands install ``cmake v3.15.6``.

   .. code-block:: bash

      wget https://github.com/Kitware/CMake/releases/download/v3.15.6/cmake-3.15.6-Linux-x86_64.sh
      sudo bash cmake-3.15.6-Linux-x86_64.sh --skip-license --prefix=/usr/local

2. Install the remaining dependencies.

   .. code-block:: bash

      sudo apt-get install -y libmbedtls-dev python3-pip
      pip3 install numpy pandas sklearn numproto grpcio grpcio-tools kubernetes   


***********************
Building Secure XGBoost
***********************

Our goal is to build the shared library, along with the enclave:

- On Linux the target library is ``libxgboost.so``
- The target enclave is ``xgboost_enclave.signed``

The minimal building requirement is

- A recent C++ compiler supporting C++11 (g++-4.8 or higher)
- CMake 3.11 or higher

Building the Targets
==================

1. **Clone the repository recursively**:

   .. code-block:: bash

      git clone --recursive https://github.com/mc2-project/secure-xgboost.git

2. **Configure the build parameters listed in** ``CMakeLists.txt``. 

   * ``CLIENT_LIST``: This is a list of usernames of all parties in the collaboration. 
   * ``SIGNER_PUB_FILE``: Path to the file containing the enclave developer's public key. This is used during remote attestation to authenticate the enclaves.
   * ``SIGNER_KEY_FILE``: Path to the file containing the enclave developer's private key. This is used to sign the enclave while building it.
   * ``CA_CERT_FILE``: Path to the file containing the root certificate. Th enclaves use this certificate to authenticate the clients.

   In addition, the following parameters are used by Open Enclave to configure the enclave build.

   * ``OE_DEBUG``: Set this parameter to 0 to build the enclave in release mode, or 1 to build in debug mode.
   * ``OE_NUM_HEAP_PAGES``: The amount of heap memory (in pages) committed to the enclave; this is the maximum amount of heap memory available to your enclave application.
   * ``OE_NUM_STACK_PAGES``: The amount of stack memory (in pages) committed to the enclave.
   * ``OE_NUM_TCS``: The number of enclave thread control structures; this is the maximum number of concurrent threads that can execute within the enclave.
   * ``OE_PRODUCT_ID``: Enclave product ID.
   * ``OE_SECURITY_VERSION``: Enclave security version number.

   More details on these parameters can be found `here <https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/buildandsign.md#signing-the-enclave>`_.

   We also provide some additional configuration options:

   * ``LOGGING``: Set this parameter to ``ON`` to enable logging within the enclave. This parameter requires ``OE_DEBUG`` to be set to 1.
   * ``SIMULATE``: Set this parameter to ``ON`` to build the enclave in simulation mode (for local development and testing, in case your machine does not support hardware enclaves). This parameter requires ``OE_DEBUG`` to be set to 1.
   * ``OBLIVIOUS``: Set this parameter to ``ON`` to perform model training and inference using data-oblivious algorithms (to mitigate access-pattern based side-channel attacks).

   Finally, we also provide options to build the library with LVI mitigation.
   
   * ``LVI_MITIGATION``: Set this to ``ON`` to enable LVI mitigation. 
   * ``LVI_MITIGATION_BINDIR``: Set this variable to point to the location where you installed the LVI mitigated Open Enclave libraries.


3. **Build the Secure XGBoost targets**:

   .. code-block:: bash

      cd secure-xgboost
      mkdir -p build

      pushd build
      cmake ..
      make -j4
      popd

   Note that you can pass the configuration parameters as arguments to ``cmake`` without modifying ``CMakeLists.txt``. For example, to build with LVI mitigation, if you installed the LVI mitigated libraries at the location ``/opt/openenclave/lvi_mitigation_bin``, then you can run ``cmake`` as follows:

   .. code-block:: bash

      cmake -DLVI_MITIGATION=ON -DLVI_MITIGATION_BINDIR=/opt/openenclave/lvi_mitigation_bin ..


Python Package Installation
===========================

The Python package is located at ``python-package/``.

1. Install system-wide, which requires root permission:

   .. code-block:: bash

     cd python-package; sudo python3 setup.py install

.. note:: Re-compiling Secure XGBoost

  If you recompiled Secure XGBoost, then you need to reinstall it again to make the new library take effect.



