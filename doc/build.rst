##################
Installation Guide
##################

****************************
Building XGBoost from source
****************************
This page gives instructions on how to build and install Secure XGBoost from scratch. Secure XGBoost has been tested only on Ubuntu 18.04, but it should also work with Ubuntu 16.04. It consists of four steps:

1. First install the Open Enclave SDK
2. Next install the Secure XGBoost dependencies
3. Then build the shared library from the C++ codes (``libxgboost.so``). 
4. Lastly, install the Python package.

.. note:: Use of Git submodules

  XGBoost uses Git submodules to manage dependencies. So when you clone the repo, remember to specify ``--recursive`` option:

  .. code-block:: bash

   git clone -b hackathon --recursive https://github.com/mc2-project/secure-xgboost.git

Please refer to `Trouble Shooting`_ section first if you have any problem
during installation. If the instructions do not work for you, please feel free
to ask questions at `the user forum <https://discuss.xgboost.ai>`_.

**Contents**

* `Installing the Open Enclave SDK`_

* `Installing Secure XGBoost Dependencies`_

* `Building the Shared Library`_

  - `Building on Ubuntu`_

* `Python Package Installation`_
* `Trouble Shooting`_

*******************************
Installing the Open Enclave SDK
*******************************

Follow the instructions `here <https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/install_oe_sdk-Ubuntu_18.04.md>`_. You may also acquire a VM with the required features from `Azure Confidential Compute <https://azure.microsoft.com/en-us/solutions/confidential-compute/>`_; in this case, however, you may need to manually upgrade the SDK installed in the VM to version 0.7:

.. code-block:: bash

   sudo apt -y install open-enclave

Configure environment variables for Open Enclave SDK for Linux:

.. code-block:: bash

   source /opt/openenclave/share/openenclave/openenclaverc


**************************************
Installing Secure XGBoost Dependencies 
**************************************

.. code-block:: bash

   sudo apt-get install -y libmbedtls-dev python3-pip
   pip3 install numpy pandas sklearn numproto grpcio grpcio-tools kubernetes   

Install cmake >= v3.11. E.g., the following commands install cmake v3.15.6.

.. code-block:: bash

   wget https://github.com/Kitware/CMake/releases/download/v3.15.6/cmake-3.15.6-Linux-x86_64.sh
   sudo bash cmake-3.15.6-Linux-x86_64.sh --skip-license --prefix=/usr/local

***************************
Building the Shared Library
***************************

Our goal is to build the shared library:

- On Linux the target library is ``libxgboost.so``

The minimal building requirement is

- A recent C++ compiler supporting C++11 (g++-4.8 or higher)
- CMake 3.11 or higher

Building on Ubuntu
==================

On Ubuntu, one builds XGBoost by running CMake:

.. code-block:: bash
   
   git clone --recursive https://github.com/mc2-project/mc2-xgboost.git
   cd secure-xgboost
   mkdir -p build

   pushd build
   cmake ..
   make -j4
   popd

Python Package Installation
===========================

The Python package is located at ``python-package/``.

1. Install system-wide, which requires root permission:

.. code-block:: bash

  cd python-package; sudo python3 setup.py install

.. note:: Re-compiling Secure XGBoost

  If you recompiled Secure XGBoost, then you need to reinstall it again to make the new library take effect.

2. Set the environment variable ``PYTHONPATH`` to tell Python where to find
   the RPC library. For example, assume we cloned ``secure-xgboost`` on the home directory
   ``~``. then we can added the following line in ``~/.bashrc``.

.. code-block:: bash

   export PYTHONPATH=/path/to/mc2-xgboost/rpc


Trouble Shooting
================

1. Compile failed after ``git pull``

   Please first update the submodules, clean all and recompile:

   .. code-block:: bash

     git submodule update && make clean_all && make -j4

2. ``Makefile: dmlc-core/make/dmlc.mk: No such file or directory``

   We need to recursively clone the submodule:

   .. code-block:: bash

     git submodule init
     git submodule update

   Alternatively, do another clone

   .. code-block:: bash
      
      git clone --recursive https://github.com/mc2-project/secure-xgboost.git
