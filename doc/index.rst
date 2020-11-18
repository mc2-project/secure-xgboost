############################
Secure XGBoost Documentation
############################


Secure XGBoost is a library for **secure training and inference** of `XGBoost <https://github.com/dmlc/xgboost>`_ models.
It allows users to train models on their data in an untrusted cloud environment, while ensuring that the cloud provider only sees encrypted data.
In particular, it facilitates secure collaborative learning -- where mutually distrustful data owners can jointly train a model on their data, but without revealing their data to each other.

At its core, Secure XGBoost uses `secure hardware enclaves <https://en.wikipedia.org/wiki/Trusted_execution_environment>`_ (such as Intel SGX) to protect the data and computation even in the presence of a hostile cloud environment.
On top of the enclaves, we add a second layer of security that additionally protects the data and computation against a large class of side-channel attacks.
For a more in-depth technical overview, please check out our `blog post <https://towardsdatascience.com/secure-collaborative-xgboost-on-encrypted-data-ac7bc0ec7741>`_ or our `CCS PPMLP paper <https://arxiv.org/pdf/2010.02524.pdf>`_.


This project is currently under development as part of the broader `MC^2 project <https://github.com/mc2-project/mc2>`_ by the UC Berkeley `RISE Lab <https://rise.cs.berkeley.edu/>`_. 

Secure XGBoost is open source, and we welcome contributions to our work `here <https://github.com/mc2-project/secure-xgboost>`_. For questions, please `open an issue <https://github.com/mc2-project/secure-xgboost/issues>`_.

********
Contents
********

.. toctree::
  :maxdepth: 2
  :titlesonly:

  about
  build
  get_started
  tutorials/index
  parameter
  Python package <python/index>
  troubleshoot
