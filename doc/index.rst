############################
Secure XGBoost Documentation
############################

**Secure XGBoost** is a secure gradient boosted decision tree library based off the popular `XGBoost <https://github.com/dmlc/xgboost>`_ project that supports scalable, distributed, and efficient `gradient boosting <https://en.wikipedia.org/wiki/Gradient_boosting>`_. In addition to offering the efficiency, flexibility, and portability that vanilla XGBoost does to solve a variety of problems, Secure XGBoost enables secure collaborative learning by leveraging `hardware enclaves <https://inst.eecs.berkeley.edu/~cs261/fa18/slides/Hardware_Enclaves.pdf>`_ and `oblivious algorithms <https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_ohrimenko.pdf>`_. This project allows multiple parties to each share their sensitive data to perform joint computation *without revealing the contents of the data*.

This project is currently under development as part of the broader `Multiparty Collaboration and Coopetition effort <https://github.com/mc2-project/mc2>`_ by the UC Berkeley `RISE Lab <https://rise.cs.berkeley.edu/>`_. 

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
