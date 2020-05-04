Python API Reference
====================
This page gives the Python API reference of xgboost, please also refer to Python Package Introduction for more information about python package.

.. contents::
  :backlinks: none
  :local:

Core Data Structure
-------------------
.. automodule:: securexgboost.core

.. autoclass:: securexgboost.DMatrix
    :members:
    :show-inheritance:

.. autoclass:: securexgboost.Booster
    :members:
    :show-inheritance:

.. autoclass:: securexgboost.Enclave
    :members:
    :show-inheritance:

.. autoclass:: securexgboost.CryptoUtils
    :members:
    :show-inheritance:

Learning API
------------
.. automodule:: securexgboost.training

.. autofunction:: securexgboost.train
.. 
.. .. autofunction:: xgboost.cv
.. 
.. 
.. Scikit-Learn API
.. ----------------
.. .. automodule:: xgboost.sklearn
.. .. autoclass:: xgboost.XGBRegressor
    .. :members:
    .. :inherited-members:
    .. :show-inheritance:
.. .. autoclass:: xgboost.XGBClassifier
    .. :members:
    .. :inherited-members:
    .. :show-inheritance:
.. .. autoclass:: xgboost.XGBRanker
    .. :members:
    .. :inherited-members:
    .. :show-inheritance:
.. 
.. Plotting API
.. ------------
.. .. automodule:: xgboost.plotting
.. 
.. .. autofunction:: xgboost.plot_importance
.. 
.. .. autofunction:: xgboost.plot_tree
.. 
.. .. autofunction:: xgboost.to_graphviz
.. 
.. .. _callback_api:
.. 
.. Callback API
.. ------------
.. .. autofunction:: xgboost.callback.print_evaluation
.. 
.. .. autofunction:: xgboost.callback.record_evaluation
.. 
.. .. autofunction:: xgboost.callback.reset_learning_rate
.. 
.. .. autofunction:: xgboost.callback.early_stop
