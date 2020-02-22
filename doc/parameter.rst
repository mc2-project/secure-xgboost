##################
XGBoost Parameters
##################
Before running XGBoost, we must set three types of parameters: general parameters, booster parameters and task parameters.

- **General parameters** relate to which booster we are using to do boosting, commonly tree or linear model
- **Booster parameters** depend on which booster you have chosen
- **Learning task parameters** decide on the learning scenario. For example, regression tasks may use different parameters with ranking tasks.

.. contents::
  :backlinks: none
  :local:

******************
General Parameters
******************
* ``silent`` [default=0] [Deprecated]

  - Deprecated.  Please use ``verbosity`` instead.

* ``verbosity`` [default=1]

  - Verbosity of printing messages.  Valid values are 0 (silent),
    1 (warning), 2 (info), 3 (debug).  Sometimes XGBoost tries to change
    configurations based on heuristics, which is displayed as warning message.
    If there's unexpected behaviour, please try to increase value of verbosity.

* ``disable_default_eval_metric`` [default=0]

  - Flag to disable default metric. Set to >0 to disable.

* ``num_pbuffer`` [set automatically by XGBoost, no need to be set by user]

  - Size of prediction buffer, normally set to number of training instances. The buffers are used to save the prediction results of last boosting step.

* ``num_feature`` [set automatically by XGBoost, no need to be set by user]

  - Feature dimension used in boosting, set to maximum dimension of the feature

Parameters for Tree Booster
===========================
* ``eta`` [default=0.3, alias: ``learning_rate``]

  - Step size shrinkage used in update to prevents overfitting. After each boosting step, we can directly get the weights of new features, and ``eta`` shrinks the feature weights to make the boosting process more conservative.
  - range: [0,1]

* ``gamma`` [default=0, alias: ``min_split_loss``]

  - Minimum loss reduction required to make a further partition on a leaf node of the tree. The larger ``gamma`` is, the more conservative the algorithm will be.
  - range: [0,∞]

* ``max_depth`` [default=6]

  - Maximum depth of a tree. Increasing this value will make the model more complex and more likely to overfit. 0 is only accepted in ``lossguided`` growing policy when tree_method is set as ``hist`` and it indicates no limit on depth. Beware that XGBoost aggressively consumes memory when training a deep tree.
  - range: [0,∞] (0 is only accepted in ``lossguided`` growing policy when tree_method is set as ``hist``)

* ``min_child_weight`` [default=1]

  - Minimum sum of instance weight (hessian) needed in a child. If the tree partition step results in a leaf node with the sum of instance weight less than ``min_child_weight``, then the building process will give up further partitioning. In linear regression task, this simply corresponds to minimum number of instances needed to be in each node. The larger ``min_child_weight`` is, the more conservative the algorithm will be.
  - range: [0,∞]

* ``max_delta_step`` [default=0]

  - Maximum delta step we allow each leaf output to be. If the value is set to 0, it means there is no constraint. If it is set to a positive value, it can help making the update step more conservative. Usually this parameter is not needed, but it might help in logistic regression when class is extremely imbalanced. Set it to value of 1-10 might help control the update.
  - range: [0,∞]

* ``subsample`` [default=1]

  - Subsample ratio of the training instances. Setting it to 0.5 means that XGBoost would randomly sample half of the training data prior to growing trees. and this will prevent overfitting. Subsampling will occur once in every boosting iteration.
  - range: (0,1]

* ``colsample_bytree``, ``colsample_bylevel``, ``colsample_bynode`` [default=1]
  - This is a family of parameters for subsampling of columns.
  - All ``colsample_by*`` parameters have a range of (0, 1], the default value of 1, and
    specify the fraction of columns to be subsampled.
  - ``colsample_bytree`` is the subsample ratio of columns when constructing each
    tree. Subsampling occurs once for every tree constructed.
  - ``colsample_bylevel`` is the subsample ratio of columns for each level. Subsampling
    occurs once for every new depth level reached in a tree. Columns are subsampled from
    the set of columns chosen for the current tree.
  - ``colsample_bynode`` is the subsample ratio of columns for each node
    (split). Subsampling occurs once every time a new split is evaluated. Columns are
    subsampled from the set of columns chosen for the current level.
  - ``colsample_by*`` parameters work cumulatively. For instance,
    the combination ``{'colsample_bytree':0.5, 'colsample_bylevel':0.5,
    'colsample_bynode':0.5}`` with 64 features will leave 8 features to choose from at
    each split.

* ``lambda`` [default=1, alias: ``reg_lambda``]

  - L2 regularization term on weights. Increasing this value will make model more conservative.

* ``alpha`` [default=0, alias: ``reg_alpha``]

  - L1 regularization term on weights. Increasing this value will make model more conservative.

* ``tree_method`` string [default= ``auto``]

  - The tree construction algorithm used in XGBoost. See description in the `reference paper <http://arxiv.org/abs/1603.02754>`_.
  - XGBoost supports ``hist`` and ``approx`` for distributed training and only support ``approx`` for external memory version.
  - Choices: ``auto``, ``exact``, ``approx``, ``hist``, ``gpu_exact``, ``gpu_hist``

    - ``auto``: Use heuristic to choose the fastest method.

      - For small to medium dataset, exact greedy (``exact``) will be used.
      - For very large dataset, approximate algorithm (``approx``) will be chosen.
      - Because old behavior is always use exact greedy in single machine,
        user will get a message when approximate algorithm is chosen to notify this choice.

    - ``exact``: Exact greedy algorithm.
    - ``approx``: Approximate greedy algorithm using quantile sketch and gradient histogram.
    - ``hist``: Fast histogram optimized approximate greedy algorithm. It uses some performance improvements such as bins caching.
    - ``gpu_exact``: GPU implementation of ``exact`` algorithm.
    - ``gpu_hist``: GPU implementation of ``hist`` algorithm.

* ``sketch_eps`` [default=0.03]

  - Only used for ``tree_method=approx``.
  - This roughly translates into ``O(1 / sketch_eps)`` number of bins.
    Compared to directly select number of bins, this comes with theoretical guarantee with sketch accuracy.
  - Usually user does not have to tune this.
    But consider setting to a lower number for more accurate enumeration of split candidates.
  - range: (0, 1)

* ``scale_pos_weight`` [default=1]

  - Control the balance of positive and negative weights, useful for unbalanced classes. A typical value to consider: ``sum(negative instances) / sum(positive instances)``. See :doc:`Parameters Tuning </tutorials/param_tuning>` for more discussion. Also, see Higgs Kaggle competition demo for examples: `R <https://github.com/dmlc/xgboost/blob/master/demo/kaggle-higgs/higgs-train.R>`_, `py1 <https://github.com/dmlc/xgboost/blob/master/demo/kaggle-higgs/higgs-numpy.py>`_, `py2 <https://github.com/dmlc/xgboost/blob/master/demo/kaggle-higgs/higgs-cv.py>`_, `py3 <https://github.com/dmlc/xgboost/blob/master/demo/guide-python/cross_validation.py>`_.

* ``updater`` [default= ``grow_colmaker,prune``]

  - A comma separated string defining the sequence of tree updaters to run, providing a modular way to construct and to modify the trees. This is an advanced parameter that is usually set automatically, depending on some other parameters. However, it could be also set explicitly by a user. The following updater plugins exist:

    - ``grow_colmaker``: non-distributed column-based construction of trees.
    - ``distcol``: distributed tree construction with column-based data splitting mode.
    - ``grow_histmaker``: distributed tree construction with row-based data splitting based on global proposal of histogram counting.
    - ``grow_local_histmaker``: based on local histogram counting.
    - ``grow_skmaker``: uses the approximate sketching algorithm.
    - ``sync``: synchronizes trees in all distributed nodes.
    - ``refresh``: refreshes tree's statistics and/or leaf values based on the current data. Note that no random subsampling of data rows is performed.
    - ``prune``: prunes the splits where loss < min_split_loss (or gamma).

  - In a distributed setting, the implicit updater sequence value would be adjusted to ``grow_histmaker,prune`` by default, and you can set ``tree_method`` as ``hist`` to use ``grow_histmaker``. 

* ``refresh_leaf`` [default=1]

  - This is a parameter of the ``refresh`` updater plugin. When this flag is 1, tree leafs as well as tree nodes' stats are updated. When it is 0, only node stats are updated.

* ``process_type`` [default= ``default``]

  - A type of boosting process to run.
  - Choices: ``default``, ``update``

    - ``default``: The normal boosting process which creates new trees.
    - ``update``: Starts from an existing model and only updates its trees. In each boosting iteration, a tree from the initial model is taken, a specified sequence of updater plugins is run for that tree, and a modified tree is added to the new model. The new model would have either the same or smaller number of trees, depending on the number of boosting iteratons performed. Currently, the following built-in updater plugins could be meaningfully used with this process type: ``refresh``, ``prune``. With ``process_type=update``, one cannot use updater plugins that create new trees.

* ``grow_policy`` [default= ``depthwise``]

  - Controls a way new nodes are added to the tree.
  - Currently supported only if ``tree_method`` is set to ``hist``.
  - Choices: ``depthwise``, ``lossguide``

    - ``depthwise``: split at nodes closest to the root.
    - ``lossguide``: split at nodes with highest loss change.

* ``max_leaves`` [default=0]

  - Maximum number of nodes to be added. Only relevant when ``grow_policy=lossguide`` is set.

* ``max_bin``, [default=256]

  - Only used if ``tree_method`` is set to ``hist``.
  - Maximum number of discrete bins to bucket continuous features.
  - Increasing this number improves the optimality of splits at the cost of higher computation time.

* ``predictor``, [default=``cpu_predictor``]

  - The type of predictor algorithm to use. Provides the same results but allows the use of GPU or CPU.

    - ``cpu_predictor``: Multicore CPU prediction algorithm.
    - ``gpu_predictor``: Prediction using GPU. Default when ``tree_method`` is ``gpu_exact`` or ``gpu_hist``.

* ``num_parallel_tree``, [default=1]
  - Number of parallel trees constructed during each iteration. This option is used to support boosted random forest.

************************
Learning Task Parameters
************************
Specify the learning task and the corresponding learning objective. The objective options are below:

* ``objective`` [default=reg:squarederror]

  - ``reg:squarederror``: regression with squared loss
  - ``reg:logistic``: logistic regression
  - ``binary:logistic``: logistic regression for binary classification, output probability
  - ``binary:logitraw``: logistic regression for binary classification, output score before logistic transformation
  - ``binary:hinge``: hinge loss for binary classification. This makes predictions of 0 or 1, rather than producing probabilities.
  - ``count:poisson`` --poisson regression for count data, output mean of poisson distribution

    - ``max_delta_step`` is set to 0.7 by default in poisson regression (used to safeguard optimization)

  - ``survival:cox``: Cox regression for right censored survival time data (negative values are considered right censored).
    Note that predictions are returned on the hazard ratio scale (i.e., as HR = exp(marginal_prediction) in the proportional hazard function ``h(t) = h0(t) * HR``).
  - ``multi:softmax``: set XGBoost to do multiclass classification using the softmax objective, you also need to set num_class(number of classes)
  - ``multi:softprob``: same as softmax, but output a vector of ``ndata * nclass``, which can be further reshaped to ``ndata * nclass`` matrix. The result contains predicted probability of each data point belonging to each class.
  - ``rank:pairwise``: Use LambdaMART to perform pairwise ranking where the pairwise loss is minimized
  - ``rank:ndcg``: Use LambdaMART to perform list-wise ranking where `Normalized Discounted Cumulative Gain (NDCG) <http://en.wikipedia.org/wiki/NDCG>`_ is maximized
  - ``rank:map``: Use LambdaMART to perform list-wise ranking where `Mean Average Precision (MAP) <http://en.wikipedia.org/wiki/Mean_average_precision#Mean_average_precision>`_ is maximized
  - ``reg:gamma``: gamma regression with log-link. Output is a mean of gamma distribution. It might be useful, e.g., for modeling insurance claims severity, or for any outcome that might be `gamma-distributed <https://en.wikipedia.org/wiki/Gamma_distribution#Applications>`_.
  - ``reg:tweedie``: Tweedie regression with log-link. It might be useful, e.g., for modeling total loss in insurance, or for any outcome that might be `Tweedie-distributed <https://en.wikipedia.org/wiki/Tweedie_distribution#Applications>`_.

* ``base_score`` [default=0.5]

  - The initial prediction score of all instances, global bias
  - For sufficient number of iterations, changing this value will not have too much effect.

* ``eval_metric`` [default according to objective]

  - Evaluation metrics for validation data, a default metric will be assigned according to objective (rmse for regression, and error for classification, mean average precision for ranking)
  - User can add multiple evaluation metrics. Python users: remember to pass the metrics in as list of parameters pairs instead of map, so that latter ``eval_metric`` won't override previous one
  - The choices are listed below:

    - ``rmse``: `root mean square error <http://en.wikipedia.org/wiki/Root_mean_square_error>`_
    - ``mae``: `mean absolute error <https://en.wikipedia.org/wiki/Mean_absolute_error>`_
    - ``logloss``: `negative log-likelihood <http://en.wikipedia.org/wiki/Log-likelihood>`_
    - ``error``: Binary classification error rate. It is calculated as ``#(wrong cases)/#(all cases)``. For the predictions, the evaluation will regard the instances with prediction value larger than 0.5 as positive instances, and the others as negative instances.
    - ``error@t``: a different than 0.5 binary classification threshold value could be specified by providing a numerical value through 't'.
    - ``merror``: Multiclass classification error rate. It is calculated as ``#(wrong cases)/#(all cases)``.
    - ``mlogloss``: `Multiclass logloss <http://scikit-learn.org/stable/modules/generated/sklearn.metrics.log_loss.html>`_.
    - ``auc``: `Area under the curve <http://en.wikipedia.org/wiki/Receiver_operating_characteristic#Area_under_curve>`_
    - ``aucpr``: `Area under the PR curve <https://en.wikipedia.org/wiki/Precision_and_recall>`_
    - ``ndcg``: `Normalized Discounted Cumulative Gain <http://en.wikipedia.org/wiki/NDCG>`_
    - ``map``: `Mean Average Precision <http://en.wikipedia.org/wiki/Mean_average_precision#Mean_average_precision>`_
    - ``ndcg@n``, ``map@n``: 'n' can be assigned as an integer to cut off the top positions in the lists for evaluation.
    - ``ndcg-``, ``map-``, ``ndcg@n-``, ``map@n-``: In XGBoost, NDCG and MAP will evaluate the score of a list without any positive samples as 1. By adding "-" in the evaluation metric XGBoost will evaluate these score as 0 to be consistent under some conditions.
    - ``poisson-nloglik``: negative log-likelihood for Poisson regression
    - ``gamma-nloglik``: negative log-likelihood for gamma regression
    - ``cox-nloglik``: negative partial log-likelihood for Cox proportional hazards regression
    - ``gamma-deviance``: residual deviance for gamma regression
    - ``tweedie-nloglik``: negative log-likelihood for Tweedie regression (at a specified value of the ``tweedie_variance_power`` parameter)

* ``seed`` [default=0]

  - Random number seed.

