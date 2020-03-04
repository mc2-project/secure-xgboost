../../../host/dmlc-core/tracker/dmlc-submit --log-level DEBUG --cluster ssh --host-file hosts.config --num-workers $1 --worker-memory 4g python3 distr-training.py
