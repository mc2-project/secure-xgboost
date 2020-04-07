# include
python3 tests/ci-build/lint.py xgboost cpp include/xgboost
python3 tests/ci-build/lint.py xgboost cpp include/enclave
python3 tests/ci-build/lint.py dmlc cpp include/dmlc --exclude_path include/dmlc/blockingconcurrentqueue.h include/dmlc/concurrentqueue.h include/dmlc/build_config.h include/dmlc/build_config_default.h
python3 tests/ci-build/lint.py rabit cpp include/rabit

# host
python3 tests/ci-build/lint.py xgboost cpp host/src/
python3 tests/ci-build/lint.py rabit cpp host/rabit
python3 tests/ci-build/lint.py dmlc cpp host/dmlc-core --exclude_path host/dmlc-core/include/dmlc/build_config.h

# enclave
python3 tests/ci-build/lint.py rabit cpp enclave/rabit
python3 tests/ci-build/lint.py dmlc cpp enclave/dmlc-core
python3 tests/ci-build/lint.py xgboost cpp enclave/ --exclude_path enclave/rabit enclave/dmlc-core

# demo
python3 tests/ci-build/lint.py xgboost cpp demo --exclude_path demo/osort-mem-trace/arr_*.h
