SRC_COMPARE=security-demo.cc
TGT_COMPARE=security-demo

cc=g++
CFLAGS ?=-O3 -g
XGBOOST_ROOT ?=../..
INCLUDE_DIR=-I$(XGBOOST_ROOT)/include -I$(XGBOOST_ROOT)/dmlc-core/include -I$(XGBOOST_ROOT)/rabit/include
LIB_DIR=-L$(XGBOOST_ROOT)/build -L/usr/lib/x86_64-linux-gnu/
#LIB_DIR=-Wl,-rpath,$(XGBOOST_ROOT)/lib

SGX_CFLAGS = $(CFLAGS) -D__SGX__ -D__HOST__ $(shell pkg-config oehost-g++ --cflags)
SGX_LDFLAGS = $(shell pkg-config oehost-g++ --libs)


$(TGT_COMPARE): $(SGX_COMPARE) Makefile
	$(cc) $(SGX_CFLAGS) $(INCLUDE_DIR) $(LIB_DIR) -o $(TGT_COMPARE) $(SRC_COMPARE) -lxgboost -lmbedtls -lmbedcrypto $(SGX_LDFLAGS)

secure: $(TGT_COMPARE)
	LD_LIBRARY_PATH=$(XGBOOST_ROOT)/build ./$(TGT_COMPARE) ../../build/enclave/xgboost_enclave.signed

clean:
	rm -f $(TGT_COMPARE)
