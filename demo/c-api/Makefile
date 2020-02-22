SRC=c-api-demo.cc
TGT=c-api-demo
TGT_SGX=c-api-demo-sgx
TGT_ENC=c-api-demo-enc

cc=g++
CFLAGS ?=-O3 -g
XGBOOST_ROOT ?=../..
INCLUDE_DIR=-I$(XGBOOST_ROOT)/include -I$(XGBOOST_ROOT)/dmlc-core/include -I$(XGBOOST_ROOT)/rabit/include
LIB_DIR=-L$(XGBOOST_ROOT)/build -L/usr/lib/x86_64-linux-gnu/
#LIB_DIR=-Wl,-rpath,$(XGBOOST_ROOT)/lib

SGX_SRC = $(SRC) # encrypt.cc encrypt.h
SGX_CFLAGS = $(CFLAGS) -D__SGX__ -D__HOST__ $(shell pkg-config oehost-g++ --cflags)
SGX_LDFLAGS = $(shell pkg-config oehost-g++ --libs)

$(TGT): $(SRC) Makefile
	$(cc) $(CFLAGS) $(INCLUDE_DIR) $(LIB_DIR) -o $(TGT) $(SRC) -lxgboost $(LDFLAGS)

$(TGT_SGX): $(SGX_SRC) Makefile
	$(cc) $(SGX_CFLAGS) $(INCLUDE_DIR) $(LIB_DIR) -o $(TGT_SGX) $(SGX_SRC) -lxgboost -lmbedtls -lmbedcrypto $(SGX_LDFLAGS)

build: $(TGT)

run: $(TGT)
	LD_LIBRARY_PATH=$(XGBOOST_ROOT)/build ./$(TGT)

sgx: $(TGT_SGX)
	LD_LIBRARY_PATH=$(XGBOOST_ROOT)/build ./$(TGT_SGX) ../../build/enclave/xgboost_enclave.signed

debug: $(TGT_SGX)
	LD_LIBRARY_PATH=$(XGBOOST_ROOT)/build /opt/openenclave/bin/oegdb -arg ./$(TGT_SGX) ../../build/enclave/xgboost_enclave.signed --simulate

simulate: $(TGT_SGX)
	LD_LIBRARY_PATH=$(XGBOOST_ROOT)/build:/usr/lib/x86_64-linux-gnu/ ./$(TGT_SGX) ../../build/enclave/xgboost_enclave.signed --simulate

encrypt: $(TGT_SGX)
	LD_LIBRARY_PATH=$(XGBOOST_ROOT)/build:/usr/lib/x86_64-linux-gnu/ ./$(TGT_SGX) ../../build/enclave/xgboost_enclave.signed --encrypt

clean:
	rm -f $(TGT) $(TGT_SGX)
