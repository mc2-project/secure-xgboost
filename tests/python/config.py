import os
import securexgboost as xgb

username = "user1"
HOME_DIR = os.path.dirname(os.path.realpath(__file__)) + "/../../"
sym_key_file = HOME_DIR + "demo/data/key_zeros.txt"
priv_key_file = HOME_DIR + "config/user1.pem"
cert_file = HOME_DIR + "config/user1.crt"

xgb.init_client(user_name=username, sym_key_file=sym_key_file, priv_key_file=priv_key_file, cert_file=cert_file)
xgb.init_server(enclave_image=HOME_DIR + "build/enclave/xgboost_enclave.signed", client_list=[username])
xgb.attest(verify=False)
