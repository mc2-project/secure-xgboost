mbedtls/programs/x509/cert_write selfsign=1 issuer_key=keypair.pem                    \
                         issuer_name=CN=securexgboost,O=riselab,C=NL        \
                         not_before=20130101000000 not_after=20251231235959   \
                         is_ca=1 max_pathlen=0 output_file=CA.crt
