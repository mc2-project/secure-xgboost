mbedtls/programs/x509/cert_write selfsign=0 subject_key=userkeys/private_user_2.pem \
                    issuer_key=keypair.pem issuer_name=CN=securexgboost,O=riselab,C=NL \
                    subject_name=CN=user2,O=riselab,C=NL not_before=20130101000000 not_after=20251231235959 \
                    is_ca=0 max_pathlen=0 output_file=user2.crt