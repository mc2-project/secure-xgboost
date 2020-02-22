#ifndef RABIT_SSL_ATTESTATION_H_
#define RABIT_SSL_ATTESTATION_H_

#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509_crt.h>
#include <openenclave/enclave.h>
#include <xgboost/attestation.h>

oe_result_t generate_certificate_and_pkey(
        mbedtls_x509_crt* cert,
        mbedtls_pk_context* private_key);

int cert_verify_callback(
        void* data,
        mbedtls_x509_crt* crt,
        int depth,
        uint32_t* flags);

#endif
