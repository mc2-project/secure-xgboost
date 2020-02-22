#include "ssl_attestation.h"
#include <stdio.h>
#include "xgboost/crypto.h"

// input: input_data and input_data_len
// output: key, key_size
oe_result_t generate_key_pair(
    uint8_t** public_key,
    size_t* public_key_size,
    uint8_t** private_key,
    size_t* private_key_size) {
  oe_result_t result = OE_FAILURE;
  oe_asymmetric_key_params_t params;
  char user_data[] = "XGBoost enclave";
  size_t user_data_size = sizeof(user_data) - 1;

  // Call oe_get_public_key_by_policy() to generate key pair derived from an
  // enclave's seal key If an enclave does not want to have this key pair tied
  // to enclave instance, it can generate its own key pair using any chosen
  // crypto API

  params.type = OE_ASYMMETRIC_KEY_EC_SECP256P1; // MBEDTLS_ECP_DP_SECP256R1
  params.format = OE_ASYMMETRIC_KEY_PEM;
  params.user_data = user_data;
  params.user_data_size = user_data_size;
  result = oe_get_public_key_by_policy(
      OE_SEAL_POLICY_UNIQUE,
      &params,
      public_key,
      public_key_size,
      NULL,
      NULL);
  if (result != OE_OK) {
    printf("oe_get_public_key_by_policy(OE_SEAL_POLICY_UNIQUE) = %s",
        oe_result_str(result));
    return result;
  }

  result = oe_get_private_key_by_policy(
      OE_SEAL_POLICY_UNIQUE,
      &params,
      private_key,
      private_key_size,
      NULL,
      NULL);
  if (result != OE_OK) {
    printf("oe_get_private_key_by_policy(OE_SEAL_POLICY_UNIQUE) = %s",
        oe_result_str(result));
    return result;
  }

  return result;
}

// Consider to move this function into a shared directory
oe_result_t generate_certificate_and_pkey(
    mbedtls_x509_crt* cert,
    mbedtls_pk_context* private_key) {
  oe_result_t result = OE_FAILURE;
  uint8_t* host_cert_buf = NULL;
  uint8_t* output_cert = NULL;
  size_t output_cert_size = 0;
  uint8_t* private_key_buf = NULL;
  size_t private_key_buf_size = 0;
  uint8_t* public_key_buf = NULL;
  size_t public_key_buf_size = 0;
  int ret = 0;

  result = generate_key_pair(
      &public_key_buf,
      &public_key_buf_size,
      &private_key_buf,
      &private_key_buf_size);
  if (result != OE_OK) {
    printf(" failed with %s\n", oe_result_str(result));
    goto exit;
  }

  // both ec key such ASYMMETRIC_KEY_EC_SECP256P1 or RSA key work
  result = oe_generate_attestation_certificate(
      (const unsigned char*)"CN=Open Enclave SDK,O=OESDK TLS,C=US",
      private_key_buf,
      private_key_buf_size,
      public_key_buf,
      public_key_buf_size,
      &output_cert,
      &output_cert_size);
  if (result != OE_OK) {
    printf(" failed with %s\n", oe_result_str(result));
    goto exit;
  }

  // create mbedtls_x509_crt from output_cert
  ret = mbedtls_x509_crt_parse_der(cert, output_cert, output_cert_size);
  if (ret != 0) {
    printf(" failed with ret = %d\n", ret);
    result = OE_FAILURE;
    goto exit;
  }

  // create mbedtls_pk_context from private key data
  ret = mbedtls_pk_parse_key(
      private_key,
      (const unsigned char*)private_key_buf,
      private_key_buf_size,
      NULL,
      0);
  if (ret != 0) {
    printf(" failed with ret = %d\n", ret);
    result = OE_FAILURE;
    goto exit;
  }

exit:
  oe_free_key(private_key_buf, private_key_buf_size, NULL, 0);
  oe_free_key(public_key_buf, public_key_buf_size, NULL, 0);
  oe_free_attestation_certificate(output_cert);
  return result;
}

bool verify_mrsigner(
    char* siging_public_key_buf,
    size_t siging_public_key_buf_size,
    uint8_t* signer_id_buf,
    size_t signer_id_buf_size) {
  mbedtls_pk_context ctx;
  mbedtls_pk_type_t pk_type;
  mbedtls_rsa_context* rsa_ctx = NULL;
  uint8_t* modulus = NULL;
  size_t modulus_size = 0;
  int res = 0;
  bool ret = false;
  unsigned char* signer = NULL;

  signer = (unsigned char*)malloc(signer_id_buf_size);
  if (signer == NULL) {
    printf("Out of memory\n");
    goto exit;
  }

  mbedtls_pk_init(&ctx);
  res = mbedtls_pk_parse_public_key(
      &ctx,
      (const unsigned char*)siging_public_key_buf,
      siging_public_key_buf_size);
  if (res != 0) {
    printf("mbedtls_pk_parse_public_key failed with %d\n", res);
    goto exit;
  }

  pk_type = mbedtls_pk_get_type(&ctx);
  if (pk_type != MBEDTLS_PK_RSA) {
    printf("mbedtls_pk_get_type had incorrect type: %d\n", res);
    goto exit;
  }

  rsa_ctx = mbedtls_pk_rsa(ctx);
  modulus_size = mbedtls_rsa_get_len(rsa_ctx);
  modulus = (uint8_t*)malloc(modulus_size);
  if (modulus == NULL) {
    printf("malloc for modulus failed with size %zu:\n", modulus_size);
    goto exit;
  }

  res = mbedtls_rsa_export_raw(
      rsa_ctx, modulus, modulus_size, NULL, 0, NULL, 0, NULL, 0, NULL, 0);
  if (res != 0) {
    printf("mbedtls_rsa_export failed with %d\n", res);
    goto exit;
  }

  // Reverse the modulus and compute sha256 on it.
  for (size_t i = 0; i < modulus_size / 2; i++) {
    uint8_t tmp = modulus[i];
    modulus[i] = modulus[modulus_size - 1 - i];
    modulus[modulus_size - 1 - i] = tmp;
  }

  // Calculate the MRSIGNER value which is the SHA256 hash of the
  // little endian representation of the public key modulus. This value
  // is populated by the signer_id sub-field of a parsed oe_report_t's
  // identity field.
  if (compute_sha256(modulus, modulus_size, signer) != 0) {
    goto exit;
  }

  if (memcmp(signer, signer_id_buf, signer_id_buf_size) != 0) {
    printf("mrsigner is not equal!\n");
    for (int i = 0; i < signer_id_buf_size; i++) {
      printf(
          "0x%x - 0x%x\n", (uint8_t)signer[i], (uint8_t)signer_id_buf[i]);
    }
    goto exit;
  }

  ret = true;

exit:
  if (signer)
    free(signer);

  if (modulus != NULL)
    free(modulus);

  mbedtls_pk_free(&ctx);
  return ret;
}

oe_result_t enclave_identity_verifier_callback(
    oe_identity_t* identity,
    void* arg) {
  oe_result_t result = OE_VERIFY_FAILED;
  bool bret = false;

#if false // FIXME verify MRENCLAVE
  // the unique ID for the enclave, for SGX enclaves, this is the MRENCLAVE value
  for (int i = 0; i < OE_UNIQUE_ID_SIZE; i++) {
    printf("0x%0x ", (uint8_t)identity->unique_id[i]);
    if (SERVER_ENCLAVE_MRENCLAVE[i] != (uint8_t)identity->unique_id[i]) {
      printf(
          "identity->unique_id[%d] expected: 0x%0x  found: 0x%0x ",
          i,
          SERVER_ENCLAVE_MRENCLAVE[i],
          (uint8_t)identity->unique_id[i]);
      printf(TLS_CLIENT "failed:unique_id not equal!\n");
      goto exit;
    }
  }
#endif

  // The signer ID for the enclave, for SGX enclaves, this is the MRSIGNER value
  if (!verify_mrsigner(
        (char*)ENCLAVE_PUBLIC_KEY,
        sizeof(ENCLAVE_PUBLIC_KEY),
        identity->signer_id,
        sizeof(identity->signer_id))) {
    printf( "failed:mrsigner not equal!\n");
    goto exit;
  }

  result = OE_OK;
exit:
  return result;
}

int cert_verify_callback(
    void* data,
    mbedtls_x509_crt* crt,
    int depth,
    uint32_t* flags) {
  oe_result_t result = OE_FAILURE;
  int ret = 1;
  unsigned char* cert_buf = NULL;
  size_t cert_size = 0;

  (void)data;

  cert_buf = crt->raw.p;
  cert_size = crt->raw.len;

  if (cert_size <= 0)
    return ret;

  result = oe_verify_attestation_certificate(
      cert_buf, cert_size, enclave_identity_verifier_callback, NULL);
  if (result != OE_OK) {
    printf(
        "oe_verify_attestation_certificate failed with result = %s\n",
        oe_result_str(result));
    return ret;
  }

  ret = 0;
  *flags = 0;

  return ret;
}
