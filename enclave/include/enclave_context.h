#ifndef ENCLAVE_CONTEXT_H_
#define ENCLAVE_CONTEXT_H_

#include "xgboost_t.h"
#include "xgboost/crypto.h"

class EnclaveContext {
  // FIXME Embed root CA for clients

  private:
    mbedtls_ctr_drbg_context m_ctr_drbg_context;
    mbedtls_entropy_context m_entropy_context;
    mbedtls_pk_context m_pk_context;
    uint8_t m_public_key[CIPHER_PK_SIZE];
    uint8_t m_private_key[CIPHER_PK_SIZE];

    // FIXME use array of fixed length instead of vector
    //std::unordered_map<std::string, std::vector<uint8_t>> client_keys;
    uint8_t client_key[CIPHER_KEY_SIZE];
    bool client_key_is_set;

    EnclaveContext() {
      generate_public_key();
      client_key_is_set = false;
    }

  public:
    // Don't forget to declare these two. You want to make sure they
    // are unacceptable otherwise you may accidentally get copies of
    // your singleton appearing.
    EnclaveContext(EnclaveContext const&) = delete;
    void operator=(EnclaveContext const&) = delete;

    static EnclaveContext& getInstance() {
      static EnclaveContext instance;
      return instance;
    }

    uint8_t* get_public_key() {
      return m_public_key;
    }

    uint8_t* get_private_key() {
      return m_private_key;
    }

    //bool get_client_key(std::string fname, uint8_t* key) {
    //  std::unordered_map<std::string, std::vector<uint8_t>>::const_iterator iter = client_keys.find(fname);
    //
    //  if (iter == client_keys.end()) {
    //    memset(key, 0, CIPHER_KEY_SIZE);
    //    return false;
    //  } else {
    //    //memcpy(key, iter->second, CIPHER_KEY_SIZE);
    //    std::copy(iter->second.begin(), iter->second.end(), key);
    //    return true;
    //  }
    //}

    bool get_client_key(uint8_t* key) {
      if (client_key_is_set)
          memcpy(key, client_key, CIPHER_KEY_SIZE);
      else
          memset(key, 0, CIPHER_KEY_SIZE);
    }

    // FIXME verify client identity using root CA
    bool verifySignature(uint8_t* data, size_t data_len, uint8_t* signature, size_t sig_len) {
      mbedtls_pk_context _pk_context;

      unsigned char hash[32];
      int ret = 1;

      mbedtls_pk_init(&_pk_context);

      const char* key =  "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArzxQ9wZ8pwKYEs+XZ1aJ\n"
        "POur2Fm2AZhnev9hblLVAKUUcRijzieYLDrVoremwSNNoMtN1BED24yLBWJgaAli\n"
        "0IQsfalXkQQUHOTdfqc6fH0IqdENbKCVMiVfKZ+hLZmuNPVH373xtMT2k95yqExR\n"
        "wh6/4QRt/zHwUN+1FeumrM3TGB81ZjD5LDAr9AxhQVo17HuU94Nm5FDsCi/mumJ3\n"
        "9vgi3TWKPAPs0egUbdpzakDBO0gmS9R4FlOQf2ygv8t3Q9Lmv1gr4iXrw1+fyZbf\n"
        "vInXl8iUINK7imBUGffub1ALgsOuBVd5XomYYAsGdvmNovZu68Iqy2btwf9Bsgbi\n"
        "uwIDAQAB\n"
        "-----END PUBLIC KEY-----";

      if((ret = mbedtls_pk_parse_public_key(&_pk_context, (const unsigned char*) key, strlen(key) + 1)) != 0) {
        LOG(INFO) << "verification failed - Could not read key";
        LOG(INFO) << "verification failed - mbedtls_pk_parse_public_keyfile returned" << ret;
        return false;
      }

      if(!mbedtls_pk_can_do(&_pk_context, MBEDTLS_PK_RSA)) {
        LOG(INFO) << "verification failed - Key is not an RSA key";
        return false;
      }

      mbedtls_rsa_set_padding(mbedtls_pk_rsa(_pk_context), MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

      if((ret = compute_sha256(data, data_len, hash)) != 0) {
        LOG(INFO) << "verification failed -- Could not hash";
        return false;
      }

      if((ret = mbedtls_pk_verify(&_pk_context, MBEDTLS_MD_SHA256, hash, 0, signature, sig_len)) != 0) {
        LOG(INFO) << "verification failed -- mbedtls_pk_verify returned " << ret;
        return false;
      }

      return true;
    }

    bool decrypt_and_save_client_key(uint8_t* data, size_t data_len, uint8_t* signature, size_t sig_len) {
      if (!verifySignature(data, data_len, signature, sig_len)) {
        LOG(INFO) << "Signature verification failed";
        return false;
      }

      int res = 0;
      mbedtls_rsa_context* rsa_context;

      mbedtls_pk_rsa(m_pk_context)->len = data_len;
      rsa_context = mbedtls_pk_rsa(m_pk_context);
      rsa_context->padding = MBEDTLS_RSA_PKCS_V21;
      rsa_context->hash_id = MBEDTLS_MD_SHA256;

      size_t output_size;
      uint8_t output[CIPHER_KEY_SIZE];

      res = mbedtls_rsa_pkcs1_decrypt(
          rsa_context,
          mbedtls_ctr_drbg_random,
          &m_ctr_drbg_context,
          MBEDTLS_RSA_PRIVATE,
          &output_size,
          data,
          output,
          CIPHER_KEY_SIZE);
      if (res != 0) {
        LOG(INFO) << "mbedtls_rsa_pkcs1_decrypt failed with " << res;
        return false;
      }
      //fprintf(stdout, "Decrypted key\n");
      //for (int i = 0; i < CIPHER_KEY_SIZE; i++)
      //  fprintf(stdout, "%d\t", output[i]);
      //fprintf(stdout, "\n");
      std::vector<uint8_t> v(output, output + CIPHER_KEY_SIZE);
      //client_keys.insert({fname, v});
      memcpy(client_key, output, CIPHER_KEY_SIZE);
      client_key_is_set = true;
      return true;
    }

  private:
    /**
     * Generate an ephermeral public key pair for the enclave
     */
    bool generate_public_key() {
      mbedtls_ctr_drbg_init(&m_ctr_drbg_context);
      mbedtls_entropy_init(&m_entropy_context);
      mbedtls_pk_init(&m_pk_context);

      int res = -1;
      // Initialize entropy.
      res = mbedtls_ctr_drbg_seed(&m_ctr_drbg_context, mbedtls_entropy_func, &m_entropy_context, NULL, 0);
      if (res != 0) {
        LOG(INFO) << "mbedtls_ctr_drbg_seed failed.";
        return false;
      }

      // Initialize RSA context.
      res = mbedtls_pk_setup(&m_pk_context, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
      if (res != 0) {
        LOG(INFO) << "mbedtls_pk_setup failed " << res;
        return false;
      }

      // Generate an ephemeral 2048-bit RSA key pair with
      // exponent 65537 for the enclave.
      res = mbedtls_rsa_gen_key(
          mbedtls_pk_rsa(m_pk_context),
          mbedtls_ctr_drbg_random,
          &m_ctr_drbg_context,
          2048,
          65537);

      if (res != 0) {
        LOG(INFO) << "mbedtls_rsa_gen_key failed " << res;
        return false;
      }

      // Write out the public key in PEM format for exchange with other enclaves.
      res = mbedtls_pk_write_pubkey_pem(&m_pk_context, m_public_key, sizeof(m_public_key));
      if (res != 0) {
        LOG(INFO) << "mbedtls_pk_write_pubkey_pem failed " << res;
        return false;
      }

      // FIXME
      // Write out the private key in PEM format for exchange with other enclaves.
      //res = mbedtls_pk_write_key_pem(&m_pk_context, m_private_key, sizeof(m_private_key));
      //if (res != 0) {
      //  LOG(INFO) << "mbedtls_pk_write_pubkey_pem failed " << res;
      //  return false;
      //}
      //return true;
    }

  public:
    // Compute the sha256 hash of given data.
    int static compute_sha256(const uint8_t* data, size_t data_len, uint8_t sha256[32]) {
      int ret = 0;
      mbedtls_sha256_context ctx;

#define safe_sha(call) {                \
int ret = (call);                       \
if (ret) {                              \
  mbedtls_sha256_free(&ctx);            \
  return -1;                            \
}                                       \
}
      mbedtls_sha256_init(&ctx);
      safe_sha(mbedtls_sha256_starts_ret(&ctx, 0));
      safe_sha(mbedtls_sha256_update_ret(&ctx, data, data_len));
      safe_sha(mbedtls_sha256_finish_ret(&ctx, sha256));

      mbedtls_sha256_free(&ctx);
      return ret;
    }
};

#endif
