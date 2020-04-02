#ifndef ENCLAVE_CONTEXT_H_
#define ENCLAVE_CONTEXT_H_

#include "xgboost_t.h"
#include <enclave/crypto.h>

// needed for certificate
#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"


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

    // map username to client_key
    std::unordered_map<std::string, std::vector<uint8_t>> client_keys;

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

    bool get_client_key(uint8_t* key, char *username) {

      // returning the key held by user
      LOG(INFO) << "User requested username " << username;
      if (client_keys.count(username) > 0){
        memcpy(key,(uint8_t *) &client_keys[CharPtrToString(username)][0], CIPHER_KEY_SIZE);
      }
      else
      {
        LOG(INFO) << "User " << username << " does not exist, using zero key instead";
        memset(key, 0, CIPHER_KEY_SIZE);
      }
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

    void sync_client_key() {
      // The master node (rank 0) broadcasts the client key to other nodes
      rabit::Broadcast(client_key, CIPHER_KEY_SIZE, 0);
      client_key_is_set = true;
    }

    bool decrypt_and_save_client_key(uint8_t* data, size_t data_len, uint8_t* signature, size_t sig_len) {
      if (rabit::GetRank() == 0) {
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
        std::vector<uint8_t> v(output, output + CIPHER_KEY_SIZE);
        memcpy(client_key, output, CIPHER_KEY_SIZE);
        client_key_is_set = true;
      }
      sync_client_key();
      return true;
    }



    bool verifySignatureWithCertificate(char* cert,
                int cert_len,
                uint8_t* data,
                size_t data_len,
                uint8_t* signature,
                size_t sig_len) {
      mbedtls_pk_context _pk_context;

      unsigned char hash[32];
      int ret = 1;

      mbedtls_pk_init(&_pk_context);

      const char* rootkey =  "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArzxQ9wZ8pwKYEs+XZ1aJ\n"
        "POur2Fm2AZhnev9hblLVAKUUcRijzieYLDrVoremwSNNoMtN1BED24yLBWJgaAli\n"
        "0IQsfalXkQQUHOTdfqc6fH0IqdENbKCVMiVfKZ+hLZmuNPVH373xtMT2k95yqExR\n"
        "wh6/4QRt/zHwUN+1FeumrM3TGB81ZjD5LDAr9AxhQVo17HuU94Nm5FDsCi/mumJ3\n"
        "9vgi3TWKPAPs0egUbdpzakDBO0gmS9R4FlOQf2ygv8t3Q9Lmv1gr4iXrw1+fyZbf\n"
        "vInXl8iUINK7imBUGffub1ALgsOuBVd5XomYYAsGdvmNovZu68Iqy2btwf9Bsgbi\n"
        "uwIDAQAB\n"
        "-----END PUBLIC KEY-----";

      const char* CA_cert = "-----BEGIN CERTIFICATE-----\n"
          "MIIDPDCCAiSgAwIBAgIBATANBgkqhkiG9w0BAQsFADA3MRYwFAYDVQQDDA1zZWN1\n"
          "cmV4Z2Jvb3N0MRAwDgYDVQQKDAdyaXNlbGFiMQswCQYDVQQGEwJOTDAeFw0xMzAx\n"
          "MDEwMDAwMDBaFw0yNTEyMzEyMzU5NTlaMDcxFjAUBgNVBAMMDXNlY3VyZXhnYm9v\n"
          "c3QxEDAOBgNVBAoMB3Jpc2VsYWIxCzAJBgNVBAYTAk5MMIIBIjANBgkqhkiG9w0B\n"
          "AQEFAAOCAQ8AMIIBCgKCAQEArzxQ9wZ8pwKYEs+XZ1aJPOur2Fm2AZhnev9hblLV\n"
          "AKUUcRijzieYLDrVoremwSNNoMtN1BED24yLBWJgaAli0IQsfalXkQQUHOTdfqc6\n"
          "fH0IqdENbKCVMiVfKZ+hLZmuNPVH373xtMT2k95yqExRwh6/4QRt/zHwUN+1Feum\n"
          "rM3TGB81ZjD5LDAr9AxhQVo17HuU94Nm5FDsCi/mumJ39vgi3TWKPAPs0egUbdpz\n"
          "akDBO0gmS9R4FlOQf2ygv8t3Q9Lmv1gr4iXrw1+fyZbfvInXl8iUINK7imBUGffu\n"
          "b1ALgsOuBVd5XomYYAsGdvmNovZu68Iqy2btwf9BsgbiuwIDAQABo1MwUTAPBgNV\n"
          "HRMECDAGAQH/AgEAMB0GA1UdDgQWBBQsyoN7J2skAO4oDOLrFCA1QarjjDAfBgNV\n"
          "HSMEGDAWgBQsyoN7J2skAO4oDOLrFCA1QarjjDANBgkqhkiG9w0BAQsFAAOCAQEA\n"
          "KkN+iohzbT97qz2DwlpQywVkz5t6Z0mZsTVexNObPsylEi4hz3mj2NHsgr8BNEdl\n"
          "nLpOeDaFKs44giavKUPOfvREU2RiDm0lwLkWNVY232s/3YxXlUSGGONQtfJbOf9D\n"
          "YQVCUi1twlLyFq5ZaBeBrKras7MCimKhZxUvPf6c99myBGsSkjH15UzX90bQev/q\n"
          "tTStoaXW4CfAhz385U8PffADBpdOHqW8wpOh54juyPGK6UsQUKtVuxDeb3kzS6PM\n"
          "wGfqCp4LSbJ0UQr2FTnI29qlS9LQqh1fdNhcrnMZ5iw6klPO+ZLAMyjpBXzVnDU7\n"
          "ko6CD0TAPKr7JWDfUPSP/g==\n"
          "-----END CERTIFICATE-----";

      printf("print usable??");
      mbedtls_x509_crt _cacert;
      mbedtls_x509_crt_init(&_cacert);
      if ((ret = mbedtls_x509_crt_parse(&_cacert, (const unsigned char *) CA_cert,
                   strlen(CA_cert)+1)) != 0) {
         LOG(INFO) << "verification failed - Could not read root certificate";
         LOG(INFO) << "verification failed - mbedtls_x509_crt_parse returned" << ret;
         printf("parse failed");
         return false;
}

      mbedtls_x509_crt user_cert;
      mbedtls_x509_crt_init(&user_cert);
      if ((ret = mbedtls_x509_crt_parse(&user_cert, (const unsigned char *) cert,
                   cert_len+1)) != 0) {
         LOG(INFO) << "verification failed - Could not read user certificate";
         LOG(INFO) << "verification failed - mbedtls_x509_crt_parse returned" << ret;
         return false;
      }

      uint32_t result;
      mbedtls_x509_crt_verify(&user_cert, &_cacert, NULL, NULL, &result, NULL, NULL);
      if (result!=0){
        LOG(INFO) << "verification failed - mbedtls_x509_crt_verify returned" << result;
        return false;
      }

      mbedtls_pk_context user_public_key_context = user_cert.pk;

      if(!mbedtls_pk_can_do(&user_public_key_context, MBEDTLS_PK_RSA)) {
        LOG(INFO) << "verification failed - Key is not an RSA key";
        return false;
      }

      mbedtls_rsa_set_padding(mbedtls_pk_rsa(user_public_key_context), MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

      if((ret = compute_sha256(data, data_len, hash)) != 0) {
        LOG(INFO) << "verification failed -- Could not hash";
        return false;
      }

      if((ret = mbedtls_pk_verify(&user_public_key_context, MBEDTLS_MD_SHA256, hash, 0, signature, sig_len)) != 0) {
        LOG(INFO) << "verification failed -- mbedtls_pk_verify returned " << ret;
        return false;
      }

      return true;
    }

    bool decrypt_and_save_client_key_with_certificate(char * cert,
            int cert_len,
            uint8_t* data,
            size_t data_len,
            uint8_t* signature,
            size_t sig_len) {
      if (!verifySignatureWithCertificate(cert,cert_len,data,data_len,signature,sig_len)) {
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

      mbedtls_x509_crt user_cert;
      mbedtls_x509_crt_init(&user_cert);
      int ret;
      if ((ret = mbedtls_x509_crt_parse(&user_cert, (const unsigned char *) cert,
                   cert_len+1)) != 0) {
         LOG(INFO) << "verification failed - Could not read user certificate";
         LOG(INFO) << "verification failed - mbedtls_x509_crt_parse returned" << ret;
         return false;
      }

      mbedtls_x509_name subject_name = user_cert.subject;
      mbedtls_asn1_buf name = subject_name.val;
      unsigned char * nameptr = name.p;
      size_t name_len = name.len;

      //fprintf(stdout, "Decrypted key\n");
      //for (int i = 0; i < CIPHER_KEY_SIZE; i++)
      //  fprintf(stdout, "%d\t", output[i]);
      //fprintf(stdout, "\n");
      std::vector<uint8_t> v(output, output + CIPHER_KEY_SIZE);
      std::string user_nam =  convertToString((char *)nameptr, name_len);
      client_keys.insert({user_nam, v});

      LOG(INFO) << "verifiation succeded - user added";
      LOG(INFO) << "username :" << user_nam;
      return true;
    }

    std::string convertToString(char* a, int size) {
    int i;
    std::string s = "";
    for (i = 0; i < size; i++) {
        s = s + a[i];
    }
    return s;
}

std::string CharPtrToString(char* a) {
  int i;
  std::string s = "";
  for (i = 0; a[i] != (char) 0; i++) {
      s = s + a[i];
  }
  return s;
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
