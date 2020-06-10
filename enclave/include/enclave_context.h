#ifndef ENCLAVE_CONTEXT_H_
#define ENCLAVE_CONTEXT_H_

#include "xgboost_t.h"
#include <enclave/crypto.h>
#include <enclave/attestation.h>

// needed for certificate
#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/pk_internal.h"

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
    
    // 12 bytes for the session nonce and four bytes for a counter within the session.
    uint8_t m_nonce[CIPHER_IV_SIZE];
    uint32_t m_nonce_ctr;
    uint8_t m_symm_key[CIPHER_KEY_SIZE];

     /* We maintain these maps to avoid having to pass out pointers to application code outside
      * the enclave; instead, the application is given a string nickname that the enclave resolves
      * to a pointer internally.
      */
    std::unordered_map<std::string, void*> booster_map;
    std::unordered_map<std::string, void*> dmatrix_map;
    std::unordered_map<std::string, std::vector<std::string>> dmatrix_owner_map;
    int booster_ctr;
    int dmatrix_ctr;

    // FIXME use array of fixed length instead of vector
    //std::unordered_map<std::string, std::vector<uint8_t>> client_keys;
    uint8_t client_key[CIPHER_KEY_SIZE];
    bool client_key_is_set;

    // map username to client_key
    std::unordered_map<std::string, std::vector<uint8_t>> client_keys;

    // map user name to public key
    std::unordered_map<std::string, std::vector<uint8_t>> client_public_keys;

    EnclaveContext() {
      generate_public_key();
      generate_nonce();
      m_nonce_ctr = 0;
      generate_symm_key();
      client_key_is_set = false;
      booster_ctr = 0;
      dmatrix_ctr = 0;
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

    uint8_t* get_symm_key() {
      return m_symm_key;
    }

    uint8_t* get_nonce() {
      return m_nonce;
    }

    // Checks equality of received and expected nonce and nonce counter and increments nonce counter.
    // FIXME: Redundant check; signature verification is enough
    bool check_seq_num(uint8_t* recv_nonce, uint32_t recv_nonce_ctr) {
      bool retval = recv_nonce_ctr == m_nonce_ctr;
      if (!retval) return retval;
      for (int i = 0; i < CIPHER_IV_SIZE; i++) {
        retval = retval && (recv_nonce[i] == m_nonce[i]); 
      }
      if (retval)
        m_nonce_ctr += 1;
      return retval;
    }

    // Note: Returned handle needs to be freed
    BoosterHandle add_booster(void* booster) {
      std::ostringstream oss;
      oss << "Booster_" << ++booster_ctr;
      auto str = oss.str();
      booster_map[str] = booster;
      BoosterHandle handle = strdup(str.c_str());
      LOG(DEBUG) << "Added booster " << handle;
      return handle;
    }

    // Note: Returned handle needs to be freed
    DMatrixHandle add_dmatrix(void* dmatrix, char* usernames[], int len) {
      std::ostringstream oss;
      oss << "DMatrix_" << ++dmatrix_ctr;
      auto str = oss.str();
      dmatrix_map[str] = dmatrix;

      std::vector<std::string> v(usernames, usernames + len);
      dmatrix_owner_map[str] = v;

      DMatrixHandle handle = strdup(str.c_str());
      LOG(DEBUG) << "Added dmatrix " << handle;
      debug_print_dmatrix_map();
      debug_print_dmatrix_owner_map();
      return handle;
    }

    void* get_booster(BoosterHandle handle) {
      LOG(DEBUG) << "Getting booster " << handle;
      std::string str(handle);
      std::unordered_map<std::string, void*>::const_iterator iter = booster_map.find(str);
      if (iter == booster_map.end()) {
        debug_print_booster_map();
        LOG(FATAL) << "No such booster oject: " << handle;
        return NULL;
      } else {
        return iter->second;
      }
    }

    void* get_dmatrix(DMatrixHandle handle) {
      LOG(DEBUG) << "Getting dmatrix " << handle;
      std::string str(handle);
      std::unordered_map<std::string, void*>::const_iterator iter = dmatrix_map.find(str);
      if (iter == dmatrix_map.end()) {
        debug_print_dmatrix_map();
        LOG(FATAL) << "No such dmatrix oject: " << handle;
        return NULL;
      } else {
        return iter->second;
      }
    }

    std::vector<std::string> get_dmatrix_owners(DMatrixHandle handle) {
      LOG(DEBUG) << "Getting dmatrix " << handle;
      std::string str(handle);
      auto iter = dmatrix_owner_map.find(str);
      if (iter == dmatrix_owner_map.end()) {
        debug_print_dmatrix_owner_map();
        LOG(FATAL) << "No such dmatrix oject: " << handle;
      } else {
        return iter->second;
      }
    }

    void debug_print_dmatrix_map() {
      std::ostringstream oss;
      oss << "DMatrix map---------------" << "\n";
      for(auto elem : dmatrix_map) {
        oss << elem.first << " " << elem.second << "\n";
      }
      oss << "--------------------------" << "\n";
      LOG(DEBUG) << oss.str();
    }

    void debug_print_dmatrix_owner_map() {
      std::ostringstream oss;
      oss << "DMatrix owner map---------------" << "\n";
      for(auto elem : dmatrix_owner_map) {
        oss << elem.first << "\n";
        for(auto name : elem.second) {
          oss << "\t" << name << "\n";
        }
      }
      oss << "--------------------------" << "\n";
      LOG(DEBUG) << oss.str();
    }

    void debug_print_booster_map() {
      std::ostringstream oss;
      oss << "Booster map---------------" << "\n";
      for(auto elem : booster_map) {
        oss << elem.first << " " << elem.second << "\n";
      }
      oss << "--------------------------" << "\n";
      LOG(DEBUG) << oss.str();
    }

    void del_booster(BoosterHandle handle) {
      booster_map.erase(handle);
    }

    void del_dmatrix(DMatrixHandle handle) {
      dmatrix_map.erase(handle);
    }

    void get_client_key(uint8_t* key, char *username) {
      LOG(DEBUG) << "Getting client key for user: " << username;
      std::string str(username);
      auto iter = client_keys.find(str);
      if (iter == client_keys.end()) {
        LOG(FATAL) << "No client key for user: " << username;
      } else {
        memcpy(key, (uint8_t*) iter->second.data(), CIPHER_KEY_SIZE);
      }
    }

    char* get_client_cert(char *username) {
      LOG(DEBUG) << "Getting username " << username;
      std::string str(username);
      auto iter = client_public_keys.find(str);
      if (iter == client_public_keys.end()) {
        LOG(FATAL) << "No certificate for user: " << username;
      } else {
        return (char*) iter->second.data();
      }
    }

    bool verifyClientSignatures(uint8_t* data, size_t data_len, char* signers[], uint8_t* signatures[], size_t sig_lengths[]){
      mbedtls_pk_context _pk_context;

      unsigned char hash[SHA_DIGEST_SIZE];
      int ret = 1;

      // FIXME: Currently we expect sigs to be in same order as users
      for (auto _username: CLIENT_NAMES) {
        char* username = (char*)_username.c_str();

        mbedtls_pk_init(&_pk_context);
        char* cert = get_client_cert(username);
        mbedtls_x509_crt user_cert;
        mbedtls_x509_crt_init(&user_cert);
        if ((ret = mbedtls_x509_crt_parse(&user_cert, (const unsigned char *) cert, strlen(cert) + 1)) != 0) {
          LOG(FATAL) << "verification failed - mbedtls_x509_crt_parse returned" << ret;
        }
        int i = -1;
        for (int j = 0; j < NUM_CLIENTS; j++) {
          if (strcmp(signers[j], username) == 0) {
            i = j;
            break;
          }
        }
        if (i < 0) {
          LOG(FATAL) << "Client not found in signature list: " << username;
        }
        uint8_t* signature = signatures[i];
        size_t sig_len = sig_lengths[i];
        _pk_context = user_cert.pk;
        if (verifySignature(_pk_context, data, data_len, signature, sig_len) != 0) {
          LOG(FATAL) << "Signature verification failed";
        }
      }
      return true;
    }

    bool verify_signatures_with_nonce(std::vector<uint8_t> *bytes, char* signers[], uint8_t* signatures[], size_t sig_lengths[]){
      for (int i = 0; i < CIPHER_IV_SIZE; i ++) {
        bytes->push_back(m_nonce[i]);
      }
      bytes->push_back(m_nonce_ctr >> 24);
      bytes->push_back(m_nonce_ctr >> 16);
      bytes->push_back(m_nonce_ctr >>  8);
      bytes->push_back(m_nonce_ctr      );
      
      return verifyClientSignatures(bytes->data(), bytes->size(), signers, signatures, sig_lengths);
    }

    bool verifySignatureWithCertificate(char* cert,
                int cert_len,
                uint8_t* data,
                size_t data_len,
                uint8_t* signature,
                size_t sig_len) {
      mbedtls_pk_context _pk_context;
      LOG(DEBUG) << "Verifying signature with certificate";

      unsigned char hash[32];
      int ret = 1;

      mbedtls_pk_init(&_pk_context);

      mbedtls_x509_crt _cacert;
      mbedtls_x509_crt_init(&_cacert);
      if ((ret = mbedtls_x509_crt_parse(&_cacert, (const unsigned char *) CA_CERT,
                   strlen(CA_CERT)+1)) != 0) {
         LOG(FATAL) << "verification failed - Could not read root certificate\n" 
           << "mbedtls_x509_crt_parse returned " << ret;
      }

      mbedtls_x509_crt user_cert;
      mbedtls_x509_crt_init(&user_cert);
      if ((ret = mbedtls_x509_crt_parse(&user_cert, (const unsigned char *) cert,
                   cert_len)) != 0) {
         LOG(FATAL) << "verification failed - Could not read user certificate\n"
           << "mbedtls_x509_crt_parse returned " << ret;
         return false;
      }

      uint32_t flags;
      if((ret = mbedtls_x509_crt_verify(&user_cert, &_cacert, NULL, NULL, &flags,
              NULL, NULL)) != 0) {
        LOG(FATAL) << "verification failed - mbedtls_x509_crt_verify flags returned" << flags;
      }

      mbedtls_pk_context user_public_key_context = user_cert.pk;

      if(verifySignature(user_public_key_context, data, data_len, signature, sig_len) != 0) {
        LOG(FATAL) << "Signature verification failed";
      }

      return true;
    }

    bool sign_args(char* data,
        uint8_t* signature,
        size_t* sig_len) {
      return sign_data(m_pk_context, (uint8_t*)data, strlen(data), signature, sig_len);
    }

    bool sign_bytes_with_nonce(std::vector<uint8_t> *bytes, uint8_t* signature, size_t* sig_len) {
      for (int i = 0; i < CIPHER_IV_SIZE; i ++) {
        bytes->push_back(m_nonce[i]);
      }
      bytes->push_back(m_nonce_ctr >> 24);
      bytes->push_back(m_nonce_ctr >> 16);
      bytes->push_back(m_nonce_ctr >>  8);
      bytes->push_back(m_nonce_ctr      );

      return sign_data(m_pk_context, bytes->data(), bytes->size(), signature, sig_len);
    }

    // TODO(rishabh): Fix sequence of the various checks in this function
    bool decrypt_and_save_client_key_with_certificate(char * cert,
            int cert_len,
            uint8_t* data,
            size_t data_len,
            uint8_t* signature,
            size_t sig_len) {

      size_t output_size;
      uint8_t output[CIPHER_KEY_SIZE];
      // FIXME: set size of names
      unsigned char nameptr[50];
      size_t name_len;

      // Only the master node verifies signature and certificate
      if (rabit::GetRank() == 0) {
          if (!verifySignatureWithCertificate(cert, cert_len, data, data_len, signature, sig_len)) {
              LOG(FATAL) << "Signature verification failed";
          }

          int res = 0;
          mbedtls_rsa_context* rsa_context;

          mbedtls_pk_rsa(m_pk_context)->len = data_len;
          rsa_context = mbedtls_pk_rsa(m_pk_context);
          rsa_context->padding = MBEDTLS_RSA_PKCS_V21;
          rsa_context->hash_id = MBEDTLS_MD_SHA256;


          // Only the master node can decrypt the symmetric key
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
          }

          int ret;
          mbedtls_x509_crt user_cert;
          mbedtls_x509_crt_init(&user_cert);
          if ((ret = mbedtls_x509_crt_parse(&user_cert, (const unsigned char *) cert,
                          cert_len)) != 0) {
              LOG(FATAL) << "verification failed - Could not read user certificate\n"
                  << "mbedtls_x509_crt_parse returned " << ret;
          }

          mbedtls_x509_name subject_name = user_cert.subject;
          mbedtls_asn1_buf name = subject_name.val;
          strcpy((char*) nameptr, (const char*) name.p);
          name_len = name.len;
      } 

      // Signature and certificate verification has passed
      // The master node (rank 0) broadcasts the client key and client name to other nodes
      rabit::Broadcast(&output, CIPHER_KEY_SIZE, 0);
      rabit::Broadcast(&name_len, sizeof(name_len), 0);
      rabit::Broadcast(nameptr, name_len, 0);

      // Store the client's symmetric key
      std::vector<uint8_t> user_private_key(output, output + CIPHER_KEY_SIZE);
      std::string user_nam(nameptr, nameptr + name_len);

      // Verify client's identity
      if (std::find(CLIENT_NAMES.begin(), CLIENT_NAMES.end(), user_nam) == CLIENT_NAMES.end()) {
        LOG(FATAL) << "No such authorized client";
      }
      client_keys[user_nam] = user_private_key;

      // Store the client's public key
      std::vector<uint8_t> user_public_key(cert, cert + cert_len);
      client_public_keys.insert({user_nam, user_public_key});

      LOG(DEBUG) << "verification succeeded - user added: " << user_nam;
      return true;
    }

    void share_keys_and_nonce() {
        rabit::Broadcast(m_symm_key, CIPHER_KEY_SIZE, 0);
        rabit::Broadcast(m_nonce, CIPHER_IV_SIZE, 0);

        size_t private_key_length;
        unsigned char m_private_key[5 * CIPHER_PK_SIZE];
        int res;
       
        if (rabit::GetRank() == 0) {
            res = mbedtls_pk_write_key_pem(&m_pk_context, m_private_key, sizeof(m_private_key));
            if (res != 0) {
                LOG(FATAL) << "mbedtls_pk_write_key_pem failed with " << res;
            }
            private_key_length = strlen((const char*) m_private_key);
        }

        rabit::Broadcast(&private_key_length, sizeof(private_key_length), 0);
        rabit::Broadcast(m_private_key, private_key_length, 0);

        // Replace mbedtls_pk_context at non master enclaves so that each enclave has the same keypair
        if (rabit::GetRank() != 0) {
            mbedtls_pk_free(&m_pk_context);
            res = mbedtls_pk_parse_key(&m_pk_context, (const unsigned char*) m_private_key, private_key_length + 1, NULL, NULL);
            if (res != 0) {
                LOG(FATAL) << "mbedtls_pk_parse_key failed with " << res;
            }
        }
        
    }

  private:
    /**
     * Generate an ephemeral symmetric key for the enclave
     * This function is only run by the master enclave, assuming that remote attestation is done before anything else
     */
    bool generate_symm_key() {
      generate_random(m_symm_key, CIPHER_KEY_SIZE);
    }

    /**
     * Generate an ephemeral public key pair for the enclave
     */
    bool generate_public_key() {
      mbedtls_ctr_drbg_init(&m_ctr_drbg_context);
      mbedtls_entropy_init(&m_entropy_context);
      mbedtls_pk_init(&m_pk_context);

      int res = -1;
      // Initialize entropy.
      res = mbedtls_ctr_drbg_seed(&m_ctr_drbg_context, mbedtls_entropy_func, &m_entropy_context, NULL, 0);
      if (res != 0) {
        LOG(FATAL) << "mbedtls_ctr_drbg_seed failed with " << res;
      }

      // Initialize RSA context.
      res = mbedtls_pk_setup(&m_pk_context, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
      if (res != 0) {
        LOG(FATAL) << "mbedtls_pk_setup failed with " << res;
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
        LOG(FATAL) << "mbedtls_rsa_gen_key failed with " << res;
      }

      // Write out the public key in PEM format for exchange with other enclaves.
      res = mbedtls_pk_write_pubkey_pem(&m_pk_context, m_public_key, sizeof(m_public_key));
      if (res != 0) {
        LOG(FATAL) << "mbedtls_pk_write_pubkey_pem failed with " << res;
      }
    }

    /**
     * Generate a session nonce for the enclave to be used by clients. 
     */
    bool generate_nonce() {
      generate_random(m_nonce, CIPHER_IV_SIZE);
    } 
};

#endif
