#include "ssl_socket.h"
#include "ssl_attestation.h"
#include "../include/dmlc/logging.h"
#include "certs.h"

namespace rabit {
namespace utils {

namespace {}  // namespace

bool SSLTcpSocket::ConfigureClientSSL() {
  int ret;
  mbedtls_x509_crt_init(&srvcert);
  mbedtls_x509_crt_init(&cachain);
  mbedtls_pk_init( &pkey );

  if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0)) != 0) {
    print_err(ret);
    return false;
  }

  if ((ret = mbedtls_ssl_config_defaults(
          &conf,
          MBEDTLS_SSL_IS_CLIENT,
          MBEDTLS_SSL_TRANSPORT_STREAM,
          MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
    print_err(ret);
    return false;
  }

#if false // FIXME For testing on non-SGX platform; wrap within `SIMULATION_MODE` macro
  mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
#else
  oe_result_t result = generate_certificate_and_pkey(&srvcert, &pkey);
  if (result != OE_OK) {
      printf("Generate cert failed with %s\n", oe_result_str(result));
      return false;
  }
  mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_verify(&conf, cert_verify_callback, NULL);

  if ((ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey)) != 0) {
      print_err(ret);
      return false;
  }
#endif
  mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
  mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

  mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );
  mbedtls_debug_set_threshold(DEBUG_LEVEL);

  // set up SSL context
  if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
    print_err(ret);
    return false;
  }
  return true;
}

bool SSLTcpSocket::ConfigureServerSSL() {
  int ret;
  mbedtls_x509_crt_init(&srvcert);
  mbedtls_x509_crt_init(&cachain);
  mbedtls_pk_init( &pkey );

  if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0)) != 0) {
    print_err(ret);
    return false;
  }

#if false // FIXME Inbuilt certs for testing on non-SGX platform; wrap within `SIMULATION_MODE` macro
  if ((ret = mbedtls_x509_crt_parse( &srvcert, (const unsigned char *) mbedtls_test_srv_crt_ec, mbedtls_test_srv_crt_ec_len)) != 0) {
    print_err(ret);
    return false;
  }
  if ((ret = mbedtls_x509_crt_parse( &cachain, (const unsigned char *) mbedtls_test_cas_pem, mbedtls_test_cas_pem_len )) != 0) {
    print_err(ret);
    return false;
  }
  if ((ret = mbedtls_pk_parse_key( &pkey, (const unsigned char *) mbedtls_test_srv_key_ec, mbedtls_test_srv_key_ec_len, NULL, 0)) != 0) {
    print_err(ret);
    return false;
  }

  mbedtls_ssl_conf_ca_chain(&conf, &cachain, NULL);
#else
  oe_result_t result = generate_certificate_and_pkey(&srvcert, &pkey);
  if (result != OE_OK) {
      printf("Generate cert failed with %s\n", oe_result_str(result));
      return false;
  }
  mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_verify(&conf, cert_verify_callback, NULL);

#endif
  mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
  if ((ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey)) != 0) {
    print_err(ret);
    return false;
  }

  if ((ret = mbedtls_ssl_config_defaults(
          &conf,
          MBEDTLS_SSL_IS_SERVER,
          MBEDTLS_SSL_TRANSPORT_STREAM,
          MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
    print_err(ret);
    return false;
  }

  mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );

  mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );
  mbedtls_debug_set_threshold(DEBUG_LEVEL);

  if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
    print_err(ret);
    return false;
  }
  return true;
}

bool SSLTcpSocket::SSLHandshake() {
  int ret;
  while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      print_err(ret);
      return false;
    }
  }
  return true;
}

bool SSLTcpSocket::SSLConnect(const SockAddr &addr) {
  if (Connect(addr)) {
    if (!ConfigureClientSSL())
      return false;

    net.fd = this->sockfd;
    this->SetBio();

    if(!SSLHandshake())
      return false;

    return true;
  }
  return false;
}

bool SSLTcpSocket::SSLAccept(SSLTcpSocket* client_sock) {
  SOCKET client_fd = Accept();

  client_sock->SetSocket(client_fd);
  int ret;

  if (!client_sock->ConfigureServerSSL())
    return false;

  client_sock->SetBio();

  if(!client_sock->SSLHandshake())
    return false;

  return true;
}

} /* namespace utils */
} /* namespace rabit */
