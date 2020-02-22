#ifndef RABIT_TLS_SOCKET_H_
#define RABIT_TLS_SOCKET_H_

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/certs.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/platform.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"

#include <memory>
#include <string>

#include "socket.h"
#include "../include/dmlc/logging.h"

namespace rabit {
namespace utils {

static void print_err(int error_code) {
  const size_t LEN = 2048;
  char err_buf[LEN];
  mbedtls_strerror(error_code, err_buf, LEN);
  mbedtls_printf(" ERROR %d: %s\n", getpid(), err_buf);
  exit(1);
}

#define DEBUG_LEVEL 0

static void my_debug( void *ctx, int level,
    const char *file, int line,
    const char *str ) {
  ((void) level);

  mbedtls_fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
  fflush(  (FILE *) ctx  );
}

class SSLTcpSocket : public TCPSocket {
 public:

  SSLTcpSocket() : TCPSocket() {
    mbedtls_net_init(&net);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_ssl_init(&ssl);
  }

  bool SSLHandshake();

  // SSL Accept.
  bool SSLAccept(SSLTcpSocket* client_sock);

  // SSL Connect.
  bool SSLConnect(const SockAddr &addr);

  bool ConfigureClientSSL();
  bool ConfigureServerSSL();

  void SetSocket(int sockfd) {
    this->sockfd = sockfd;
    this->net.fd = sockfd;
  }

  void SetBio() {
    mbedtls_ssl_set_bio(&ssl, &net, mbedtls_net_send, mbedtls_net_recv, NULL);
  }

  // SSL Write, note this does not support |flag| argument.
  ssize_t SSLSend(const void *buf, size_t len) {
    int ret = -1;
    while( ( ret = mbedtls_ssl_write( &ssl, (const unsigned char*)buf, len ) ) <= 0 ) {
      if( ret == MBEDTLS_ERR_NET_CONN_RESET ) {
        print_err(ret);
        return -1;
      }

      if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE ) {
        print_err(ret);
        return -1;
      }
    }
    return ret;
  }

  // SSL Read, note this does not support |flag| argument.
  ssize_t SSLRecv(void *buf, size_t len) { 
    int ret = -1;
    do {
      ret = mbedtls_ssl_read(&ssl, (unsigned char*)buf, len);

      if( ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE )
        continue;

      if( ret <= 0 ) {
        switch( ret ) {
          case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
            print_err(ret);
            return -1;

          case MBEDTLS_ERR_NET_CONN_RESET:
            print_err(ret);
            return -1;

          default:
            print_err(ret);
            return -1;
        }
      }

      if( ret > 0 )
        break;
    } while( 1 );
    return ret;
  }

  size_t SSLSendAll(const void *buf_, size_t len) {
    const char *buf = reinterpret_cast<const char *>(buf_);
    size_t ndone = 0;
    while (ndone < len) {
      ssize_t ret = SSLSend(buf, static_cast<ssize_t>(len - ndone));
      if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret < 0) {
        if (LastErrorWouldBlock())
          return ndone;
        print_err(ret);
      }
      buf += ret;
      ndone += ret;
    }
    return ndone;
  }

  size_t SSLRecvAll(void *buf_, size_t len) {
    char *buf = reinterpret_cast<char *>(buf_);
    size_t ndone = 0;
    while (ndone < len) {
      ssize_t ret = SSLRecv(buf, static_cast<sock_size_t>(len - ndone));
      if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret < 0) {
        if (LastErrorWouldBlock())
          return ndone;
        print_err(ret);
      }
      if (ret == 0) return ndone;
      buf += ret;
      ndone += ret;
    }
    return ndone;
  }


  /*!
   * \brief send a string over network
   * \param str the string to be sent
   */
  void SSLSendStr(const std::string &str) {
    int len = static_cast<int>(str.length());
    utils::Assert(this->SSLSendAll(&len, sizeof(len)) == sizeof(len),
                  "error during send SendStr");
    if (len != 0) {
      utils::Assert(this->SSLSendAll(str.c_str(), str.length()) == str.length(),
                    "error during send SendStr");
    }
  }

  /*!
   * \brief recv a string from network
   * \param out_str the string to receive
   */
  void SSLRecvStr(std::string *out_str) {
    int len;
    utils::Assert(this->SSLRecvAll(&len, sizeof(len)) == sizeof(len),
                  "error during send RecvStr");
    out_str->resize(len);
    if (len != 0) {
      utils::Assert(this->SSLRecvAll(&(*out_str)[0], len) == out_str->length(),
                    "error during send SendStr");
    }
  }

  mbedtls_ssl_context ssl;
 private:
  mbedtls_net_context net;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ssl_config conf;
  mbedtls_entropy_context entropy;
  mbedtls_x509_crt cacert;

  mbedtls_x509_crt srvcert;
  mbedtls_x509_crt cachain;
  mbedtls_pk_context pkey;
};

}  // namespace utils
}  // namespace rabit

#endif  // RABIT_TLS_SOCKET_H_
