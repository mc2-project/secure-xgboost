/*!
 *  Copyright (c) 2015 by Contributors
 * \file text_parser.h
 * \brief iterator parser to parse text format
 * \author Tianqi Chen
 */
#ifndef DMLC_DATA_TEXT_PARSER_H_
#define DMLC_DATA_TEXT_PARSER_H_

#include <dmlc/data.h>
#include <dmlc/omp.h>
#include <dmlc/common.h>
#include <thread>
#include <mutex>
#include <vector>
#include <cstring>
#include <algorithm>
#include "./row_block.h"
#include "./parser.h"

#ifdef __ENCLAVE__  // encryption
#include <dmlc/base64.h>
#include <enclave/crypto.h>
#endif


namespace dmlc {
namespace data {
/*!
 * \brief Text parser that parses the input lines
 * and returns rows in input data
 */
template <typename IndexType, typename DType = real_t>
class TextParserBase : public ParserImpl<IndexType, DType> {
 public:
#ifdef __ENCLAVE__  // pass decryption key
  explicit TextParserBase(InputSplit *source,
      int nthread,
      bool _is_encrypted,
      const char* _key)
#else
  explicit TextParserBase(InputSplit *source,
                          int nthread)
#endif
      : bytes_read_(0), source_(source) {
    int maxthread = std::max(omp_get_num_procs() / 2 - 4, 1);
    nthread_ = std::min(maxthread, nthread);

#ifdef __ENCLAVE__  // cipher init
    is_encrypted = _is_encrypted;
    if (is_encrypted) {
        memcpy(key, _key, CIPHER_KEY_SIZE);
        int ret = cipher_init(&gcm, (unsigned char*)key);
        if (ret != 0) {
          LOG(FATAL) << "mbedtls_gcm_setkey failed with error " << -ret;
        }
    }
    this->total_rows_in_chunk = 0;
    this->total_rows_global = 0;
    this->starting_row_index = 0;
    this->prev_row_index = 0;
#endif
  }
  virtual ~TextParserBase() {
    delete source_;
#ifdef __ENCLAVE__  // cipher free
    if (is_encrypted) {
      mbedtls_gcm_free(&gcm);
    }
#endif
  }
  virtual void BeforeFirst(void) {
    source_->BeforeFirst();
  }
  virtual size_t BytesRead(void) const {
    return bytes_read_;
  }
  virtual bool ParseNext(std::vector<RowBlockContainer<IndexType, DType> > *data) {
    return FillData(data);
  }

 protected:
   /*!
    * \brief parse data into out
    * \param begin beginning of buffer
    * \param end end of buffer
    */
  virtual void ParseBlock(const char *begin, const char *end,
                          RowBlockContainer<IndexType, DType> *out) = 0;
#ifdef __ENCLAVE__  // parse encrypted data
  /*!
   * \brief parse data into out
   * \param begin beginning of buffer
   * \param end end of buffer
   */
  virtual void ParseEncryptedBlock(const char *begin, const char *end,
          RowBlockContainer<IndexType, DType> *out) = 0;
#endif
   /*!
    * \brief read in next several blocks of data
    * \param data vector of data to be returned
    * \return true if the data is loaded, false if reach end
    */
  inline bool FillData(std::vector<RowBlockContainer<IndexType, DType>> *data);
   /*!
    * \brief start from bptr, go backward and find first endof line
    * \param bptr end position to go backward
    * \param begin the beginning position of buffer
    * \return position of first endof line going backward, returns begin if not found
    */
  static inline const char *BackFindEndLine(const char *bptr, const char *begin) {
     for (; bptr != begin; --bptr) {
       if (*bptr == '\n' || *bptr == '\r')
         return bptr;
     }
     return begin;
  }

#ifdef __ENCLAVE__  // decryption
  inline void DecryptLine(const char* data, char* output, size_t len) {
    this->total_rows_in_chunk++;

    int index_pos = 0;
    int total_pos = 0;
    int iv_pos = 0;
    int tag_pos = 0;

    for (int i = 0; i < len; i++) {
      if (data[i] == ',') {
        index_pos = i;
        break;
      }
    }
    for (int i = index_pos + 1; i < len; i++) {
      if (data[i] == ',') {
        total_pos = i;
        break;
      }
    }
    for (int i = total_pos + 1; i < len; i++) {
      if (data[i] == ',') {
        iv_pos = i;
        break;
      }
    }
    for (int i = iv_pos + 1; i < len; i++) {
      if (data[i] == ',') {
        tag_pos = i;
        break;
      }
    }
    CHECK_LT(0, index_pos);
    CHECK_LT(index_pos, total_pos);
    CHECK_LT(total_pos, iv_pos);
    CHECK_LT(iv_pos, tag_pos);

    char *aad_str = reinterpret_cast<char*>(malloc(total_pos + 1));
    memcpy(aad_str, data, total_pos);
    aad_str[total_pos] = 0;

    size_t out_len;
    char tag[CIPHER_TAG_SIZE];
    char iv[CIPHER_IV_SIZE];
    char* ct = reinterpret_cast<char *>(malloc(len * sizeof(char)));

    out_len = base64_decode(data + total_pos + 1, iv_pos - total_pos, iv);
    CHECK_EQ(out_len, CIPHER_IV_SIZE);
    out_len = base64_decode(data + iv_pos + 1, tag_pos - iv_pos, tag);
    CHECK_EQ(out_len, CIPHER_TAG_SIZE);
    out_len = base64_decode(data + tag_pos + 1, len - tag_pos, ct);

    char *index_str = reinterpret_cast<char*>(malloc(index_pos));
    memcpy(index_str, data, index_pos);
    index_str[index_pos] = 0;
    uint64_t index = atoi(index_str);
    CHECK_GT(index, 0);

    uint64_t total_len = total_pos - index_pos - 1;
    char *total_str = reinterpret_cast<char*>(malloc(total_len + 1));
    memcpy(total_str, data + index_pos + 1, total_len);
    total_str[total_len] = 0;
    uint64_t total = atoi(total_str);
    CHECK_LE(index, total);

    int ret = decrypt_symm(
        &gcm,
        (const unsigned char*)ct,
        out_len,
        (unsigned char*)iv,
        (unsigned char*)tag,
        (unsigned char*)aad_str,
        strlen(aad_str),
        (unsigned char*)output);
    output[out_len] = '\0';
    free(ct);
    if (ret != 0) {
      LOG(FATAL) << "Decryption failed with error " << -ret;
    }

    // Check row indices are correct (to detect duplication/deletion of rows)
    if (this->starting_row_index == 0) {
        this->starting_row_index = index;
        this->total_rows_global = total;
        prev_row_index = index;
    } else {
        CHECK_EQ(prev_row_index+1, index);
        CHECK_EQ(this->total_rows_global, total);
        prev_row_index = index;
    }
  }
#endif
  /*!
   * \brief Ignore UTF-8 BOM if present
   * \param begin reference to begin pointer
   * \param end reference to end pointer
   */
  static inline void IgnoreUTF8BOM(const char **begin, const char **end) {
    int count = 0;
    for (count = 0; *begin != *end && count < 3; count++, ++*begin) {
      if (!begin || !*begin)
        break;
      if (**begin != '\xEF' && count == 0)
        break;
      if (**begin != '\xBB' && count == 1)
        break;
      if (**begin != '\xBF' && count == 2)
        break;
    }
    if (count < 3)
      *begin -= count;
  }

 private:
  // nthread
  int nthread_;
  // number of bytes readed
  size_t bytes_read_;
  // source split that provides the data
  InputSplit *source_;
  // OMPException object to catch and rethrow exceptions in omp blocks
  dmlc::OMPException omp_exc_;

#ifdef __ENCLAVE__  // cipher
  bool is_encrypted;

  uint64_t prev_row_index;

  mbedtls_gcm_context gcm;
  char key[CIPHER_KEY_SIZE];
#endif
};

// implementation
template <typename IndexType, typename DType>
inline bool TextParserBase<IndexType, DType>::FillData(
    std::vector<RowBlockContainer<IndexType, DType> > *data) {
  InputSplit::Blob chunk;
  if (!source_->NextChunk(&chunk)) {
    return false;
  }
  const int nthread = omp_get_max_threads();
  // reserve space for data
  data->resize(nthread);
  bytes_read_ += chunk.size;
  CHECK_NE(chunk.size, 0U);
  const char *head = reinterpret_cast<char *>(chunk.dptr);

#ifdef __ENCLAVE__  // FIXME support multi-threading
  if (is_encrypted)
      ParseEncryptedBlock(head, head + chunk.size, &(*data)[0]);
  else
      ParseBlock(head, head + chunk.size, &(*data)[0]);
#else  // __ENCLAVE__
  std::vector<std::thread> threads;
  for (int tid = 0; tid < nthread; ++tid) {
    threads.push_back(std::thread([&chunk, head, data, nthread, tid, this] {
      this->omp_exc_.Run([&] {
        size_t nstep = (chunk.size + nthread - 1) / nthread;
        size_t sbegin = std::min(tid * nstep, chunk.size);
        size_t send = std::min((tid + 1) * nstep, chunk.size);
        const char *pbegin = BackFindEndLine(head + sbegin, head);
        const char *pend;
        if (tid + 1 == nthread) {
          pend = head + send;
        } else {
          pend = BackFindEndLine(head + send, head);
        }
        ParseBlock(pbegin, pend, &(*data)[tid]);
      });
    }));
  }
  for (int i = 0; i < nthread; ++i) {
    threads[i].join();
  }
#endif  // __ENCLAVE__
  omp_exc_.Rethrow();

  this->data_ptr_ = 0;
  return true;
}

}  // namespace data
}  // namespace dmlc
#endif  // DMLC_DATA_TEXT_PARSER_H_
