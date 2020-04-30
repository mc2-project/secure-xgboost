// Copyright by Contributors
#include <dmlc/base.h>
#include <dmlc/io.h>
#include <dmlc/logging.h>
#include <dmlc/data.h>
#include <dmlc/registry.h>
#include <cstring>
#include <string>
#include "io/uri_spec.h"
#include "data/parser.h"
#include "data/basic_row_iter.h"
#include "data/disk_row_iter.h"
#include "data/libsvm_parser.h"
#include "data/libfm_parser.h"
#include "data/csv_parser.h"

namespace dmlc {
/*! \brief namespace for useful input data structure */
namespace data {

template<typename IndexType, typename DType = real_t>
Parser<IndexType> *
#ifdef __ENCLAVE__ // Init with encryption key
CreateLibSVMParser(const std::string& path,
    const std::map<std::string, std::string>& args,
    unsigned part_index,
    unsigned num_parts,
    bool is_encrypted,
    const char* key) {
#else
CreateLibSVMParser(const std::string& path,
                   const std::map<std::string, std::string>& args,
                   unsigned part_index,
                   unsigned num_parts) {
#endif
  InputSplit* source = InputSplit::Create(
      path.c_str(), part_index, num_parts, "text");
#ifdef __ENCLAVE__ // Init with encryption key
  ParserImpl<IndexType> *parser = new LibSVMParser<IndexType>(source, args, 2, is_encrypted, key);
#else
  ParserImpl<IndexType> *parser = new LibSVMParser<IndexType>(source, args, 2);
#endif
#if DMLC_ENABLE_STD_THREAD
  parser = new ThreadedParser<IndexType>(parser);
#endif
  return parser;
}

template<typename IndexType, typename DType = real_t>
Parser<IndexType> *
#ifdef __ENCLAVE__ // Init with encryption key
CreateLibFMParser(const std::string& path,
    const std::map<std::string, std::string>& args,
    unsigned part_index,
    unsigned num_parts,
    bool is_encrypted,
    const char* key) {
#else
CreateLibFMParser(const std::string& path,
                  const std::map<std::string, std::string>& args,
                  unsigned part_index,
                  unsigned num_parts) {
#endif
  InputSplit* source = InputSplit::Create(
      path.c_str(), part_index, num_parts, "text");
#ifdef __ENCLAVE__ // Init with encryption key
  ParserImpl<IndexType> *parser = new LibFMParser<IndexType>(source, args, 2, is_encrypted, key);
#else
  ParserImpl<IndexType> *parser = new LibFMParser<IndexType>(source, args, 2);
#endif
#if DMLC_ENABLE_STD_THREAD
  parser = new ThreadedParser<IndexType>(parser);
#endif
  return parser;
}

template<typename IndexType, typename DType = real_t>
Parser<IndexType, DType> *
#ifdef __ENCLAVE__ // Init with encryption key
CreateCSVParser(const std::string& path,
    const std::map<std::string, std::string>& args,
    unsigned part_index,
    unsigned num_parts,
    bool is_encrypted,
    const char* key) {
#else
CreateCSVParser(const std::string& path,
                const std::map<std::string, std::string>& args,
                unsigned part_index,
                unsigned num_parts) {
#endif
  InputSplit* source = InputSplit::Create(
      path.c_str(), part_index, num_parts, "text");
#ifdef __ENCLAVE__ // Init with encryption key
  return new CSVParser<IndexType, DType>(source, args, 2, is_encrypted, key);
#else
  return new CSVParser<IndexType, DType>(source, args, 2);
#endif
}

template<typename IndexType, typename DType = real_t>
inline Parser<IndexType, DType> *
#ifdef __ENCLAVE__ // Init with encryption key
CreateParser_(const char *uri_,
    unsigned part_index,
    unsigned num_parts,
    const char *type,
    bool is_encrypted,
    const char* key) {
#else
CreateParser_(const char *uri_,
              unsigned part_index,
              unsigned num_parts,
              const char *type) {
#endif
  std::string ptype = type;
  io::URISpec spec(uri_, part_index, num_parts);
  if (ptype == "auto") {
    if (spec.args.count("format") != 0) {
      ptype = spec.args.at("format");
    } else {
      ptype = "libsvm";
    }
  }

  const ParserFactoryReg<IndexType, DType>* e =
      Registry<ParserFactoryReg<IndexType, DType> >::Get()->Find(ptype);
  if (e == NULL) {
    LOG(FATAL) << "Unknown data type " << ptype;
  }
  // create parser
#ifdef __ENCLAVE__ // Init with encryption key
  return (*e->body)(spec.uri, spec.args, part_index, num_parts, is_encrypted, key);
#else
  return (*e->body)(spec.uri, spec.args, part_index, num_parts);
#endif
}

#ifndef __ENCLAVE__
template<typename IndexType, typename DType = real_t>
inline RowBlockIter<IndexType, DType> *
CreateIter_(const char *uri_,
            unsigned part_index,
            unsigned num_parts,
            const char *type) {
  using namespace std;
  io::URISpec spec(uri_, part_index, num_parts);
  Parser<IndexType, DType> *parser = CreateParser_<IndexType, DType>
      (spec.uri.c_str(), part_index, num_parts, type);
  if (spec.cache_file.length() != 0) {
#if DMLC_ENABLE_STD_THREAD
    return new DiskRowIter<IndexType, DType>(parser, spec.cache_file.c_str(), true);
#else
    LOG(FATAL) << "compile with c++0x or c++11 to enable cache file";
    return NULL;
#endif
  } else {
    return new BasicRowIter<IndexType, DType>(parser);
  }
}
#endif

DMLC_REGISTER_PARAMETER(LibSVMParserParam);
DMLC_REGISTER_PARAMETER(LibFMParserParam);
DMLC_REGISTER_PARAMETER(CSVParserParam);
}  // namespace data

#ifndef __ENCLAVE__
// template specialization
template<>
RowBlockIter<uint32_t, real_t> *
RowBlockIter<uint32_t, real_t>::Create(const char *uri,
                                       unsigned part_index,
                                       unsigned num_parts,
                                       const char *type) {
  return data::CreateIter_<uint32_t, real_t>(uri, part_index, num_parts, type);
}

template<>
RowBlockIter<uint64_t, real_t> *
RowBlockIter<uint64_t, real_t>::Create(const char *uri,
                                       unsigned part_index,
                                       unsigned num_parts,
                                       const char *type) {
  return data::CreateIter_<uint64_t, real_t>(uri, part_index, num_parts, type);
}

template<>
RowBlockIter<uint32_t, int32_t> *
RowBlockIter<uint32_t, int32_t>::Create(const char *uri,
                                    unsigned part_index,
                                    unsigned num_parts,
                                    const char *type) {
  return data::CreateIter_<uint32_t, int32_t>(uri, part_index, num_parts, type);
}

template<>
RowBlockIter<uint64_t, int32_t> *
RowBlockIter<uint64_t, int32_t>::Create(const char *uri,
                                    unsigned part_index,
                                    unsigned num_parts,
                                    const char *type) {
  return data::CreateIter_<uint64_t, int32_t>(uri, part_index, num_parts, type);
}

template<>
RowBlockIter<uint32_t, int64_t> *
RowBlockIter<uint32_t, int64_t>::Create(const char *uri,
                                        unsigned part_index,
                                        unsigned num_parts,
                                        const char *type) {
  return data::CreateIter_<uint32_t, int64_t>(uri, part_index, num_parts, type);
}

template<>
RowBlockIter<uint64_t, int64_t> *
RowBlockIter<uint64_t, int64_t>::Create(const char *uri,
                                        unsigned part_index,
                                        unsigned num_parts,
                                        const char *type) {
  return data::CreateIter_<uint64_t, int64_t>(uri, part_index, num_parts, type);
}

template<>
Parser<uint32_t, real_t> *
Parser<uint32_t, real_t>::Create(const char *uri_,
                                 unsigned part_index,
                                 unsigned num_parts,
                                 const char *type) {
  return data::CreateParser_<uint32_t, real_t>(uri_, part_index, num_parts, type);
}

template<>
Parser<uint64_t, real_t> *
Parser<uint64_t, real_t>::Create(const char *uri_,
                                 unsigned part_index,
                                 unsigned num_parts,
                                 const char *type) {
  return data::CreateParser_<uint64_t, real_t>(uri_, part_index, num_parts, type);
}

template<>
Parser<uint32_t, int32_t> *
Parser<uint32_t, int32_t>::Create(const char *uri_,
                              unsigned part_index,
                              unsigned num_parts,
                              const char *type) {
  return data::CreateParser_<uint32_t, int32_t>(uri_, part_index, num_parts, type);
}

template<>
Parser<uint64_t, int32_t> *
Parser<uint64_t, int32_t>::Create(const char *uri_,
                              unsigned part_index,
                              unsigned num_parts,
                              const char *type) {
  return data::CreateParser_<uint64_t, int32_t>(uri_, part_index, num_parts, type);
}

template<>
Parser<uint32_t, int64_t> *
Parser<uint32_t, int64_t>::Create(const char *uri_,
                                  unsigned part_index,
                                  unsigned num_parts,
                                  const char *type) {
  return data::CreateParser_<uint32_t, int64_t>(uri_, part_index, num_parts, type);
}

template<>
Parser<uint64_t, int64_t> *
Parser<uint64_t, int64_t>::Create(const char *uri_,
                                  unsigned part_index,
                                  unsigned num_parts,
                                  const char *type) {
  return data::CreateParser_<uint64_t, int64_t>(uri_, part_index, num_parts, type);
}
#else // __ENCLAVE__
template<>
Parser<uint32_t, real_t> *
Parser<uint32_t, real_t>::Create(const char *uri_,
    unsigned part_index,
    unsigned num_parts,
    const char *type,
    bool is_encrypted,
    const char* key) {
  return data::CreateParser_<uint32_t, real_t>(uri_, part_index, num_parts, type, is_encrypted, key);
}

template<>
Parser<uint64_t, real_t> *
Parser<uint64_t, real_t>::Create(const char *uri_,
    unsigned part_index,
    unsigned num_parts,
    const char *type,
    bool is_encrypted,
    const char* key) {
  return data::CreateParser_<uint64_t, real_t>(uri_, part_index, num_parts, type, is_encrypted, key);
}

template<>
Parser<uint32_t, int32_t> *
Parser<uint32_t, int32_t>::Create(const char *uri_,
    unsigned part_index,
    unsigned num_parts,
    const char *type,
    bool is_encrypted,
    const char* key) {
  return data::CreateParser_<uint32_t, int32_t>(uri_, part_index, num_parts, type, is_encrypted, key);
}

template<>
Parser<uint64_t, int32_t> *
Parser<uint64_t, int32_t>::Create(const char *uri_,
    unsigned part_index,
    unsigned num_parts,
    const char *type,
    bool is_encrypted,
    const char* key) {
  return data::CreateParser_<uint64_t, int32_t>(uri_, part_index, num_parts, type, is_encrypted, key);
}

template<>
Parser<uint32_t, int64_t> *
Parser<uint32_t, int64_t>::Create(const char *uri_,
    unsigned part_index,
    unsigned num_parts,
    const char *type,
    bool is_encrypted,
    const char* key) {
  return data::CreateParser_<uint32_t, int64_t>(uri_, part_index, num_parts, type, is_encrypted, key);
}

template<>
Parser<uint64_t, int64_t> *
Parser<uint64_t, int64_t>::Create(const char *uri_,
    unsigned part_index,
    unsigned num_parts,
    const char *type,
    bool is_encrypted,
    const char* key) {
  return data::CreateParser_<uint64_t, int64_t>(uri_, part_index, num_parts, type, is_encrypted, key);
}
#endif // __ENCLAVE__

// registry
typedef ParserFactoryReg<uint32_t, real_t> Reg32flt;
typedef ParserFactoryReg<uint32_t, int32_t> Reg32int32;
typedef ParserFactoryReg<uint32_t, int64_t> Reg32int64;
typedef ParserFactoryReg<uint64_t, real_t> Reg64flt;
typedef ParserFactoryReg<uint64_t, int32_t> Reg64int32;
typedef ParserFactoryReg<uint64_t, int64_t> Reg64int64;
DMLC_REGISTRY_ENABLE(Reg32flt);
DMLC_REGISTRY_ENABLE(Reg32int32);
DMLC_REGISTRY_ENABLE(Reg32int64);
DMLC_REGISTRY_ENABLE(Reg64flt);
DMLC_REGISTRY_ENABLE(Reg64int32);
DMLC_REGISTRY_ENABLE(Reg64int64);

DMLC_REGISTER_DATA_PARSER(
  uint32_t, real_t, libsvm, data::CreateLibSVMParser<uint32_t __DMLC_COMMA real_t>);
DMLC_REGISTER_DATA_PARSER(
  uint64_t, real_t, libsvm, data::CreateLibSVMParser<uint64_t __DMLC_COMMA real_t>);
DMLC_REGISTER_DATA_PARSER(
  uint32_t, real_t, libfm, data::CreateLibFMParser<uint32_t __DMLC_COMMA real_t>);
DMLC_REGISTER_DATA_PARSER(
  uint64_t, real_t, libfm, data::CreateLibFMParser<uint64_t __DMLC_COMMA real_t>);
DMLC_REGISTER_DATA_PARSER(
  uint32_t, real_t, csv, data::CreateCSVParser<uint32_t __DMLC_COMMA real_t>);
DMLC_REGISTER_DATA_PARSER(
  uint64_t, real_t, csv, data::CreateCSVParser<uint64_t __DMLC_COMMA real_t>);
DMLC_REGISTER_DATA_PARSER(
  uint32_t, int32_t, csv, data::CreateCSVParser<uint32_t __DMLC_COMMA int32_t>);
DMLC_REGISTER_DATA_PARSER(
  uint64_t, int32_t, csv, data::CreateCSVParser<uint64_t __DMLC_COMMA int32_t>);
DMLC_REGISTER_DATA_PARSER(
  uint32_t, int64_t, csv, data::CreateCSVParser<uint32_t __DMLC_COMMA int64_t>);
DMLC_REGISTER_DATA_PARSER(
  uint64_t, int64_t, csv, data::CreateCSVParser<uint64_t __DMLC_COMMA int64_t>);

}  // namespace dmlc
