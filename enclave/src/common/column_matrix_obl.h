/*!
 * Copyright 2017 by Contributors
 * Modifications Copyright 2020-22 by Secure XGBoost Contributors
 * \file column_matrix.h
 * \brief Utility for fast column-wise access
 * \author Philip Cho
 */

#ifdef __ENCLAVE_OBLIVIOUS__

#ifndef XGBOOST_COMMON_COLUMN_MATRIX_H_
#define XGBOOST_COMMON_COLUMN_MATRIX_H_

#include <limits>
#include <vector>
#include "hist_util.h"


namespace xgboost {
namespace common {


/*! \brief column type */
enum ColumnType {
  kDenseColumn,
  kSparseColumn
};

/*! \brief a column storage, to be used with ApplySplit. Note that each
    bin id is stored as index[i] + index_base. */
class Column {
 public:
  Column(ColumnType type, const uint32_t* index, uint32_t index_base,
         const size_t* row_ind, size_t len)
      : type_(type),
        index_(index),
        index_base_(index_base),
        row_ind_(row_ind),
        len_(len) {}
  size_t Size() const { return len_; }
  uint32_t GetGlobalBinIdx(size_t idx) const { return index_base_ + index_[idx]; }
  uint32_t GetFeatureBinIdx(size_t idx) const { return index_[idx]; }
  // column.GetFeatureBinIdx(idx) + column.GetBaseIdx(idx) ==
  // column.GetGlobalBinIdx(idx)
  uint32_t GetBaseIdx() const { return index_base_; }
  ColumnType GetType() const { return type_; }
  size_t GetRowIdx(size_t idx) const {
    // clang-tidy worries that row_ind_ might be a nullptr, which is possible,
    // but low level structure is not safe anyway.
    return type_ == ColumnType::kDenseColumn ? idx : row_ind_[idx];  // NOLINT
  }
  bool IsMissing(size_t idx) const {
    return index_[idx] == std::numeric_limits<uint32_t>::max();
  }
  const size_t* GetRowData() const { return row_ind_; }

 private:
  ColumnType type_;
  const uint32_t* index_;
  uint32_t index_base_;
  const size_t* row_ind_;
  const size_t len_;
};

/*! \brief a collection of columns, with support for construction from
    GHistIndexMatrix. */
class ColumnMatrix {
 public:
  // get number of features
  inline bst_uint GetNumFeature() const {
    return static_cast<bst_uint>(type_.size());
  }

  // construct column matrix from GHistIndexMatrix
  inline void Init(const GHistIndexMatrix& gmat,
                   double  sparse_threshold) {
    const int32_t nfeature = static_cast<int32_t>(gmat.cut.row_ptr.size() - 1);
    const size_t nrow = gmat.row_ptr.size() - 1;

    // identify type of each column
    feature_counts_.resize(nfeature);
    type_.resize(nfeature);
    std::fill(feature_counts_.begin(), feature_counts_.end(), 0);

    uint32_t max_val = std::numeric_limits<uint32_t>::max();
    for (bst_uint fid = 0; fid < nfeature; ++fid) {
      CHECK_LE(gmat.cut.row_ptr[fid + 1] - gmat.cut.row_ptr[fid], max_val);
    }

    gmat.GetFeatureCounts(&feature_counts_[0]);
    // classify features
    for (int32_t fid = 0; fid < nfeature; ++fid) {
      if (static_cast<double>(feature_counts_[fid])
                 < sparse_threshold * nrow) {
        type_[fid] = kSparseColumn;
      } else {
        type_[fid] = kDenseColumn;
      }
    }

    // want to compute storage boundary for each feature
    // using variants of prefix sum scan
    boundary_.resize(nfeature);
    size_t accum_index_ = 0;
    size_t accum_row_ind_ = 0;
    for (int32_t fid = 0; fid < nfeature; ++fid) {
      boundary_[fid].index_begin = accum_index_;
      boundary_[fid].row_ind_begin = accum_row_ind_;
      if (type_[fid] == kDenseColumn) {
        accum_index_ += static_cast<size_t>(nrow);
        accum_row_ind_ += static_cast<size_t>(nrow);
      } else {
        accum_index_ += feature_counts_[fid];
        accum_row_ind_ += feature_counts_[fid];
      }
      boundary_[fid].index_end = accum_index_;
      boundary_[fid].row_ind_end = accum_row_ind_;
    }

    index_.resize(boundary_[nfeature - 1].index_end);
    row_ind_.resize(boundary_[nfeature - 1].row_ind_end);

    // store least bin id for each feature
    index_base_.resize(nfeature);
    for (bst_uint fid = 0; fid < nfeature; ++fid) {
      index_base_[fid] = gmat.cut.row_ptr[fid];
    }

    // pre-fill index_ for dense columns

    #pragma omp parallel for
    for (int32_t fid = 0; fid < nfeature; ++fid) {
      if (type_[fid] == kDenseColumn) {
        const size_t ibegin = boundary_[fid].index_begin;
        uint32_t* begin = &index_[ibegin];
        uint32_t* end = begin + nrow;
        std::fill(begin, end, std::numeric_limits<uint32_t>::max());
        // max() indicates missing values
      }
    }

    // loop over all rows and fill column entries
    // num_nonzeros[fid] = how many nonzeros have this feature accumulated so far?
    std::vector<size_t> num_nonzeros;
    num_nonzeros.resize(nfeature);
    std::fill(num_nonzeros.begin(), num_nonzeros.end(), 0);

    // For oblivious.
    row_wise_index_.resize(nrow * nfeature);
    std::fill(row_wise_index_.begin(), row_wise_index_.end(),
              std::numeric_limits<uint32_t>::max());
    nfeature_ = nfeature;

    for (size_t rid = 0; rid < nrow; ++rid) {
      const size_t ibegin = gmat.row_ptr[rid];
      const size_t iend = gmat.row_ptr[rid + 1];
      size_t fid = 0;
      for (size_t i = ibegin; i < iend; ++i) {
        // NOTE: For dense data structure, below codes are already oblivious,
        // given the |gmat.index| in one instance are already sorted.
        const uint32_t bin_id = gmat.index[i];
        while (bin_id >= gmat.cut.row_ptr[fid + 1]) {
          ++fid;
        }

        // For oblivious. Note this contains index_base.
        row_wise_index_[rid * nfeature + fid] = bin_id;

        if (type_[fid] == kDenseColumn) {
          uint32_t* begin = &index_[boundary_[fid].index_begin];
          begin[rid] = bin_id - index_base_[fid];
        } else {
          uint32_t* begin = &index_[boundary_[fid].index_begin];
          begin[num_nonzeros[fid]] = bin_id - index_base_[fid];
          row_ind_[boundary_[fid].row_ind_begin + num_nonzeros[fid]] = rid;
          ++num_nonzeros[fid];
        }
      }
    }
  }

  /* Fetch an individual column. This code should be used with XGBOOST_TYPE_SWITCH
     to determine type of bin id's */
  inline Column GetColumn(unsigned fid) const {
    Column c(type_[fid], &index_[boundary_[fid].index_begin], index_base_[fid],
             (type_[fid] == ColumnType::kSparseColumn ?
              &row_ind_[boundary_[fid].row_ind_begin] : nullptr),
             boundary_[fid].index_end - boundary_[fid].index_begin);
    return c;
  }

  inline uint32_t OGetRowFeatureBinIndex(size_t row_idx, int fid) const {
    // NOTE: `oaccess` between [row_idx * nfeature, (row_idx + 1) * nfeature]
    // return row_wise_index_[row_idx * nfeature_ + fid];
    return ObliviousArrayAccess(row_wise_index_.data() + row_idx * nfeature_,
                                fid, nfeature_);
  }

 private:
  struct ColumnBoundary {
    // indicate where each column's index and row_ind is stored.
    // index_begin and index_end are logical offsets, so they should be converted to
    // actual offsets by scaling with packing_factor_
    size_t index_begin;
    size_t index_end;
    size_t row_ind_begin;
    size_t row_ind_end;
  };

  std::vector<size_t> feature_counts_;
  std::vector<ColumnType> type_;
  SimpleArray<uint32_t> index_;  // index_: may store smaller integers; needs padding
  SimpleArray<size_t> row_ind_;
  std::vector<ColumnBoundary> boundary_;

  // For oblivious.
  // Row wise feature index, this helps reduce `oaccess` range to number of features.
  SimpleArray<uint32_t> row_wise_index_;
  int32_t nfeature_;

  // index_base_[fid]: least bin id for feature fid
  std::vector<uint32_t> index_base_;
};

}  // namespace common
}  // namespace xgboost
#endif  // XGBOOST_COMMON_COLUMN_MATRIX_H_
#endif  // __ENCLAVE_OBLIVIOUS__ 
