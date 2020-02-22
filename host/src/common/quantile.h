/*!
 * Copyright 2014 by Contributors
 * \file quantile.h
 * \brief util to compute quantiles
 * \author Tianqi Chen
 */
#ifndef XGBOOST_COMMON_QUANTILE_H_
#define XGBOOST_COMMON_QUANTILE_H_

#include <dmlc/base.h>
#include <xgboost/logging.h>
#include <algorithm>
#include <cmath>
#include <cstring>
#include <iostream>
#include <vector>
#include "obl_primitives.h"

namespace xgboost {
namespace common {

bool ObliviousSetCombineEnabled();
bool ObliviousSetPruneEnabled();
bool ObliviousDebugCheckEnabled();
bool ObliviousEnabled();

template <typename DType, typename RType>
struct WQSummaryEntry {
  /*! \brief minimum rank */
  RType rmin;
  /*! \brief maximum rank */
  RType rmax;
  /*! \brief maximum weight */
  RType wmin;
  /*! \brief the value of data */
  DType value;
  // constructor
  XGBOOST_DEVICE WQSummaryEntry() {}  // NOLINT
  // constructor
  XGBOOST_DEVICE WQSummaryEntry(RType rmin, RType rmax, RType wmin, DType value)
      : rmin(rmin), rmax(rmax), wmin(wmin), value(value) {}
  /*!
   * \brief debug function,  check Valid
   * \param eps the tolerate level for violating the relation
   */
  inline void CheckValid(RType eps = 0) const {
    CHECK(rmin >= 0 && rmax >= 0 && wmin >= 0) << "nonneg constraint";
    CHECK(rmax - rmin - wmin > -eps) << "relation constraint: min/max";
  }

  // For bitonic sort/merge.
  inline bool operator<(const WQSummaryEntry &b) const {
    return value < b.value;
  }

  inline bool operator==(const WQSummaryEntry &b) const {
    return value == b.value && rmin == b.rmin && rmax == b.rmax &&
           wmin == b.wmin;
  }

  inline bool operator!=(const WQSummaryEntry &b) const {
    return !(*this == b);
  }

  /*! \return rmin estimation for v strictly bigger than value */
  XGBOOST_DEVICE inline RType RMinNext() const { return rmin + wmin; }
  /*! \return rmax estimation for v strictly smaller than value */
  XGBOOST_DEVICE inline RType RMaxPrev() const { return rmax - wmin; }
};

template <typename DType, typename RType>
std::ostream &operator<<(std::ostream &out,
                         const WQSummaryEntry<DType, RType> &entry) {
  out << "[ v=" << entry.value << ", w=" << entry.wmin
      << ", rmin,rmax=" << entry.rmin << "," << entry.rmax << " ]";
  return out;
}

template <typename DType, typename RType>
struct WQSummaryQEntry {
  // value of the instance
  DType value;
  // weight of instance
  RType weight;
  // default constructor
  WQSummaryQEntry() = default;
  // constructor
  WQSummaryQEntry(DType value, RType weight) : value(value), weight(weight) {}
  // comparator on value
  inline bool operator<(const WQSummaryQEntry &b) const {
    return value < b.value;
  }
};

template <typename DType, typename RType>
std::ostream &operator<<(std::ostream &out,
                         const WQSummaryQEntry<DType, RType> &entry) {
  out << "[ v=" << entry.value << ", w=" << entry.weight << " ]";
  return out;
}

template <typename DType, typename RType>
struct WQSummaryQEntryHelper {
  using QEntry = WQSummaryQEntry<DType, RType>;
  // Entry
  QEntry entry;
  // New
  bool is_new;
  // default constructor
  WQSummaryQEntryHelper() = default;
  // constructor
  WQSummaryQEntryHelper(DType value, RType weight)
      : entry(value, weight), is_new(false) {}
  // ctor from entry
  WQSummaryQEntryHelper(const QEntry &entry) : entry(entry), is_new(false) {}
  // comparator
  inline bool operator<(const WQSummaryQEntryHelper &b) const {
    return entry < b.entry;
  }
};

template <typename DType, typename RType>
std::ostream &operator<<(std::ostream &out,
                         const WQSummaryQEntryHelper<DType, RType> &entry) {
  out << "[ entry=" << entry << ", is_new=" << entry.is_new
      << ", wsum=" << entry.wsum << " ]";
  return out;
}

template <typename DType, typename RType>
struct PruneItem {
  using Entry = WQSummaryEntry<DType, RType>;
  Entry entry;
  RType rank;
  bool has_entry;

  inline bool operator<(const PruneItem &rhs) const {
    return rank < rhs.rank ||
           (rank == rhs.rank && entry.value < rhs.entry.value);
  }
};

template <typename DType, typename RType>
std::ostream &operator<<(std::ostream &out,
                         const PruneItem<DType, RType> &item) {
  out << item.entry << ", rank=" << item.rank
      << ", has_entry=" << item.has_entry;
  return out;
}

template <typename DType, typename RType>
struct EntryWithPartyInfo {
  using Entry = WQSummaryEntry<DType, RType>;
  Entry entry;
  bool is_party_a;

  inline bool operator<(const EntryWithPartyInfo &b) const {
    return entry < b.entry;
  }
};

template <typename DType, typename RType>
std::ostream &operator<<(std::ostream &out,
                         const EntryWithPartyInfo<DType, RType> &item) {
  out << item.entry << ", is_party_a=" << item.is_party_a;
  return out;
}

}  // namespace common
}  // namespace xgboost

namespace obl {

// Implement oblivious less.

using SummaryEntry = ::xgboost::common::WQSummaryEntry<float, float>;
using SummaryQEntry = ::xgboost::common::WQSummaryQEntry<float, float>;
using SummaryPruneItem = ::xgboost::common::PruneItem<float, float>;
using SummaryEntryWithPartyInfo =
    ::xgboost::common::EntryWithPartyInfo<float, float>;

template <>
struct less<SummaryEntry> {
  bool operator()(const SummaryEntry &x, const SummaryEntry &y) {
    return ObliviousLess(x.value, y.value);
  }
};

template <>
struct less<SummaryQEntry> {
  bool operator()(const SummaryQEntry &x, const SummaryQEntry &y) {
    return ObliviousLess(x.value, y.value);
  }
};

template <>
struct less<SummaryPruneItem> {
  bool operator()(const SummaryPruneItem &a, const SummaryPruneItem &b) {
    bool b0 = ObliviousLess(a.rank, b.rank);
    bool same_rank = ObliviousEqual(a.rank, b.rank);
    bool b1 = ObliviousChoose(
        same_rank, ::obl::less<SummaryPruneItem::Entry>()(a.entry, b.entry),
        false);
    bool ret = ObliviousChoose(b0, true, b1);
    CHECK_EQ(ret, a < b) << "a=" << a << ", b=" << b;
    return ret;
  }
};

template <>
struct less<SummaryEntryWithPartyInfo> {
  bool operator()(const SummaryEntryWithPartyInfo &a,
                  const SummaryEntryWithPartyInfo &b) {
    return ObliviousLess(a.entry, b.entry);
  }
};

}  // namespace obl

namespace xgboost {
namespace common {

template <typename DType, typename RType>
struct WQSummary;

template <typename DType, typename RType>
void CheckEqualSummary(const WQSummary<DType, RType> &lhs,
                       const WQSummary<DType, RType> &rhs) {
  auto trace = [&]() {
    LOG(CONSOLE) << "---------- lhs: ";
    lhs.Print();
    LOG(CONSOLE) << "---------- rhs: ";
    rhs.Print();
  };
  // DEBUG CHECK
  if (lhs.size != rhs.size) {
    trace();
    LOG(FATAL) << "lhs.size=" << lhs.size << ", rhs.size=" << rhs.size;
  }
  for (size_t i = 0; i < lhs.size; ++i) {
    if (lhs.data[i] != rhs.data[i]) {
      trace();
      LOG(FATAL) << "Results mismatch in index " << i;
    }
  }
}

/*!
 * \brief experimental wsummary
 * \tparam DType type of data content
 * \tparam RType type of rank
 */
template <typename DType, typename RType>
struct WQSummary {
  /*! \brief an entry in the sketch summary */
  using Entry = WQSummaryEntry<DType, RType>;

  /*! \brief input data queue before entering the summary */
  struct Queue {
    // entry in the queue
    using QEntry = WQSummaryQEntry<DType, RType>;
    using QEntryHelper = WQSummaryQEntryHelper<DType, RType>;
    // the input queue
    std::vector<QEntry> queue;
    // end of the queue
    size_t qtail;
    // push data to the queue
    inline void Push(DType x, RType w) {
      if (qtail == 0 || queue[qtail - 1].value != x) {
        queue[qtail++] = QEntry(x, w);
      } else {
        queue[qtail - 1].weight += w;
      }
    }

    inline void MakeSummary(WQSummary *out) {
      if (ObliviousEnabled()) {
        return MakeSummaryOblivious(out);
      } else {
        return MakeSummaryRaw(out);
      }
    }

    inline void MakeSummaryRaw(WQSummary *out) {
      std::sort(queue.begin(), queue.begin() + qtail);

      out->size = 0;
      // start update sketch
      RType wsum = 0;
      // construct data with unique weights
      for (size_t i = 0; i < qtail;) {
        size_t j = i + 1;
        RType w = queue[i].weight;
        while (j < qtail && queue[j].value == queue[i].value) {
          w += queue[j].weight;
          ++j;
        }
        out->data[out->size++] = Entry(wsum, wsum + w, w, queue[i].value);
        wsum += w;
        i = j;
      }
    }

    inline void MakeSummaryOblivious(WQSummary *out) {
      ObliviousSort(queue.begin(), queue.begin() + qtail);

      std::vector<QEntryHelper> qhelper(queue.begin(), queue.begin() + qtail);

      for (auto &helper_entry : qhelper) {
        // zero weights
        helper_entry.entry.weight = 0;
      }

      size_t unique_count = 0;
      for (size_t idx = 0; idx < qhelper.size(); ++idx) {
        // sum weight for same value
        qhelper[idx].entry.weight += queue[idx].weight;
        // next is not same as me
        bool is_new = idx == qhelper.size() - 1
                          ? true
                          : !ObliviousEqual(qhelper[idx + 1].entry.value,
                                            qhelper[idx].entry.value);
        qhelper[idx].is_new = is_new;
        unique_count += is_new;
        if (idx != qhelper.size() - 1) {
          // Accumulate when next is same with me, otherwise reset to zero.
          qhelper[idx + 1].entry.weight =
              ObliviousChoose(is_new, 0.f, qhelper[idx].entry.weight);
        }
      }

      struct IsNewDescendingSorter {
        bool operator()(const QEntryHelper &a, const QEntryHelper &b) {
          return ObliviousGreater(a.is_new, b.is_new);
        }
      };

      struct ValueSorter {
        bool operator()(const QEntryHelper &a, const QEntryHelper &b) {
          return ObliviousLess(a.entry.value, b.entry.value);
        }
      };

      // Remove duplicates.
      ObliviousSort(qhelper.begin(), qhelper.end(), IsNewDescendingSorter());

      // Resort by value.
      ObliviousSort(qhelper.begin(), qhelper.begin() + unique_count,
                    ValueSorter());

      out->size = 0;
      RType wsum = 0;
      for (size_t idx = 0; idx < unique_count; ++idx) {
        const RType w = qhelper[idx].entry.weight;
        out->data[out->size++] =
            Entry(wsum, wsum + w, w, qhelper[idx].entry.value);
        wsum += w;
      }

      if (ObliviousDebugCheckEnabled()) {
        std::vector<Entry> oblivious_results(out->data, out->data + out->size);
        this->MakeSummaryRaw(out);
        CheckEqualSummary(*out, WQSummary(oblivious_results.data(),
                                          oblivious_results.size()));
      }
    }
  };
  /*! \brief data field */
  Entry *data;
  /*! \brief number of elements in the summary */
  size_t size;
  // constructor
  WQSummary(Entry *data, size_t size) : data(data), size(size) {}
  /*!
   * \return the maximum error of the Summary
   */
  inline RType MaxError() const {
    RType res = data[0].rmax - data[0].rmin - data[0].wmin;
    for (size_t i = 1; i < size; ++i) {
      res = std::max(data[i].RMaxPrev() - data[i - 1].RMinNext(), res);
      res = std::max(data[i].rmax - data[i].rmin - data[i].wmin, res);
    }
    return res;
  }
  /*!
   * \brief query qvalue, start from istart
   * \param qvalue the value we query for
   * \param istart starting position
   */
  inline Entry Query(DType qvalue, size_t &istart) const {  // NOLINT(*)
    while (istart < size && qvalue > data[istart].value) {
      ++istart;
    }
    if (istart == size) {
      RType rmax = data[size - 1].rmax;
      return Entry(rmax, rmax, 0.0f, qvalue);
    }
    if (qvalue == data[istart].value) {
      return data[istart];
    } else {
      if (istart == 0) {
        return Entry(0.0f, 0.0f, 0.0f, qvalue);
      } else {
        return Entry(data[istart - 1].RMinNext(), data[istart].RMaxPrev(), 0.0f,
                     qvalue);
      }
    }
  }
  /*! \return maximum rank in the summary */
  inline RType MaxRank() const { return data[size - 1].rmax; }
  /*!
   * \brief copy content from src
   * \param src source sketch
   */
  inline void CopyFrom(const WQSummary &src) {
    size = src.size;
    std::memcpy(data, src.data, sizeof(Entry) * size);
  }
  inline void MakeFromSorted(const Entry *entries, size_t n) {
    size = 0;
    for (size_t i = 0; i < n;) {
      size_t j = i + 1;
      // ignore repeated values
      for (; j < n && entries[j].value == entries[i].value; ++j) {
      }
      data[size++] = Entry(entries[i].rmin, entries[i].rmax, entries[i].wmin,
                           entries[i].value);
      i = j;
    }
  }
  /*!
   * \brief debug function, validate whether the summary
   *  run consistency check to check if it is a valid summary
   * \param eps the tolerate error level, used when RType is floating point and
   *        some inconsistency could occur due to rounding error
   */
  inline void CheckValid(RType eps) const {
    for (size_t i = 0; i < size; ++i) {
      data[i].CheckValid(eps);
      if (i != 0) {
        CHECK(data[i].rmin >= data[i - 1].rmin + data[i - 1].wmin)
            << "rmin range constraint";
        CHECK(data[i].rmax >= data[i - 1].rmax + data[i].wmin)
            << "rmax range constraint";
      }
    }
  }

  /*!
   * \brief set current summary to be pruned summary of src
   *        assume data field is already allocated to be at least maxsize
   * \param src source summary
   * \param maxsize size we can afford in the pruned sketch
   */
  inline void ObliviousSetPrune(const WQSummary &src, size_t maxsize) {
    if (src.size <= maxsize) {
      this->CopyFrom(src);
      return;
    }

    // Make sure dx2 items are last one when `d == (rmax + rmin) / 2`.
    const Entry kDummyEntryWithMaxValue{0, 0, 1,
                                        std::numeric_limits<DType>::max()};

    const RType begin = src.data[0].rmax;
    const RType range = src.data[src.size - 1].rmin - src.data[0].rmax;
    const size_t n = maxsize - 1;

    // Construct sort vector.
    using Item = PruneItem<DType, RType>;
    std::vector<Item> items;
    items.reserve(2 * src.size + n);
    for (size_t k = 1; k < n; ++k) {
      RType dx2 = 2 * ((k * range) / n + begin);
      items.push_back(Item{kDummyEntryWithMaxValue, dx2, false});
    }
    std::transform(src.data + 1, src.data + src.size, std::back_inserter(items),
                   [](const Entry &entry) {
                     return Item{entry, entry.rmax + entry.rmin, true};
                   });
    for (size_t i = 1; i < src.size - 1; ++i) {
      items.push_back(Item{src.data[i],
                           src.data[i].RMinNext() + src.data[i + 1].RMaxPrev(),
                           true});
    }

    // Bitonic Sort.
    LOG(DEBUG) << __func__ << " BEGIN 1" << std::endl;
    ObliviousSort(items.begin(), items.end());
    LOG(DEBUG) << __func__ << " PASSED 1" << std::endl;

    // Choose entrys.
    RType last_selected_entry_value = std::numeric_limits<RType>::min();
    size_t select_count = 0;
    for (size_t i = 1; i < items.size(); ++i) {
      bool do_select = !items[i - 1].has_entry && items[i].has_entry &&
                       items[i].entry.value != last_selected_entry_value;
      ObliviousAssign(do_select, items[i].entry.value,
                      last_selected_entry_value, &last_selected_entry_value);
      ObliviousAssign(do_select, std::numeric_limits<RType>::min(),
                      items[i].rank, &items[i].rank);
      select_count += ObliviousChoose(do_select, 1, 0);
    }
    // Bitonic Sort.
    LOG(DEBUG) << __func__ << " BEGIN 2" << std::endl;
    ObliviousSort(items.begin(), items.end());
    LOG(DEBUG) << __func__ << " PASSED 2" << std::endl;

    this->data[0] = src.data[0];
    this->size = 1 + select_count;
    std::transform(items.begin(), items.begin() + select_count, this->data + 1,
                   [](const Item &item) {
                     CHECK(item.has_entry &&
                           item.rank == std::numeric_limits<RType>::min());
                     return item.entry;
                   });

    // First and last ones are always kept in prune.
    if (data[size - 1].value != src.data[src.size - 1].value) {
      CHECK(size < maxsize);
      data[size++] = src.data[src.size - 1];
    }

    if (ObliviousDebugCheckEnabled()) {
      std::vector<Entry> oblivious_results(data, data + size);
      RawSetPrune(src, maxsize);
      CheckEqualSummary(
          *this, WQSummary(oblivious_results.data(), oblivious_results.size()));
    }
  }

  /*!
   * \brief set current summary to be pruned summary of src
   *        assume data field is already allocated to be at least maxsize
   * \param src source summary
   * \param maxsize size we can afford in the pruned sketch
   */
  inline void RawSetPrune(const WQSummary &src, size_t maxsize) {
    if (src.size <= maxsize) {
      this->CopyFrom(src);
      return;
    }
    const RType begin = src.data[0].rmax;
    const RType range = src.data[src.size - 1].rmin - src.data[0].rmax;
    const size_t n = maxsize - 1;
    data[0] = src.data[0];
    this->size = 1;
    // lastidx is used to avoid duplicated records
    size_t i = 1, lastidx = 0;
    for (size_t k = 1; k < n; ++k) {
      RType dx2 = 2 * ((k * range) / n + begin);
      // find first i such that  d < (rmax[i+1] + rmin[i+1]) / 2
      while (i < src.size - 1 &&
             dx2 >= src.data[i + 1].rmax + src.data[i + 1].rmin)
        ++i;
      CHECK(i != src.size - 1);
      if (dx2 < src.data[i].RMinNext() + src.data[i + 1].RMaxPrev()) {
        if (i != lastidx) {
          data[size++] = src.data[i];
          lastidx = i;
        }
      } else {
        if (i + 1 != lastidx) {
          data[size++] = src.data[i + 1];
          lastidx = i + 1;
        }
      }
    }
    if (lastidx != src.size - 1) {
      data[size++] = src.data[src.size - 1];
    }
  }
  /*!
   * \brief set current summary to be pruned summary of src
   *        assume data field is already allocated to be at least maxsize
   * \param src source summary
   * \param maxsize size we can afford in the pruned sketch
   */

  inline void SetPrune(const WQSummary &src, size_t maxsize) {
    if (ObliviousSetPruneEnabled())
      return ObliviousSetPrune(src, maxsize);
    else
      return RawSetPrune(src, maxsize);
  }

  /*!
   * \brief set current summary to be merged summary of sa and sb
   * \param sa first input summary to be merged
   * \param sb second input summary to be merged
   */
  inline void ObliviousSetCombine(const WQSummary &sa, const WQSummary &sb) {
    this->size = sa.size + sb.size;
    if (this->size == 0) {
      return;
    }

    // TODO: need confirm.
    if (sa.size == 0) {
      this->CopyFrom(sb);
      return;
    }
    if (sb.size == 0) {
      this->CopyFrom(sa);
      return;
    }

    using EntryWithPartyInfo = EntryWithPartyInfo<DType, RType>;

    std::vector<EntryWithPartyInfo> merged_party_entrys(this->size);
    // Fill party info and build bitonic sequence.
    std::transform(sa.data, sa.data + sa.size, merged_party_entrys.begin(),
                   [](const Entry &entry) {
                     return EntryWithPartyInfo{entry, true};
                   });
    std::transform(sb.data, sb.data + sb.size,
                   merged_party_entrys.begin() + sa.size,
                   [](const Entry &entry) {
                     return EntryWithPartyInfo{entry, false};
                   });
    // Build bitonic sequence.
    std::reverse(merged_party_entrys.begin(),
                 merged_party_entrys.begin() + sa.size);
    // Bitonic merge.
    // ObliviousSort(merged_party_entrys.begin(), merged_party_entrys.end());
    ObliviousMerge(merged_party_entrys.begin(), merged_party_entrys.end());

    // Forward pass to compute rmin.
    RType a_prev_rmin = 0;
    RType b_prev_rmin = 0;
    for (size_t idx = 0; idx < merged_party_entrys.size(); ++idx) {
      bool equal_next =
          (idx == merged_party_entrys.size() - 1)
              ? false
              : ObliviousEqual(merged_party_entrys[idx].entry.value,
                               merged_party_entrys[idx + 1].entry.value);
      bool equal_prev =
          idx == 0 ? false
                   : ObliviousEqual(merged_party_entrys[idx].entry.value,
                                    merged_party_entrys[idx - 1].entry.value);

      // Save first.
      RType next_aprev_rmin = ObliviousChoose(
          merged_party_entrys[idx].is_party_a,
          merged_party_entrys[idx].entry.RMinNext(), a_prev_rmin);
      RType next_bprev_rmin = ObliviousChoose(
          !merged_party_entrys[idx].is_party_a,
          merged_party_entrys[idx].entry.RMinNext(), b_prev_rmin);

      // This is a. Need to add previous b->RMinNext().
      RType chosen_prev_rmin = ObliviousChoose(
          merged_party_entrys[idx].is_party_a, b_prev_rmin, a_prev_rmin);

      // Update rmin. Skip for equal groups now.
      RType rmin_to_add = ObliviousChoose(
          equal_next || equal_prev, static_cast<RType>(0), chosen_prev_rmin);
      merged_party_entrys[idx].entry.rmin += rmin_to_add;

      // Update prev_rmin.
      a_prev_rmin = next_aprev_rmin;
      b_prev_rmin = next_bprev_rmin;
    }

    // Backward pass to compute rmax.
    RType a_prev_rmax = sa.data[sa.size - 1].rmax;
    RType b_prev_rmax = sb.data[sb.size - 1].rmax;
    size_t duplicate_count = 0;
    for (ssize_t idx = merged_party_entrys.size() - 1; idx >= 0; --idx) {
      bool equal_prev =
          idx == 0 ? false
                   : ObliviousEqual(merged_party_entrys[idx].entry.value,
                                    merged_party_entrys[idx - 1].entry.value);
      bool equal_next =
          idx == merged_party_entrys.size() - 1
              ? false
              : ObliviousEqual(merged_party_entrys[idx].entry.value,
                               merged_party_entrys[idx + 1].entry.value);
      duplicate_count += ObliviousChoose(equal_next, 1, 0);

      // Need to save first since the rmax will be overwritten.
      RType next_aprev_rmax = ObliviousChoose(
          merged_party_entrys[idx].is_party_a,
          merged_party_entrys[idx].entry.RMaxPrev(), a_prev_rmax);
      RType next_bprev_rmax = ObliviousChoose(
          !merged_party_entrys[idx].is_party_a,
          merged_party_entrys[idx].entry.RMaxPrev(), b_prev_rmax);

      // Add peer RMaxPrev.
      RType rmax_to_add = ObliviousChoose(merged_party_entrys[idx].is_party_a,
                                          b_prev_rmax, a_prev_rmax);
      // Handle equals.
      RType rmin_to_add =
          ObliviousChoose(equal_prev, merged_party_entrys[idx - 1].entry.rmin,
                          static_cast<RType>(0));
      RType wmin_to_add =
          ObliviousChoose(equal_prev, merged_party_entrys[idx - 1].entry.wmin,
                          static_cast<RType>(0));
      rmax_to_add = ObliviousChoose(
          equal_prev, merged_party_entrys[idx - 1].entry.rmax, rmax_to_add);
      // Update.
      merged_party_entrys[idx].entry.rmax += rmax_to_add;
      merged_party_entrys[idx].entry.rmin += rmin_to_add;
      merged_party_entrys[idx].entry.wmin += wmin_to_add;

      // Copy rmin, rmax, wmin from previous if values are equal.
      // Value is ok to be infinite now since this is two party merge, at most
      // two items are the same given a specific value.
      ObliviousAssign(equal_next, merged_party_entrys[idx + 1].entry,
                      merged_party_entrys[idx].entry,
                      &merged_party_entrys[idx].entry);
      ObliviousAssign(equal_next, std::numeric_limits<DType>::max(),
                      merged_party_entrys[idx].entry.value,
                      &merged_party_entrys[idx].entry.value);

      a_prev_rmax = next_aprev_rmax;
      b_prev_rmax = next_bprev_rmax;
    }

    // Bitonic sort to push duplicates to end of list.
    std::transform(merged_party_entrys.begin(), merged_party_entrys.end(),
                   this->data, [](const EntryWithPartyInfo &party_entry) {
                     return party_entry.entry;
                   });
    LOG(DEBUG) << __func__ << " BEGIN 3" << std::endl;
    ObliviousSort(this->data, this->data + this->size);
    // std::sort(this->data, this->data + this->size);
    LOG(DEBUG) << __func__ << " PASSED 3" << std::endl;

    // Need to confirm shrink.
    this->size -= duplicate_count;

    if (ObliviousDebugCheckEnabled()) {
      std::vector<Entry> oblivious_results(this->data, this->data + this->size);
      RawSetCombine(sa, sb);
      CheckEqualSummary(
          *this, WQSummary(oblivious_results.data(), oblivious_results.size()));
    }
  }

  /*!
   * \brief set current summary to be merged summary of sa and sb
   * \param sa first input summary to be merged
   * \param sb second input summary to be merged
   */
  inline void RawSetCombine(const WQSummary &sa, const WQSummary &sb) {
    if (sa.size == 0) {
      this->CopyFrom(sb);
      return;
    }
    if (sb.size == 0) {
      this->CopyFrom(sa);
      return;
    }
    CHECK(sa.size > 0 && sb.size > 0);
    const Entry *a = sa.data, *a_end = sa.data + sa.size;
    const Entry *b = sb.data, *b_end = sb.data + sb.size;
    // extended rmin value
    RType aprev_rmin = 0, bprev_rmin = 0;
    Entry *dst = this->data;
    while (a != a_end && b != b_end) {
      // duplicated value entry
      if (a->value == b->value) {
        *dst = Entry(a->rmin + b->rmin, a->rmax + b->rmax, a->wmin + b->wmin,
                     a->value);
        aprev_rmin = a->RMinNext();
        bprev_rmin = b->RMinNext();
        ++dst;
        ++a;
        ++b;
      } else if (a->value < b->value) {
        *dst = Entry(a->rmin + bprev_rmin, a->rmax + b->RMaxPrev(), a->wmin,
                     a->value);
        aprev_rmin = a->RMinNext();
        ++dst;
        ++a;
      } else {
        *dst = Entry(b->rmin + aprev_rmin, b->rmax + a->RMaxPrev(), b->wmin,
                     b->value);
        bprev_rmin = b->RMinNext();
        ++dst;
        ++b;
      }
    }
    if (a != a_end) {
      RType brmax = (b_end - 1)->rmax;
      do {
        *dst = Entry(a->rmin + bprev_rmin, a->rmax + brmax, a->wmin, a->value);
        ++dst;
        ++a;
      } while (a != a_end);
    }
    if (b != b_end) {
      RType armax = (a_end - 1)->rmax;
      do {
        *dst = Entry(b->rmin + aprev_rmin, b->rmax + armax, b->wmin, b->value);
        ++dst;
        ++b;
      } while (b != b_end);
    }
    this->size = dst - data;
    const RType tol = 10;
    RType err_mingap, err_maxgap, err_wgap;
    this->FixError(&err_mingap, &err_maxgap, &err_wgap);
    if (err_mingap > tol || err_maxgap > tol || err_wgap > tol) {
      LOG(INFO) << "mingap=" << err_mingap << ", maxgap=" << err_maxgap
                << ", wgap=" << err_wgap;
    }
    CHECK(size <= sa.size + sb.size) << "bug in combine";
  }
  /*!
   * \brief set current summary to be merged summary of sa and sb
   * \param sa first input summary to be merged
   * \param sb second input summary to be merged
   */
  inline void SetCombine(const WQSummary &sa, const WQSummary &sb) {
    if (ObliviousSetCombineEnabled())
      return ObliviousSetCombine(sa, sb);
    else
      return RawSetCombine(sa, sb);
  }
  // helper function to print the current content of sketch
  inline void Print() const {
    for (size_t i = 0; i < this->size; ++i) {
      LOG(CONSOLE) << "[" << i << "] rmin=" << data[i].rmin
                   << ", rmax=" << data[i].rmax << ", wmin=" << data[i].wmin
                   << ", v=" << data[i].value;
    }
  }

  inline void CheckAndPrint() const {
    CheckValid(kRtEps);
    Print();
  }

  // try to fix rounding error
  // and re-establish invariance
  inline void FixError(RType *err_mingap, RType *err_maxgap,
                       RType *err_wgap) const {
    *err_mingap = 0;
    *err_maxgap = 0;
    *err_wgap = 0;
    RType prev_rmin = 0, prev_rmax = 0;
    for (size_t i = 0; i < this->size; ++i) {
      if (data[i].rmin < prev_rmin) {
        data[i].rmin = prev_rmin;
        *err_mingap = std::max(*err_mingap, prev_rmin - data[i].rmin);
      } else {
        prev_rmin = data[i].rmin;
      }
      if (data[i].rmax < prev_rmax) {
        data[i].rmax = prev_rmax;
        *err_maxgap = std::max(*err_maxgap, prev_rmax - data[i].rmax);
      }
      RType rmin_next = data[i].RMinNext();
      if (data[i].rmax < rmin_next) {
        data[i].rmax = rmin_next;
        *err_wgap = std::max(*err_wgap, data[i].rmax - rmin_next);
      }
      prev_rmax = data[i].rmax;
    }
  }
  // check consistency of the summary
  inline bool Check(const char *msg) const {
    const float tol = 10.0f;
    for (size_t i = 0; i < this->size; ++i) {
      if (data[i].rmin + data[i].wmin > data[i].rmax + tol ||
          data[i].rmin < -1e-6f || data[i].rmax < -1e-6f) {
        LOG(INFO) << "---------- WQSummary::Check did not pass ----------";
        this->Print();
        return false;
      }
    }
    return true;
  }
};

/*! \brief try to do efficient pruning */
template <typename DType, typename RType>
struct WXQSummary : public WQSummary<DType, RType> {
  // redefine entry type
  using Entry = typename WQSummary<DType, RType>::Entry;
  // constructor
  WXQSummary(Entry *data, size_t size) : WQSummary<DType, RType>(data, size) {}
  // check if the block is large chunk
  inline static bool CheckLarge(const Entry &e, RType chunk) {
    return e.RMinNext() > e.RMaxPrev() + chunk;
  }
  // set prune
  inline void SetPrune(const WQSummary<DType, RType> &src, size_t maxsize) {
    if (ObliviousSetPruneEnabled()) {
      return WQSummary<DType, RType>::ObliviousSetPrune(src, maxsize);
    }
    if (src.size <= maxsize) {
      this->CopyFrom(src);
      return;
    }
    RType begin = src.data[0].rmax;
    // n is number of points exclude the min/max points
    size_t n = maxsize - 2, nbig = 0;
    // these is the range of data exclude the min/max point
    RType range = src.data[src.size - 1].rmin - begin;
    // prune off zero weights
    if (range == 0.0f || maxsize <= 2) {
      // special case, contain only two effective data pts
      this->data[0] = src.data[0];
      this->data[1] = src.data[src.size - 1];
      this->size = 2;
      return;
    } else {
      range = std::max(range, static_cast<RType>(1e-3f));
    }
    // Get a big enough chunk size, bigger than range / n
    // (multiply by 2 is a safe factor)
    const RType chunk = 2 * range / n;
    // minimized range
    RType mrange = 0;
    {
      // first scan, grab all the big chunk
      // moving block index, exclude the two ends.
      size_t bid = 0;
      for (size_t i = 1; i < src.size - 1; ++i) {
        // detect big chunk data point in the middle
        // always save these data points.
        if (CheckLarge(src.data[i], chunk)) {
          if (bid != i - 1) {
            // accumulate the range of the rest points
            mrange += src.data[i].RMaxPrev() - src.data[bid].RMinNext();
          }
          bid = i;
          ++nbig;
        }
      }
      if (bid != src.size - 2) {
        mrange += src.data[src.size - 1].RMaxPrev() - src.data[bid].RMinNext();
      }
    }
    // assert: there cannot be more than n big data points
    if (nbig >= n) {
      // see what was the case
      LOG(INFO) << " check quantile stats, nbig=" << nbig << ", n=" << n;
      LOG(INFO) << " srcsize=" << src.size << ", maxsize=" << maxsize
                << ", range=" << range << ", chunk=" << chunk;
      src.Print();
      CHECK(nbig < n) << "quantile: too many large chunk";
    }
    this->data[0] = src.data[0];
    this->size = 1;
    // The counter on the rest of points, to be selected equally from small
    // chunks.
    n = n - nbig;
    // find the rest of point
    size_t bid = 0, k = 1, lastidx = 0;
    for (size_t end = 1; end < src.size; ++end) {
      if (end == src.size - 1 || CheckLarge(src.data[end], chunk)) {
        if (bid != end - 1) {
          size_t i = bid;
          RType maxdx2 = src.data[end].RMaxPrev() * 2;
          for (; k < n; ++k) {
            RType dx2 = 2 * ((k * mrange) / n + begin);
            if (dx2 >= maxdx2) break;
            while (i < end &&
                   dx2 >= src.data[i + 1].rmax + src.data[i + 1].rmin)
              ++i;
            if (i == end) break;
            if (dx2 < src.data[i].RMinNext() + src.data[i + 1].RMaxPrev()) {
              if (i != lastidx) {
                this->data[this->size++] = src.data[i];
                lastidx = i;
              }
            } else {
              if (i + 1 != lastidx) {
                this->data[this->size++] = src.data[i + 1];
                lastidx = i + 1;
              }
            }
          }
        }
        if (lastidx != end) {
          this->data[this->size++] = src.data[end];
          lastidx = end;
        }
        bid = end;
        // shift base by the gap
        begin += src.data[bid].RMinNext() - src.data[bid].RMaxPrev();
      }
    }
  }
};
/*!
 * \brief traditional GK summary
 */
template <typename DType, typename RType>
struct GKSummary {
  /*! \brief an entry in the sketch summary */
  struct Entry {
    /*! \brief minimum rank */
    RType rmin;
    /*! \brief maximum rank */
    RType rmax;
    /*! \brief the value of data */
    DType value;
    // constructor
    Entry() = default;
    // constructor
    Entry(RType rmin, RType rmax, DType value)
        : rmin(rmin), rmax(rmax), value(value) {}
  };
  /*! \brief input data queue before entering the summary */
  struct Queue {
    // the input queue
    std::vector<DType> queue;
    // end of the queue
    size_t qtail;
    // push data to the queue
    inline void Push(DType x, RType w) { queue[qtail++] = x; }
    inline void MakeSummary(GKSummary *out) {
      std::sort(queue.begin(), queue.begin() + qtail);
      out->size = qtail;
      for (size_t i = 0; i < qtail; ++i) {
        out->data[i] = Entry(i + 1, i + 1, queue[i]);
      }
    }
  };
  /*! \brief data field */
  Entry *data;
  /*! \brief number of elements in the summary */
  size_t size;
  GKSummary(Entry *data, size_t size) : data(data), size(size) {}
  /*! \brief the maximum error of the summary */
  inline RType MaxError() const {
    RType res = 0;
    for (size_t i = 1; i < size; ++i) {
      res = std::max(data[i].rmax - data[i - 1].rmin, res);
    }
    return res;
  }
  /*! \return maximum rank in the summary */
  inline RType MaxRank() const { return data[size - 1].rmax; }
  /*!
   * \brief copy content from src
   * \param src source sketch
   */
  inline void CopyFrom(const GKSummary &src) {
    size = src.size;
    std::memcpy(data, src.data, sizeof(Entry) * size);
  }
  inline void CheckValid(RType eps) const {
    // assume always valid
  }
  /*! \brief used for debug purpose, print the summary */
  inline void Print() const {
    for (size_t i = 0; i < size; ++i) {
      LOG(CONSOLE) << "x=" << data[i].value << "\t"
                   << "[" << data[i].rmin << "," << data[i].rmax << "]";
    }
  }
  /*!
   * \brief set current summary to be pruned summary of src
   *        assume data field is already allocated to be at least maxsize
   * \param src source summary
   * \param maxsize size we can afford in the pruned sketch
   */
  inline void SetPrune(const GKSummary &src, size_t maxsize) {
    if (src.size <= maxsize) {
      this->CopyFrom(src);
      return;
    }
    const RType max_rank = src.MaxRank();
    this->size = maxsize;
    data[0] = src.data[0];
    size_t n = maxsize - 1;
    RType top = 1;
    for (size_t i = 1; i < n; ++i) {
      RType k = (i * max_rank) / n;
      while (k > src.data[top + 1].rmax) ++top;
      // assert src.data[top].rmin <= k
      // because k > src.data[top].rmax >= src.data[top].rmin
      if ((k - src.data[top].rmin) < (src.data[top + 1].rmax - k)) {
        data[i] = src.data[top];
      } else {
        data[i] = src.data[top + 1];
      }
    }
    data[n] = src.data[src.size - 1];
  }
  inline void SetCombine(const GKSummary &sa, const GKSummary &sb) {
    if (sa.size == 0) {
      this->CopyFrom(sb);
      return;
    }
    if (sb.size == 0) {
      this->CopyFrom(sa);
      return;
    }
    CHECK(sa.size > 0 && sb.size > 0) << "invalid input for merge";
    const Entry *a = sa.data, *a_end = sa.data + sa.size;
    const Entry *b = sb.data, *b_end = sb.data + sb.size;
    this->size = sa.size + sb.size;
    RType aprev_rmin = 0, bprev_rmin = 0;
    Entry *dst = this->data;
    while (a != a_end && b != b_end) {
      if (a->value < b->value) {
        *dst = Entry(bprev_rmin + a->rmin, a->rmax + b->rmax - 1, a->value);
        aprev_rmin = a->rmin;
        ++dst;
        ++a;
      } else {
        *dst = Entry(aprev_rmin + b->rmin, b->rmax + a->rmax - 1, b->value);
        bprev_rmin = b->rmin;
        ++dst;
        ++b;
      }
    }
    if (a != a_end) {
      RType bprev_rmax = (b_end - 1)->rmax;
      do {
        *dst = Entry(bprev_rmin + a->rmin, bprev_rmax + a->rmax, a->value);
        ++dst;
        ++a;
      } while (a != a_end);
    }
    if (b != b_end) {
      RType aprev_rmax = (a_end - 1)->rmax;
      do {
        *dst = Entry(aprev_rmin + b->rmin, aprev_rmax + b->rmax, b->value);
        ++dst;
        ++b;
      } while (b != b_end);
    }
    CHECK(dst == data + size) << "bug in combine";
  }
};

/*!
 * \brief template for all quantile sketch algorithm
 *        that uses merge/prune scheme
 * \tparam DType type of data content
 * \tparam RType type of rank
 * \tparam TSummary actual summary data structure it uses
 */
template <typename DType, typename RType, class TSummary>
class QuantileSketchTemplate {
 public:
  /*! \brief type of summary type */
  using Summary = TSummary;
  /*! \brief the entry type */
  using Entry = typename Summary::Entry;
  /*! \brief same as summary, but use STL to backup the space */
  struct SummaryContainer : public Summary {
    std::vector<Entry> space;
    SummaryContainer(const SummaryContainer &src) : Summary(nullptr, src.size) {
      this->space = src.space;
      this->data = dmlc::BeginPtr(this->space);
    }
    SummaryContainer() : Summary(nullptr, 0) {}
    /*! \brief reserve space for summary */
    inline void Reserve(size_t size) {
      if (size > space.size()) {
        space.resize(size);
        this->data = dmlc::BeginPtr(space);
      }
    }
    /*!
     * \brief set the space to be merge of all Summary arrays
     * \param begin beginning position in the summary array
     * \param end ending position in the Summary array
     */
    inline void SetMerge(const Summary *begin, const Summary *end) {
      CHECK(begin < end) << "can not set combine to empty instance";
      size_t len = end - begin;
      if (len == 1) {
        this->Reserve(begin[0].size);
        this->CopyFrom(begin[0]);
      } else if (len == 2) {
        this->Reserve(begin[0].size + begin[1].size);
        this->SetMerge(begin[0], begin[1]);
      } else {
        // recursive merge
        SummaryContainer lhs, rhs;
        lhs.SetCombine(begin, begin + len / 2);
        rhs.SetCombine(begin + len / 2, end);
        this->Reserve(lhs.size + rhs.size);
        this->SetCombine(lhs, rhs);
      }
    }
    /*!
     * \brief do elementwise combination of summary array
     *        this[i] = combine(this[i], src[i]) for each i
     * \param src the source summary
     * \param max_nbyte maximum number of byte allowed in here
     */
    inline void Reduce(const Summary &src, size_t max_nbyte) {
      this->Reserve((max_nbyte - sizeof(this->size)) / sizeof(Entry));
      SummaryContainer temp;
      temp.Reserve(this->size + src.size);
      temp.SetCombine(*this, src);
      this->SetPrune(temp, space.size());
    }
    /*! \brief return the number of bytes this data structure cost in
     * serialization */
    inline static size_t CalcMemCost(size_t nentry) {
      return sizeof(size_t) + sizeof(Entry) * nentry;
    }
    /*! \brief save the data structure into stream */
    template <typename TStream>
    inline void Save(TStream &fo) const {  // NOLINT(*)
      fo.Write(&(this->size), sizeof(this->size));
      if (this->size != 0) {
        fo.Write(this->data, this->size * sizeof(Entry));
      }
    }
    /*! \brief load data structure from input stream */
    template <typename TStream>
    inline void Load(TStream &fi) {  // NOLINT(*)
      CHECK_EQ(fi.Read(&this->size, sizeof(this->size)), sizeof(this->size));
      this->Reserve(this->size);
      if (this->size != 0) {
        CHECK_EQ(fi.Read(this->data, this->size * sizeof(Entry)),
                 this->size * sizeof(Entry));
      }
    }
  };
  /*!
   * \brief initialize the quantile sketch, given the performance specification
   * \param maxn maximum number of data points can be feed into sketch
   * \param eps accuracy level of summary
   */
  inline void Init(size_t maxn, double eps) {
    LimitSizeLevel(maxn, eps, &nlevel, &limit_size);
    // lazy reserve the space, if there is only one value, no need to allocate
    // space
    inqueue.queue.resize(1);
    inqueue.qtail = 0;
    data.clear();
    level.clear();
  }

  inline static void LimitSizeLevel(size_t maxn, double eps, size_t *out_nlevel,
                                    size_t *out_limit_size) {
    size_t &nlevel = *out_nlevel;
    size_t &limit_size = *out_limit_size;
    nlevel = 1;
    while (true) {
      limit_size = static_cast<size_t>(ceil(nlevel / eps)) + 1;
      size_t n = (1ULL << nlevel);
      if (n * limit_size >= maxn) break;
      ++nlevel;
    }
    // check invariant
    size_t n = (1ULL << nlevel);
    CHECK(n * limit_size >= maxn) << "invalid init parameter";
    CHECK(nlevel <= limit_size * eps) << "invalid init parameter";
  }

  /*!
   * \brief add an element to a sketch
   * \param x The element added to the sketch
   * \param w The weight of the element.
   */
  inline void Push(DType x, RType w = 1) {
    if (w == static_cast<RType>(0)) return;
    if (inqueue.qtail == inqueue.queue.size()) {
      // jump from lazy one value to limit_size * 2
      if (inqueue.queue.size() == 1) {
        inqueue.queue.resize(limit_size * 2);
      } else {
        temp.Reserve(limit_size * 2);
        inqueue.MakeSummary(&temp);
        // cleanup queue
        inqueue.qtail = 0;
        this->PushTemp();
      }
    }
    inqueue.Push(x, w);
  }

  inline void PushSummary(const Summary &summary) {
    temp.Reserve(limit_size * 2);
    temp.SetPrune(summary, limit_size * 2);
    PushTemp();
  }

  /*! \brief push up temp */
  inline void PushTemp() {
    temp.Reserve(limit_size * 2);
    for (size_t l = 1; true; ++l) {
      this->InitLevel(l + 1);
      // check if level l is empty
      if (level[l].size == 0) {
        level[l].SetPrune(temp, limit_size);
        break;
      } else {
        // level 0 is actually temp space
        level[0].SetPrune(temp, limit_size);
        temp.SetCombine(level[0], level[l]);
        if (temp.size > limit_size) {
          // try next level
          level[l].size = 0;
        } else {
          // if merged record is still smaller, no need to send to next level
          level[l].CopyFrom(temp);
          break;
        }
      }
    }
  }
  /*! \brief get the summary after finalize */
  inline void GetSummary(SummaryContainer *out) {
    if (level.size() != 0) {
      out->Reserve(limit_size * 2);
    } else {
      out->Reserve(inqueue.queue.size());
    }
    inqueue.MakeSummary(out);
    if (level.size() != 0) {
      level[0].SetPrune(*out, limit_size);
      for (size_t l = 1; l < level.size(); ++l) {
        if (level[l].size == 0) continue;
        if (level[0].size == 0) {
          level[0].CopyFrom(level[l]);
        } else {
          out->SetCombine(level[0], level[l]);
          level[0].SetPrune(*out, limit_size);
        }
      }
      out->CopyFrom(level[0]);
    } else {
      if (out->size > limit_size) {
        temp.Reserve(limit_size);
        temp.SetPrune(*out, limit_size);
        out->CopyFrom(temp);
      }
    }
  }
  // used for debug, check if the sketch is valid
  inline void CheckValid(RType eps) const {
    for (size_t l = 1; l < level.size(); ++l) {
      level[l].CheckValid(eps);
    }
  }
  // initialize level space to at least nlevel
  inline void InitLevel(size_t nlevel) {
    if (level.size() >= nlevel) return;
    data.resize(limit_size * nlevel);
    level.resize(nlevel, Summary(nullptr, 0));
    for (size_t l = 0; l < level.size(); ++l) {
      level[l].data = dmlc::BeginPtr(data) + l * limit_size;
    }
  }
  // input data queue
  typename Summary::Queue inqueue;
  // number of levels
  size_t nlevel;
  // size of summary in each level
  size_t limit_size;
  // the level of each summaries
  std::vector<Summary> level;
  // content of the summary
  std::vector<Entry> data;
  // temporal summary, used for temp-merge
  SummaryContainer temp;
};

/*!
 * \brief Quantile sketch use WQSummary
 * \tparam DType type of data content
 * \tparam RType type of rank
 */
template <typename DType, typename RType = unsigned>
class WQuantileSketch
    : public QuantileSketchTemplate<DType, RType, WQSummary<DType, RType> > {};

/*!
 * \brief Quantile sketch use WXQSummary
 * \tparam DType type of data content
 * \tparam RType type of rank
 */
template <typename DType, typename RType = unsigned>
class WXQuantileSketch
    : public QuantileSketchTemplate<DType, RType, WXQSummary<DType, RType> > {};
/*!
 * \brief Quantile sketch use WQSummary
 * \tparam DType type of data content
 * \tparam RType type of rank
 */
template <typename DType, typename RType = unsigned>
class GKQuantileSketch
    : public QuantileSketchTemplate<DType, RType, GKSummary<DType, RType> > {};
}  // namespace common
}  // namespace xgboost
#endif  // XGBOOST_COMMON_QUANTILE_H_
