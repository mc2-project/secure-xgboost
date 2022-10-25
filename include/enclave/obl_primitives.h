/*
 * Modifications Copyright 2020-22 by Secure XGBoost Contributors
 */
#pragma once
#include <cstddef>
#include <cstdint>
#include <type_traits>
#include <cstring>

#ifdef USE_AVX2
#include <intrinsics/immintrin.h>
#endif

//----------------------------------------------------------------------------
// Interface

constexpr size_t CACHE_LINE_SIZE = 64;

template <typename T>
inline bool ObliviousLess(const T &x, const T &y);

template <typename T>
inline bool ObliviousLessOrEqual(const T &x, const T &y);

template <typename T>
inline bool ObliviousGreater(const T &x, const T &y);

template <typename T>
inline bool ObliviousGreaterOrEqual(const T &x, const T &y);

template <typename T,
          typename std::enable_if<std::is_scalar<T>::value, int>::type = 0>
inline bool ObliviousEqual(T x, T y);

template <typename T, typename std::enable_if<std::is_standard_layout<T>::value,
                                              int>::type = 0>
inline void ObliviousAssign(bool pred, const T &t_val, const T &f_val, T *out);

template <typename T>
inline T ObliviousChoose(bool pred, const T &t_val, const T &f_val);

template <typename Iter>
inline void ObliviousMerge(Iter begin, Iter end);

template <typename Iter>
inline void ObliviousSort(Iter begin, Iter end);

template <typename Iter, typename Comparator>
inline void ObliviousMerge(Iter begin, Iter end, Comparator cmp);

template <typename Iter, typename Comparator>
inline void ObliviousSort(Iter begin, Iter end, Comparator cmp);

template <typename T>
inline T ObliviousArrayAccess(const T *arr, size_t i, size_t n);

inline void ObliviousArrayAccessBytes(void *dst, const void *array,
                                      size_t nbytes, size_t i, size_t n);

template <typename T>
inline T ObliviousArrayAccessSimd(const T *arr, size_t i, size_t n); 

template <typename T>
inline void ObliviousArrayAssign(T *arr, size_t i, size_t n, const T &val);

inline void ObliviousArrayAssignBytes(void *array, const void *src,
                                      size_t nbytes, size_t i, size_t n);

// Impl.

namespace obl {

void ObliviousBytesAssign(bool pred, size_t nbytes, const void *t_val,
                          const void *f_val, void *out);

template <typename T,
          typename std::enable_if<std::is_integral<T>::value, int>::type = 0>
inline bool LessImpl(T x, T y) {
  bool result;
  __asm__ volatile(
      "cmp %2, %1;"
      "setl %0;"
      : "=r"(result)
      : "r"(x), "r"(y)
      : "cc");
  return result;
}

bool LessImplDouble(double x, double y);

template <typename T, typename std::enable_if<std::is_floating_point<T>::value,
                                              int>::type = 0>
inline bool LessImpl(T x, T y) {
  return LessImplDouble(x, y);
}

template <typename T>
struct less {
  bool operator()(const T &a, const T &b) { return LessImpl<T>(a, b); }
};

template <typename T, typename Comparator>
struct reverse_cmp {
  bool operator()(const T &a, const T &b) {
    Comparator cmp;
    return cmp(b, a);
  }
};

template <typename T>
struct greater {
  bool operator()(const T &a, const T &b) { return less<T>()(b, a); }
};

template <typename T>
struct greater_equal {
  bool operator()(const T &a, const T &b) { return !less<T>()(a, b); }
};

template <typename T>
struct less_equal {
  bool operator()(const T &a, const T &b) { return !greater<T>()(a, b); }
};

}  // namespace obl

template <typename T>
inline bool ObliviousLess(const T &x, const T &y) {
  return obl::less<T>()(x, y);
}

template <typename T>
inline bool ObliviousGreater(const T &x, const T &y) {
  return obl::greater<T>()(x, y);
}

template <typename T>
inline bool ObliviousGreaterOrEqual(const T &x, const T &y) {
  return obl::greater_equal<T>()(x, y);
}

template <typename T>
inline bool ObliviousLessOrEqual(const T &x, const T &y) {
  return obl::less_equal<T>()(x, y);
}

template <typename T,
          typename std::enable_if<std::is_scalar<T>::value, int>::type>
inline bool ObliviousEqual(T x, T y) {
  bool result;
  __asm__ volatile(
      "cmp %2, %1;"
      "sete %0;"
      : "=r"(result)
      : "r"(x), "r"(y)
      : "cc");
  return result;
}

template <typename T,
          typename std::enable_if<std::is_standard_layout<T>::value, int>::type>
inline void ObliviousAssign(bool pred, const T &t_val, const T &f_val, T *out) {
  return obl::ObliviousBytesAssign(pred, sizeof(T), &t_val, &f_val, out);
}

template <typename T>
inline T ObliviousChoose(bool pred, const T &t_val, const T &f_val) {
  T result;
  ObliviousAssign(pred, t_val, f_val, &result);
  return result;
}

template <typename Iter, typename Comparator>
inline void ObliviousMerge(Iter begin, Iter end, Comparator cmp);

template <typename Iter, typename Comparator>
inline void ObliviousSort(Iter begin, Iter end, Comparator cmp);

template <typename Iter>
inline void ObliviousMerge(Iter begin, Iter end) {
  using value_type = typename std::remove_reference<decltype(*begin)>::type;
  return ObliviousMerge(begin, end, ::obl::less<value_type>());
}

template <typename Iter>
inline void ObliviousSort(Iter begin, Iter end) {
  using value_type = typename std::remove_reference<decltype(*begin)>::type;
  return ObliviousSort(begin, end, ::obl::less<value_type>());
}

// Return arr[i]
template <typename T>
inline T ObliviousArrayAccess(const T *arr, size_t i, size_t n) {
  T result = arr[0];
  ObliviousArrayAccessBytes(&result, arr, sizeof(T), i, n);
  return result;
}

inline void ObliviousArrayAccessBytes(void *dst, const void *array,
        size_t nbytes, size_t i, size_t n) {
    size_t step = nbytes < CACHE_LINE_SIZE ? CACHE_LINE_SIZE / nbytes : 1;
    for (size_t j = 0; j < n; j += step) {
        bool cond = ObliviousEqual(j / step, i / step);
        int pos = ObliviousChoose(cond, i, j);
        void *src_pos = (char *)(array) + pos * nbytes;
        obl::ObliviousBytesAssign(cond, nbytes, src_pos, dst, dst);
    }
}

#ifdef USE_AVX2
/**
 *  Vectorized oblivious array operation helpers
 */
inline int _mm256_extract_epi32_var_indx(__m256i vec, int i ) {   
    __m128i indx = _mm_cvtsi32_si128(i);
    __m256i shuffled  = _mm256_permutevar8x32_epi32(vec, _mm256_castsi128_si256(indx));
    return         _mm_cvtsi128_si32(_mm256_castsi256_si128(shuffled));
}
inline float _mm256_extract_ps_var_indx(__m256 vec, int i) {
    __m128i vidx = _mm_cvtsi32_si128(i);          // vmovd
    __m256i vidx256 = _mm256_castsi128_si256(vidx);  // no instructions
    __m256  shuffled = _mm256_permutevar8x32_ps(vec, vidx256);  // vpermps
    return _mm256_cvtss_f32(shuffled);
}
inline int _mm_extract_epi32_var_indx(__m128i vec, int i) {
    __m128i indx = _mm_cvtsi32_si128(i);
	__m128i shuffled = (__m128i)_mm_permutevar_ps((__m128)vec, indx);
	return _mm_cvtsi128_si32(shuffled);
}
inline float _mm_extract_ps_var_indx(__m128 vec, int i) {
	__m128i indx = _mm_cvtsi32_si128(i);
	__m128  shuffled = _mm_permutevar_ps(vec, indx);
	return _mm_cvtss_f32(shuffled);
}

template <typename T>
inline T extract256(__m256i vec, int i);
template<>
inline int extract256<int>(__m256i vec, int i) {
    return _mm256_extract_epi32_var_indx(vec, i);
}
template<>
inline uint32_t extract256<uint32_t>(__m256i vec, int i) {
    return _mm256_extract_epi32_var_indx(vec, i);
}
template<>
inline float extract256<float>(__m256i vec, int i) {
    return _mm256_extract_ps_var_indx((__m256)vec, i);
}
template <typename T>
inline T extract128(__m128i vec, int i);
template<>
inline int extract128<int>(__m128i vec, int i) {
    return _mm_extract_epi32_var_indx(vec, i);
}
template<>
inline uint32_t extract128<uint32_t>(__m128i vec, int i) {
    return _mm_extract_epi32_var_indx(vec, i);
}
template<>
inline float extract128<float>(__m128i vec, int i) {
    return _mm_extract_ps_var_indx((__m128)vec, i);
}
inline __m256i gather256(int const * base, __m256i index, const int scale) {
    return (__m256i) _mm256_i32gather_epi32(base, index, scale);
}
inline __m256i gather256(uint32_t const * base, __m256i index, const int scale) {
    return (__m256i) _mm256_i32gather_epi32((int const*)base, index, scale);
}
inline __m256i gather256(float const * base, __m256i index, const int scale) {
    return (__m256i) _mm256_i32gather_ps(base, index, scale);
}
inline __m128i gather128(int const * base, __m128i index, const int scale) {
    return (__m128i) _mm_i32gather_epi32(base, index, scale);
}
inline __m128i gather128(uint32_t const * base, __m128i index, const int scale) {
    return (__m128i) _mm_i32gather_epi32((int const*)base, index, scale);
}
inline __m128i gather128(float const * base, __m128i index, const int scale) {
    return (__m128i) _mm_i32gather_ps(base, index, scale);
}
inline int ObliviousArrayAccess(const int *arr, size_t i, size_t n) {
  return ObliviousArrayAccessSimd(arr, i, n);
}
inline uint32_t ObliviousArrayAccess(const uint32_t *arr, size_t i, size_t n) {
  return ObliviousArrayAccessSimd(arr, i, n);
}
inline float ObliviousArrayAccess(const float *arr, size_t i, size_t n) {
  return ObliviousArrayAccessSimd(arr, i, n);
}

// Vectorized access into int or float array. Implemented as described in Oblivious Multi-Party Machine Learning paper (Ohrimenko et al.) 
template <typename T>
inline T ObliviousArrayAccessSimd(const T *arr, size_t i, size_t n) {
    T retval;

    // number of elements per cache line
    int elem_per_cache_line = CACHE_LINE_SIZE / 4;
    
    // offset into the cache line
    int cache_line_offset = i % elem_per_cache_line;

    size_t j = 0;
    // Gather 8 cache lines at a time
    {
      // can jump ahead CACHE_LINE_SIZE * (256 / (sizeof(T) * 8)) bytes per gather...
      int step_size = elem_per_cache_line * 8; // number of elements we can effectively scan per `gather`

      // the index of the gather that will yield the target
      int m = i / step_size;

      // offset into the temporary scanning vector register
      int vector_offset = (i % step_size) / elem_per_cache_line;

      // gather instruction selects at memory addresses (base + IDX * scale)
      // VPGATHERDD __m128i _mm_i32gather_epi32 (int const * base, __m128i index, const int scale);

      __m256i indices;
      __m256i scanned;
      T maybe_retval;
      T scan_array[8];
      if (step_size <= n) {
        indices = _mm256_setr_epi32(cache_line_offset, elem_per_cache_line*1 + cache_line_offset, 
          elem_per_cache_line*2 + cache_line_offset, elem_per_cache_line*3 + cache_line_offset,
          elem_per_cache_line*4 + cache_line_offset, elem_per_cache_line*5 + cache_line_offset,
          elem_per_cache_line*6 + cache_line_offset, elem_per_cache_line*7 + cache_line_offset);
      }
      for (; j + step_size <= n; j += step_size) {
        scanned = gather256(&arr[j], indices, 4);
        maybe_retval = extract256<T>(scanned, vector_offset);
        obl::ObliviousBytesAssign(j / step_size == m, 4, &maybe_retval, &retval, &retval);
      }
    }
    
    // Gather 4 cache lines at a time
    {
        // can jump ahead CACHE_LINE_SIZE * (128 / (sizeof(T) * 8)) bytes per gather...
        int step_size = elem_per_cache_line * 4; // number of elements we can effectively scan per `gather`

        // the index of the gather that will yield the target
        int m = i / step_size;

        // offset into the temporary scanning vector register
        int vector_offset = (i % step_size) / elem_per_cache_line;

        // gather instruction selects at memory addresses (base + IDX * scale)
        // VPGATHERDD __m128i _mm_i32gather_epi32 (int const * base, __m128i index, const int scale);

        __m128i indices;
        __m128i scanned;
        T maybe_retval;
        T scan_array[4];
        if (j + step_size <= n) {
            indices = _mm_setr_epi32(cache_line_offset, elem_per_cache_line*1 + cache_line_offset, 
                    elem_per_cache_line*2 + cache_line_offset, elem_per_cache_line*3 + cache_line_offset);
        }
        for (; j + step_size <= n; j += step_size) {
            scanned = gather128(&arr[j], indices, 4);
            maybe_retval = extract128<T>(scanned, vector_offset);
            obl::ObliviousBytesAssign(j / step_size == m, 4, &maybe_retval, &retval, &retval);
        }
    }

    // Take care of remaining elements
    size_t step = CACHE_LINE_SIZE / 4; 
    for (; j < n; j += step) {
        bool cond = ObliviousEqual(j / step, i / step);
        int pos = ObliviousChoose(cond, i, j);
        void *src_pos = (void*) &arr[pos];
        obl::ObliviousBytesAssign(cond, 4, src_pos, &retval, &retval);
    }

    return retval;
}
#endif

// Set arr[i] = val
template <typename T>
inline void ObliviousArrayAssign(T *arr, size_t i, size_t n, const T &val) {
  return ObliviousArrayAssignBytes(arr, &val, sizeof(T), i, n);
}

inline void ObliviousArrayAssignBytes(void *array, const void *src,
                                      size_t nbytes, size_t i, size_t n) {
  size_t step = nbytes < CACHE_LINE_SIZE ? CACHE_LINE_SIZE / nbytes : 1;
  for (size_t j = 0; j < n; j += step) {
    bool cond = ObliviousEqual(j / step, i / step);
    int pos = ObliviousChoose(cond, i, j);
    void *dst_pos = (char *)(array) + pos * nbytes;
    obl::ObliviousBytesAssign(cond, nbytes, src, dst_pos, dst_pos);
  }
}

namespace detail {

inline uint32_t greatest_power_of_two_less_than(uint32_t n) {
  uint32_t k = 1;
  while (k < n) k = k << 1;
  return k >> 1;
}

inline uint32_t log2_ceil(uint32_t n) {
  uint32_t k = 0;
  uint32_t _n = n;
  while (n > 1) {
    k++;
    n /= 2;
  }
  if ((1 << k) < _n) k++;
  return k;
}

// Imperative implementation of bitonic merge network
template <typename T, typename Comparator>
inline void imperative_o_merge(T *arr, uint32_t low, uint32_t len,
                               Comparator cmp) {
  uint32_t i, j, k;
  uint32_t l = log2_ceil(len);
  uint32_t n = 1 << l;
  for (i = 0; i < l; i++) {
    for (j = 0; j<n; j += n>> i) {
      for (k = 0; k < (n >> i) / 2; k++) {
        uint32_t i1 = low + k + j;
        uint32_t i2 = i1 + (n >> i) / 2;
        if (i2 >= low + len) break;
        bool pred = cmp(arr[i2], arr[i1]);
        // These array accesses are oblivious because the indices are
        // deterministic
        T tmp = arr[i1];
        arr[i1] = ObliviousChoose(pred, arr[i2], arr[i1]);
        arr[i2] = ObliviousChoose(pred, tmp, arr[i2]);
      }
    }
  }
}

// Imperative implementation of bitonic sorting network -- works only for powers
// of 2
template <typename T, typename Comparator>
inline void imperative_o_sort(T *arr, size_t n, Comparator cmp) {
  uint32_t i, j, k;
  for (k = 2; k <= n; k = 2 * k) {
    for (j = k >> 1; j > 0; j = j >> 1) {
      for (i = 0; i < n; i++) {
        uint32_t ij = i ^ j;
        if (ij > i) {
          if ((i & k) == 0) {
            bool pred = cmp(arr[ij], arr[i]);
            // These array accesses are oblivious because the indices are
            // deterministic
            T tmp = arr[i];
            arr[i] = ObliviousChoose(pred, arr[ij], arr[i]);
            arr[ij] = ObliviousChoose(pred, tmp, arr[ij]);
          } else {
            bool pred = cmp(arr[i], arr[ij]);
            // These array accesses are oblivious because the indices are
            // deterministic
            T tmp = arr[i];
            arr[i] = ObliviousChoose(pred, arr[ij], arr[i]);
            arr[ij] = ObliviousChoose(pred, tmp, arr[ij]);
          }
        }
      }
    }
  }
}

// Sort <len> elements in arr -- starting from index arr[low]
template <typename T, typename Comparator>
inline void o_sort(T *arr, uint32_t low, uint32_t len, Comparator cmp) {
  if (len > 1) {
    uint32_t m = greatest_power_of_two_less_than(len);
    if (m * 2 == len) {
      imperative_o_sort(arr + low, len, cmp);
    } else {
      imperative_o_sort(arr + low, m, obl::reverse_cmp<T, Comparator>());
      o_sort(arr, low + m, len - m, cmp);
      imperative_o_merge(arr, low, len, cmp);
    }
  }
}

}  // namespace detail

template <typename Iter, typename Comparator>
inline void ObliviousMerge(Iter begin, Iter end, Comparator cmp) {
  using value_type = typename std::remove_reference<decltype(*begin)>::type;
  value_type *array = &(*begin);
  detail::imperative_o_merge<value_type, Comparator>(array, 0, end - begin, cmp);
}

template <typename Iter, typename Comparator>
inline void ObliviousSort(Iter begin, Iter end, Comparator cmp) {
  using value_type = typename std::remove_reference<decltype(*begin)>::type;
  value_type *array = &(*begin);
  return detail::o_sort<value_type, Comparator>(array, 0, end - begin, cmp);
}

namespace obl {

template <typename T,
          typename std::enable_if<!std::is_same<T, uint8_t>::value &&
                                      std::is_scalar<T>::value,
                                  int>::type = 0>
inline void ObliviousAssignHelper(bool pred, T t_val, T f_val, T *out) {
  T result;
  __asm__ volatile(
      "mov %2, %0;"
      "test %1, %1;"
      "cmovz %3, %0;"
      : "=&r"(result)
      : "r"(pred), "r"(t_val), "r"(f_val), "m"(out)
      : "cc");
  *out = result;
}

template <typename T, typename std::enable_if<std::is_same<T, uint8_t>::value,
                                              int>::type = 0>
inline void ObliviousAssignHelper(bool pred, T t_val, T f_val, T *out) {
  uint16_t result;
  uint16_t t = t_val;
  uint16_t f = f_val;
  __asm__ volatile(
      "mov %2, %0;"
      "test %1, %1;"
      "cmovz %3, %0;"
      : "=&r"(result)
      : "r"(pred), "r"(t), "r"(f), "m"(out)
      : "cc");
  *out = static_cast<uint8_t>(result);
}

#ifdef USE_AVX2
// Obliviously assigns 32 bytes starting from the address of (cond) ? t_val : f_val into out
template <typename T>
inline void ObliviousAssignHelper32(bool cond, T& t_val, T& f_val, T *out) {
    __m256i mask = _mm256_set1_epi64x((int)cond * -1); 
    __m256i t_val_vector = _mm256_loadu_si256((__m256i*) &t_val);
    __m256i f_val_vector = _mm256_loadu_si256((__m256i*) &f_val);
    __m256i result_vector = _mm256_blendv_epi8(f_val_vector, t_val_vector, mask);
    _mm256_storeu_si256((__m256i*) out, result_vector);
}

// Obliviously assigns 16 bytes starting from the address of (cond) ? t_val : f_val into out
template <typename T>
inline void ObliviousAssignHelper16(bool cond, T& t_val, T& f_val, T *out) {
    __m128i mask = _mm_set1_epi64x((int)cond * -1);
    __m128i t_val_vector = _mm_loadu_si128((__m128i*) &t_val);
    __m128i f_val_vector = _mm_loadu_si128((__m128i*) &f_val);
    __m128i result_vector = _mm_blendv_epi8(f_val_vector, t_val_vector, mask);
    _mm_storeu_si128((__m128i*) out, result_vector);
}
#endif

inline void ObliviousBytesAssign(bool pred, size_t nbytes, const void *t_val,
                                 const void *f_val, void *out) {
  const size_t bytes = nbytes;
  char *res = (char *)out;
  char *t = (char *)t_val;
  char *f = (char *)f_val;

#ifdef USE_AVX2
  // Obliviously assign 32 bytes at a time
  size_t num_32_iter = bytes / 32;
  for (int i = 0; i < num_32_iter; i++) {
    ObliviousAssignHelper32(pred, *t, *f, res);
    res += 32;
    t += 32;
    f += 32;
  }

  // Obliviously assign 16 bytes
  if ((bytes % 32) / 16) {
      ObliviousAssignHelper16(pred, *t, *f, res);
      res += 16;
      t += 16;
      f += 16;
  }

  // Obliviously assign 8 bytes
  if ((bytes % 16) / 8) {
    ObliviousAssignHelper(pred, *((uint64_t *)t), *((uint64_t *)f),
              (uint64_t *)res);
    res += 8;
    t += 8;
    f += 8;
  }
#else
  // Obliviously assign 8 bytes at a time
  size_t num_8_iter = bytes / 8;
  for (int i = 0; i < num_8_iter; i++) {
    ObliviousAssignHelper(pred, *((uint64_t *)t), *((uint64_t *)f),
                          (uint64_t *)res);
    res += 8;
    t += 8;
    f += 8;
  }
#endif

  // Obliviously assign 4 bytes
  if ((bytes % 8) / 4) {
    ObliviousAssignHelper(pred, *((uint32_t *)t), *((uint32_t *)f),
                          (uint32_t *)res);
    res += 4;
    t += 4;
    f += 4;
  }

  // Obliviously assign 2 bytes
  if ((bytes % 4) / 2) {
    ObliviousAssignHelper(pred, *((uint16_t *)t), *((uint16_t *)f),
                          (uint16_t *)res);
    res += 2;
    t += 2;
    f += 2;
  }

  // Obliviously assign 1 byte
  if ((bytes % 2)) {
    ObliviousAssignHelper(pred, *((uint8_t *)t), *((uint8_t *)f),
                          (uint8_t *)res);
  }
}
}  // namespace obl

