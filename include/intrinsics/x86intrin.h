/* Copyright (C) 2008-2017 Free Software Foundation, Inc.

   This file is part of GCC.

   GCC is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   GCC is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   Under Section 7 of GPL version 3, you are granted additional
   permissions described in the GCC Runtime Library Exception, version
   3.1, as published by the Free Software Foundation.

   You should have received a copy of the GNU General Public License and
   a copy of the GCC Runtime Library Exception along with this program;
   see the files COPYING3 and COPYING.RUNTIME respectively.  If not, see
   <http://www.gnu.org/licenses/>.  */

#ifndef _X86INTRIN_H_INCLUDED
#define _X86INTRIN_H_INCLUDED

#include <intrinsics/ia32intrin.h>

#ifndef __iamcu__

#include <intrinsics/mmintrin.h>

#include <intrinsics/xmmintrin.h>

#include <intrinsics/emmintrin.h>

#include <intrinsics/pmmintrin.h>

#include <intrinsics/tmmintrin.h>

#include <intrinsics/ammintrin.h>

#include <intrinsics/smmintrin.h>

#include <intrinsics/wmmintrin.h>

/* For including AVX instructions */
#include <intrinsics/immintrin.h>

#include <intrinsics/mm3dnow.h>

#include <intrinsics/fma4intrin.h>

#include <intrinsics/xopintrin.h>

#include <intrinsics/lwpintrin.h>

#include <intrinsics/bmiintrin.h>

#include <intrinsics/bmi2intrin.h>

#include <intrinsics/tbmintrin.h>

#include <intrinsics/lzcntintrin.h>

#include <intrinsics/popcntintrin.h>

#include <intrinsics/rdseedintrin.h>

#include <intrinsics/prfchwintrin.h>

#include <intrinsics/fxsrintrin.h>

#include <intrinsics/xsaveintrin.h>

#include <intrinsics/xsaveoptintrin.h>

#include <intrinsics/sgxintrin.h>

#endif /* __iamcu__ */

#include <intrinsics/adxintrin.h>

#ifndef __iamcu__

#include <intrinsics/clwbintrin.h>

#include <intrinsics/clflushoptintrin.h>

#include <intrinsics/xsavesintrin.h>

#include <intrinsics/xsavecintrin.h>

#include <intrinsics/mwaitxintrin.h>

#include <intrinsics/clzerointrin.h>

#include <intrinsics/pkuintrin.h>

#endif /* __iamcu__ */

#endif /* _X86INTRIN_H_INCLUDED */
