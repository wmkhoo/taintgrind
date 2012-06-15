#ifndef __TNT_STRINGS_H
#define __TNT_STRINGS_H

/* ------------------ Types ------------------ */
// VEX/pub/libvex_ir.h
const char *IRType_string[] = {
   "INVALID",
   "I1",
   "I8",
   "I16",
   "I32",
   "I64",
   "I128",
   "F32",
   "F64",
   "F128",
   "V128" };

#define IRType_MAX ( sizeof(IRType_string)/sizeof(IRType_string[0]) )

/* ------------------ Endianness ------------------ */

const char *IREndness_string[] = {
   "LE",
   "BE" };

/* ------------------ Constants ------------------ */

const char *IRConst_string[] = {
   "Ico_U1",
   "Ico_U8", 
   "Ico_U16", 
   "Ico_U32", 
   "Ico_U64",
   "Ico_F64",
   "Ico_F64i",
   "Ico_V128" };

/* --------------- Primops (arity 1,2",3 and 4) --------------- */
// Number of ops: 425 = 0x1a9
const char *IROp_string[] = {
      "INVALID",
      "Add8",  "Add16",  "Add32",  "Add64",
      "Sub8",  "Sub16",  "Sub32",  "Sub64",
      /* Signless mul.  "MullS/MullU is elsewhere. */
      "Mul8",  "Mul16",  "Mul32",  "Mul64",
      "Or8",   "Or16",   "Or32",   "Or64",
      "And8",  "And16",  "And32",  "And64",
      "Xor8",  "Xor16",  "Xor32",  "Xor64",
      "Shl8",  "Shl16",  "Shl32",  "Shl64",
      "Shr8",  "Shr16",  "Shr32",  "Shr64",
      "Sar8",  "Sar16",  "Sar32",  "Sar64",
      /* Integer comparisons. */
      "CmpEQ8",  "CmpEQ16",  "CmpEQ32",  "CmpEQ64",
      "CmpNE8",  "CmpNE16",  "CmpNE32",  "CmpNE64",
      /* Tags for unary ops */
      "Not8",  "Not16",  "Not32",  "Not64",
// 48
      /* Exactly like CmpEQ8/16/32/64", but carrying the additional
         hint that these compute the success/failure of a CAS
         operation, and hence are almost certainly applied to two
         copies of the same value, which in turn has implications for
         Memcheck's instrumentation. */
      "CasCmpEQ8", "CasCmpEQ16", "CasCmpEQ32", "CasCmpEQ64",
      "CasCmpNE8", "CasCmpNE16", "CasCmpNE32", "CasCmpNE64",

      /* -- Ordering not important after here. -- */

      /* Widening multiplies */
      "MullS8", "MullS16", "MullS32", "MullS64",
      "MullU8", "MullU16", "MullU32", "MullU64",

      /* Wierdo integer stuff */
      "Clz64", "Clz32",   /* count leading zeroes */
      "Ctz64", "Ctz32",   /* count trailing zeros */
      /* Ctz64/Ctz32/Clz64/Clz32 are UNDEFINED when given arguments of
         zero.  You must ensure they are never given a zero argument.
      */
// 68
      /* Standard integer comparisons */
      "CmpLT32S", "CmpLT64S",
      "CmpLE32S", "CmpLE64S",
      "CmpLT32U", "CmpLT64U",
      "CmpLE32U", "CmpLE64U",

      /* As a sop to Valgrind-Memcheck, the following are useful. */
      "CmpNEZ8", "CmpNEZ16",  "CmpNEZ32",  "CmpNEZ64",
      "CmpwNEZ32", "CmpwNEZ64", /* all-0s -> all-Os; other -> all-1s */
      "Left8", "Left16", "Left32", "Left64", /*  \x -> x | -x */
      "Max32U", /* unsigned max */
// 87
      /* PowerPC-style 3-way integer comparisons.  Without them it is
         difficult to simulate PPC efficiently.
         op(x,y) | x < y  = 0x8 else 
                 | x > y  = 0x4 else
                 | x == y = 0x2
      */
      "CmpORD32U", "CmpORD64U",
      "CmpORD32S", "CmpORD64S",
// 91
      /* Division */
      /* TODO: clarify semantics wrt rounding, negative values, whatever */
      "DivU32",   // :: I32",I32 -> I32 (simple div, no mod)
      "DivS32",   // ditto, signed
      "DivU64",   // :: I64",I64 -> I64 (simple div, no mod)
      "DivS64",   // ditto, signed

      "DivModU64to32", // :: I64",I32 -> I64
                         // of which lo half is div and hi half is mod
      "DivModS64to32", // ditto, signed

      "DivModU128to64", // :: V128",I64 -> V128
                          // of which lo half is div and hi half is mod
      "DivModS128to64", // ditto, signed
// 99
      /* Integer conversions.  Some of these are redundant (eg
         "64to8 is the same as "64to32 and then "32to8), but
         having a complete set reduces the typical dynamic size of IR
         and makes the instruction selectors easier to write. */

      /* Widening conversions */
      "8Uto16", "8Uto32",  "8Uto64",
               "16Uto32", "16Uto64",
                          "32Uto64",
      "8Sto16", "8Sto32",  "8Sto64",
               "16Sto32", "16Sto64",
                          "32Sto64",
// 111
      /* Narrowing conversions */
      "64to8", "32to8", "64to16",
      /* 8 <-> 16 bit conversions */
      "16to8",      // :: I16 -> I8", low half
      "16HIto8",    // :: I16 -> I8", high half
      "8HLto16",    // :: (I8",I8) -> I16
      /* 16 <-> 32 bit conversions */
      "32to16",     // :: I32 -> I16", low half
      "32HIto16",   // :: I32 -> I16", high half
      "16HLto32",   // :: (I16",I16) -> I32
      /* 32 <-> 64 bit conversions */
      "64to32",     // :: I64 -> I32", low half
      "64HIto32",   // :: I64 -> I32", high half
      "32HLto64",   // :: (I32",I32) -> I64
      /* 64 <-> 128 bit conversions */
      "128to64",    // :: I128 -> I64", low half
      "128HIto64",  // :: I128 -> I64", high half
      "64HLto128",  // :: (I64",I64) -> I128
// 126      /* 1-bit stuff */
      "Not1",   /* :: Bit -> Bit */
      "32to1",  /* :: I32 -> Bit, just select bit[0] */
      "64to1",  /* :: I64 -> Bit, just select bit[0] */
      "1Uto8",  /* :: Bit -> I8",  unsigned widen */
      "1Uto32", /* :: Bit -> I32", unsigned widen */
      "1Uto64", /* :: Bit -> I64", unsigned widen */
      "1Sto8",  /* :: Bit -> I8",  signed widen */
      "1Sto16", /* :: Bit -> I16", signed widen */
      "1Sto32", /* :: Bit -> I32", signed widen */
      "1Sto64", /* :: Bit -> I64", signed widen */

      /* ------ Floating point.  We try to be IEEE754 compliant. ------ */

      /* --- Simple stuff as mandated by 754. --- */

      /* Binary operations, with rounding. */
      /* :: IRRoundingMode(I32) x F64 x F64 -> F64 */ 
      "AddF64", "SubF64", "MulF64", "DivF64",

      /* :: IRRoundingMode(I32) x F32 x F32 -> F32 */ 
      "AddF32", "SubF32", "MulF32", "DivF32",
// 144
      /* Variants of the above which produce a 64-bit result but which
         round their result to a IEEE float range first. */
      /* :: IRRoundingMode(I32) x F64 x F64 -> F64 */ 
      "AddF64r32", "SubF64r32", "MulF64r32", "DivF64r32", 

      /* Unary operations, without rounding. */
      /* :: F64 -> F64 */
      "NegF64", "AbsF64",

      /* :: F32 -> F32 */
      "NegF32", "AbsF32",

      /* Unary operations, with rounding. */
      /* :: IRRoundingMode(I32) x F64 -> F64 */
      "SqrtF64", "SqrtF64r32",

      /* :: IRRoundingMode(I32) x F32 -> F32 */
      "SqrtF32",
// 155
      /* Comparison, yielding GT/LT/EQ/UN(ordered), as per the following:
            0x45 Unordered
            0x01 LT
            0x00 GT
            0x40 EQ
         This just happens to be the Intel encoding.  The values
         are recorded in the type IRCmpF64Result.
      */
      /* :: F64 x F64 -> IRCmpF64Result(I32) */
      "CmpF64",

      /* --- Int to/from FP conversions. --- */
// 156
      /* For the most part, these take a first argument :: I32 (as
         IRRoundingMode) which is an indication of the rounding mode
         to use, as per the following encoding ("the standard
         encoding"):
            00b  to nearest (the default)
            01b  to -infinity
            10b  to +infinity
            11b  to zero
         This just happens to be the Intel encoding.  For reference only,
         the PPC encoding is:
            00b  to nearest (the default)
            01b  to zero
            10b  to +infinity
            11b  to -infinity
         Any PPC -> IR front end will have to translate these PPC
         encodings, as encoded in the guest state, to the standard
         encodings, to pass to the primops.
         For reference only, the ARM VFP encoding is:
            00b  to nearest
            01b  to +infinity
            10b  to -infinity
            11b  to zero
         Again, this will have to be converted to the standard encoding
         to pass to primops.

         If one of these conversions gets an out-of-range condition,
         or a NaN", as an argument, the result is host-defined.  On x86
         the "integer indefinite" value 0x80..00 is produced.  On PPC
         it is either 0x80..00 or 0x7F..FF depending on the sign of
         the argument.

         On ARMvfp, when converting to a signed integer result, the
         overflow result is 0x80..00 for negative args and 0x7F..FF
         for positive args.  For unsigned integer results it is
         0x00..00 and 0xFF..FF respectively.

         Rounding is required whenever the destination type cannot
         represent exactly all values of the source type.
      */
      "F64toI16S", /* IRRoundingMode(I32) x F64 -> signed I16 */
      "F64toI32S", /* IRRoundingMode(I32) x F64 -> signed I32 */
      "F64toI64S", /* IRRoundingMode(I32) x F64 -> signed I64 */

      "F64toI32U", /* IRRoundingMode(I32) x F64 -> unsigned I32 */

      "I16StoF64", /*                       signed I16 -> F64 */
      "I32StoF64", /*                       signed I32 -> F64 */
      "I64StoF64", /* IRRoundingMode(I32) x signed I64 -> F64 */

      "I32UtoF64", /*                       unsigned I32 -> F64 */
// 164
      /* Conversion between floating point formats */
      "F32toF64",  /*                       F32 -> F64 */
      "F64toF32",  /* IRRoundingMode(I32) x F64 -> F32 */

      /* Reinterpretation.  Take an F64 and produce an I64 with 
         the same bit pattern, or vice versa. */
      "ReinterpF64asI64", "ReinterpI64asF64",
      "ReinterpF32asI32", "ReinterpI32asF32",

      /* --- guest x86/amd64 specifics, not mandated by 754. --- */

      /* Binary ops, with rounding. */
      /* :: IRRoundingMode(I32) x F64 x F64 -> F64 */ 
      "AtanF64",       /* FPATAN",  arctan(arg1/arg2)       */
      "Yl2xF64",       /* FYL2X,   arg1 * log2(arg2)       */
      "Yl2xp1F64",     /* FYL2XP1, arg1 * log2(arg2+1.0)   */
      "PRemF64",       /* FPREM,   non-IEEE remainder(arg1/arg2)    */
      "PRemC3210F64",  /* C3210 flags resulting from FPREM, :: I32 */
      "PRem1F64",      /* FPREM1,  IEEE remainder(arg1/arg2)    */
      "PRem1C3210F64", /* C3210 flags resulting from FPREM1, :: I32 */
      "ScaleF64",      /* FSCALE,  arg1 * (2^RoundTowardsZero(arg2)) */
      /* Note that on x86 guest, PRem1{C3210} has the same behaviour
         as the IEEE mandated RemF64", except it is limited in the
         range of its operand.  Hence the partialness. */
// 178
      /* Unary ops, with rounding. */
      /* :: IRRoundingMode(I32) x F64 -> F64 */
      "SinF64",    /* FSIN */
      "CosF64",    /* FCOS */
      "TanF64",    /* FTAN */
      "2xm1F64",   /* (2^arg - 1.0) */
      "RoundF64toInt", /* F64 value to nearest integral value (still
                            as F64) */
      "RoundF32toInt", /* F32 value to nearest integral value (still
                            as F32) */

      /* --- guest ppc32/64 specifics, not mandated by 754. --- */

      /* Ternary operations, with rounding. */
      /* Fused multiply-add/sub, with 112-bit intermediate
	 precision */
      /* :: IRRoundingMode(I32) x F64 x F64 x F64 -> F64 
            (computes arg2 * arg3 +/- arg4) */ 
      "MAddF64", "MSubF64",
// 186
      /* Variants of the above which produce a 64-bit result but which
         round their result to a IEEE float range first. */
      /* :: IRRoundingMode(I32) x F64 x F64 x F64 -> F64 */ 
      "MAddF64r32", "MSubF64r32",

      /* :: F64 -> F64 */
      "Est5FRSqrt",    /* reciprocal square root estimate, 5 good bits */
      "RoundF64toF64_NEAREST", /* frin */
      "RoundF64toF64_NegINF",  /* frim */ 
      "RoundF64toF64_PosINF",  /* frip */
      "RoundF64toF64_ZERO",    /* friz */

      /* :: F64 -> F32 */
      "TruncF64asF32", /* do F64->F32 truncation as per 'fsts' */

      /* :: IRRoundingMode(I32) x F64 -> F64 */
      "RoundF64toF32", /* round F64 to nearest F32 value (still as F64) */
      /* NB: pretty much the same as "F64toF32", except no change 
         of type. */

      /* :: F64 -> I32 */
      "CalcFPRF", /* Calc 5 fpscr[FPRF] bits (Class, <, =, >, Unord)
                       from FP result */
// 196
      /* ------------------ 32-bit SIMD Integer ------------------ */

      /* 16x2 add/sub, also signed/unsigned saturating variants */
      "Add16x2", "Sub16x2",
      "QAdd16Sx2", "QAdd16Ux2",
      "QSub16Sx2", "QSub16Ux2",

      /* 16x2 signed/unsigned halving add/sub.  For each lane, these
         compute bits 16:1 of (eg) sx(argL) + sx(argR),
         or zx(argL) - zx(argR) etc. */
      "HAdd16Ux2", "HAdd16Sx2",
      "HSub16Ux2", "HSub16Sx2",

      /* 8x4 add/sub, also signed/unsigned saturating variants */
      "Add8x4", "Sub8x4",
      "QAdd8Sx4", "QAdd8Ux4",
      "QSub8Sx4", "QSub8Ux4",
// 212
      /* 8x4 signed/unsigned halving add/sub.  For each lane, these
         compute bits 8:1 of (eg) sx(argL) + sx(argR),
         or zx(argL) - zx(argR) etc. */
      "HAdd8Ux4", "HAdd8Sx4",
      "HSub8Ux4", "HSub8Sx4",

      /* 8x4 sum of absolute unsigned differences. */
      "Sad8Ux4",

      /* MISC (vector integer cmp != 0) */
      "CmpNEZ16x2", "CmpNEZ8x4",
// 219
      /* ------------------ 64-bit SIMD FP ------------------------ */

      /* Convertion to/from int */
      "I32UtoFx2",  "I32StoFx2",    /* I32x4 -> F32x4 */
      "FtoI32Ux2_RZ",  "FtoI32Sx2_RZ",    /* F32x4 -> I32x4 */
      /* "Fixed32 format is floating-point number with fixed number of fraction
         bits. The number of fraction bits is passed as a second argument of
         type I8. */
      "F32ToFixed32Ux2_RZ", "F32ToFixed32Sx2_RZ", /* fp -> fixed-point */
      "Fixed32UToF32x2_RN", "Fixed32SToF32x2_RN", /* fixed-point -> fp */

      /* Binary operations */
      "Max32Fx2",      "Min32Fx2",
      /* Pairwise Min and Max. See integer pairwise operations for more
         details. */
      "PwMax32Fx2",    "PwMin32Fx2",
      /* Note: For the following compares, the arm front-end assumes a
         nan in a lane of either argument returns zero for that lane. */
      "CmpEQ32Fx2", "CmpGT32Fx2", "CmpGE32Fx2",
// 234
      /* Vector Reciprocal Estimate finds an approximate reciprocal of each
      element in the operand vector, and places the results in the destination
      vector.  */
      "Recip32Fx2",

      /* Vector Reciprocal Step computes (2.0 - arg1 * arg2).
         Note, that if one of the arguments is zero and another one is infinity
         of arbitrary sign the result of the operation is 2.0. */
      "Recps32Fx2",

      /* Vector Reciprocal Square Root Estimate finds an approximate reciprocal
         square root of each element in the operand vector. */
      "Rsqrte32Fx2",

      /* Vector Reciprocal Square Root Step computes (3.0 - arg1 * arg2) / 2.0.
         Note, that of one of the arguments is zero and another one is infiinty
         of arbitrary sign the result of the operation is 1.5. */
      "Rsqrts32Fx2",
      /* Unary */
      "Neg32Fx2", "Abs32Fx2",

// 240
      /* ------------------ 64-bit SIMD Integer. ------------------ */

      /* MISC (vector integer cmp != 0) */
      "CmpNEZ8x8", "CmpNEZ16x4", "CmpNEZ32x2",

      /* ADDITION (normal / unsigned sat / signed sat) */
      "Add8x8",   "Add16x4",   "Add32x2",
      "QAdd8Ux8", "QAdd16Ux4", "QAdd32Ux2", "QAdd64Ux1",
      "QAdd8Sx8", "QAdd16Sx4", "QAdd32Sx2", "QAdd64Sx1",

      /* PAIRWISE operations */
      /* PwFoo16x4( [a,b,c,d], [e,f,g,h] ) =
            [Foo16(a,b), Foo16(c,d), Foo16(e,f), Foo16(g,h)] */
      "PwAdd8x8",  "PwAdd16x4",  "PwAdd32x2",
      "PwMax8Sx8", "PwMax16Sx4", "PwMax32Sx2",
      "PwMax8Ux8", "PwMax16Ux4", "PwMax32Ux2",
      "PwMin8Sx8", "PwMin16Sx4", "PwMin32Sx2",
      "PwMin8Ux8", "PwMin16Ux4", "PwMin32Ux2",
// 269
      /* "Longening variant is unary. The resulting vector contains two times
         less elements than operand, but they are two times wider.
         Example:
            PAddL16Ux4( [a,b,c,d] ) = [a+b,c+d]
               where a+b and c+d are unsigned 32-bit values. */
      "PwAddL8Ux8", "PwAddL16Ux4", "PwAddL32Ux2",
      "PwAddL8Sx8", "PwAddL16Sx4", "PwAddL32Sx2",

      /* SUBTRACTION (normal / unsigned sat / signed sat) */
      "Sub8x8",   "Sub16x4",   "Sub32x2",
      "QSub8Ux8", "QSub16Ux4", "QSub32Ux2", "QSub64Ux1",
      "QSub8Sx8", "QSub16Sx4", "QSub32Sx2", "QSub64Sx1",

      /* ABSOLUTE VALUE */
      "Abs8x8", "Abs16x4", "Abs32x2",

      /* MULTIPLICATION (normal / high half of signed/unsigned) */
      "Mul8x8", "Mul16x4", "Mul32x2",
      "Mul32Fx2",
      "MulHi16Ux4",
      "MulHi16Sx4",
      /* Plynomial multiplication treats it's arguments as coefficients of
         polynoms over {0, 1}. */
      "PolynomialMul8x8",
// 296
      /* Vector Saturating Doubling Multiply Returning High Half and
         Vector Saturating Rounding Doubling Multiply Returning High Half */
      /* These IROp's multiply corresponding elements in two vectors, double
         the results, and place the most significant half of the final results
         in the destination vector. The results are truncated or rounded. If
         any of the results overflow, they are saturated. */
      "QDMulHi16Sx4", "QDMulHi32Sx2",
      "QRDMulHi16Sx4", "QRDMulHi32Sx2",
// 300
      /* AVERAGING: note: (arg1 + arg2 + 1) >>u 1 */
      "Avg8Ux8",
      "Avg16Ux4",

      /* MIN/MAX */
      "Max8Sx8", "Max16Sx4", "Max32Sx2",
      "Max8Ux8", "Max16Ux4", "Max32Ux2",
      "Min8Sx8", "Min16Sx4", "Min32Sx2",
      "Min8Ux8", "Min16Ux4", "Min32Ux2",

      /* COMPARISON */
      "CmpEQ8x8",  "CmpEQ16x4",  "CmpEQ32x2",
      "CmpGT8Ux8", "CmpGT16Ux4", "CmpGT32Ux2",
      "CmpGT8Sx8", "CmpGT16Sx4", "CmpGT32Sx2",

      /* COUNT ones / leading zeroes / leading sign bits (not including topmost
         bit) */
      "Cnt8x8",
      "Clz8Sx8", "Clz16Sx4", "Clz32Sx2",
      "Cls8Sx8", "Cls16Sx4", "Cls32Sx2",
// 327
      /* VECTOR x VECTOR SHIFT / ROTATE */
      "Shl8x8", "Shl16x4", "Shl32x2",
      "Shr8x8", "Shr16x4", "Shr32x2",
      "Sar8x8", "Sar16x4", "Sar32x2",
      "Sal8x8", "Sal16x4", "Sal32x2", "Sal64x1",

      /* VECTOR x SCALAR SHIFT (shift amt :: Ity_I8) */
      "ShlN8x8", "ShlN16x4", "ShlN32x2",
      "ShrN8x8", "ShrN16x4", "ShrN32x2",
      "SarN8x8", "SarN16x4", "SarN32x2",

      /* VECTOR x VECTOR SATURATING SHIFT */
      "QShl8x8", "QShl16x4", "QShl32x2", "QShl64x1",
      "QSal8x8", "QSal16x4", "QSal32x2", "QSal64x1",
      /* VECTOR x INTEGER SATURATING SHIFT */
      "QShlN8Sx8", "QShlN16Sx4", "QShlN32Sx2", "QShlN64Sx1",
      "QShlN8x8", "QShlN16x4", "QShlN32x2", "QShlN64x1",
      "QSalN8x8", "QSalN16x4", "QSalN32x2", "QSalN64x1",
// 369
      /* NARROWING -- narrow 2xI64 into 1xI64, hi half from left arg */
      "QNarrow16Ux4",
      "QNarrow16Sx4",
      "QNarrow32Sx2",

      /* INTERLEAVING -- interleave lanes from low or high halves of
         operands.  Most-significant result lane is from the left
         arg. */
      "InterleaveHI8x8", "InterleaveHI16x4", "InterleaveHI32x2",
      "InterleaveLO8x8", "InterleaveLO16x4", "InterleaveLO32x2",
      /* Interleave odd/even lanes of operands.  Most-significant result lane
         is from the left arg.  Note that Interleave{Odd,Even}Lanes32x2 are
         identical to Interleave{HI,LO}32x2 and so are omitted.*/
      "InterleaveOddLanes8x8", "InterleaveEvenLanes8x8",
      "InterleaveOddLanes16x4", "InterleaveEvenLanes16x4",
// 382
      /* CONCATENATION -- build a new value by concatenating either
         the even or odd lanes of both operands.  Note that
         "Cat{Odd,Even}Lanes32x2 are identical to "Interleave{HI,LO}32x2
         and so are omitted. */
      "CatOddLanes8x8", "CatOddLanes16x4", 
      "CatEvenLanes8x8", "CatEvenLanes16x4",

      /* GET / SET elements of VECTOR
         GET is binop (I64", I8) -> I<elem_size>
         SET is triop (I64", I8", I<elem_size>) -> I64 */
      /* Note: the arm back-end handles only constant second argument */
      "GetElem8x8", "GetElem16x4", "GetElem32x2",
      "SetElem8x8", "SetElem16x4", "SetElem32x2",

      /* DUPLICATING -- copy value to all lanes */
      "Dup8x8",   "Dup16x4",   "Dup32x2",
// 395
      /* EXTRACT -- copy 8-arg3 highest bytes from arg1 to 8-arg3 lowest bytes
         of result and arg3 lowest bytes of arg2 to arg3 highest bytes of
         result.
         It is a triop: (I64, I64, I8) -> I64 */
      /* Note: the arm back-end handles only constant third argumnet. */
      "Extract64",

      /* REVERSE the order of elements in each Half-words, Words,
         Double-words */
      /* Examples:
            Reverse16_8x8([a,b,c,d,e,f,g,h]) = [b,a,d,c,f,e,h,g]
            Reverse32_8x8([a,b,c,d,e,f,g,h]) = [d,c,b,a,h,g,f,e]
            Reverse64_8x8([a,b,c,d,e,f,g,h]) = [h,g,f,e,d,c,b,a] */
      "Reverse16_8x8",
      "Reverse32_8x8", "Reverse32_16x4",
      "Reverse64_8x8", "Reverse64_16x4", "Reverse64_32x2",
// 402
      /* PERMUTING -- copy src bytes to dst,
         as indexed by control vector bytes:
            for i in 0 .. 7 . result[i] = argL[ argR[i] ] 
         argR[i] values may only be in the range 0 .. 7, else behaviour
         is undefined. */
      "Perm8x8",

      /* Vector Reciprocal Estimate and Vector Reciprocal Square Root Estimate
         See floating-point equiwalents for details. */
      "Recip32x2", "Rsqrte32x2",

      /* ------------------ 128-bit SIMD FP. ------------------ */

      /* --- 32x4 vector FP --- */
// 405
      /* binary */
      "Add32Fx4", "Sub32Fx4", "Mul32Fx4", "Div32Fx4", 
      "Max32Fx4", "Min32Fx4",
      "Add32Fx2", "Sub32Fx2",
      /* Note: For the following compares, the ppc front-end assumes a
         nan in a lane of either argument returns zero for that lane. */
      "CmpEQ32Fx4", "CmpLT32Fx4", "CmpLE32Fx4", "CmpUN32Fx4", 
      "CmpGT32Fx4", "CmpGE32Fx4",

      /* Vector "Absolute */
      "Abs32Fx4",

      /* Pairwise Max and Min. See integer pairwise operations for details. */
      "PwMax32Fx4", "PwMin32Fx4",

      /* unary */
      "Sqrt32Fx4", "RSqrt32Fx4",
      "Neg32Fx4",
// 425
      /* Vector Reciprocal Estimate finds an approximate reciprocal of each
      element in the operand vector, and places the results in the destination
      vector.  */
      "Recip32Fx4",

      /* Vector Reciprocal Step computes (2.0 - arg1 * arg2).
         Note, that if one of the arguments is zero and another one is infinity
         of arbitrary sign the result of the operation is 2.0. */
      "Recps32Fx4",

      /* Vector Reciprocal Square Root Estimate finds an approximate reciprocal
         square root of each element in the operand vector. */
      "Rsqrte32Fx4",

      /* Vector Reciprocal Square Root Step computes (3.0 - arg1 * arg2) / 2.0.
         Note, that of one of the arguments is zero and another one is infiinty
         of arbitrary sign the result of the operation is 1.5. */
      "Rsqrts32Fx4",
// 429
      /* --- Int to/from FP conversion --- */
      /* Unlike the standard fp conversions, these irops take no
         rounding mode argument. Instead the irop trailers _R{M,P,N,Z}
         indicate the mode: {-inf, +inf, nearest, zero} respectively. */
      "I32UtoFx4",     "I32StoFx4",       /* I32x4 -> F32x4       */
      "FtoI32Ux4_RZ",  "FtoI32Sx4_RZ",    /* F32x4 -> I32x4       */
      "QFtoI32Ux4_RZ", "QFtoI32Sx4_RZ",   /* F32x4 -> I32x4 (with saturation) */
      "RoundF32x4_RM", "RoundF32x4_RP",   /* round to fp integer  */
      "RoundF32x4_RN", "RoundF32x4_RZ",   /* round to fp integer  */
      /* "Fixed32 format is floating-point number with fixed number of fraction
         bits. The number of fraction bits is passed as a second argument of
         type I8. */
      "F32ToFixed32Ux4_RZ", "F32ToFixed32Sx4_RZ", /* fp -> fixed-point */
      "Fixed32UToF32x4_RN", "Fixed32SToF32x4_RN", /* fixed-point -> fp */

      /* --- Single to/from half conversion --- */
      "F32toF16x4", "F16toF32x4",         /* F32x4 <-> F16x4      */

      /* --- 32x4 lowest-lane-only scalar FP --- */
// 445
      /* In binary cases, upper 3/4 is copied from first operand.  In
         unary cases, upper 3/4 is copied from the operand. */

      /* binary */
      "Add32F0x4", "Sub32F0x4", "Mul32F0x4", "Div32F0x4", 
      "Max32F0x4", "Min32F0x4",
      "CmpEQ32F0x4", "CmpLT32F0x4", "CmpLE32F0x4", "CmpUN32F0x4", 

      /* unary */
      "Recip32F0x4", "Sqrt32F0x4", "RSqrt32F0x4",

      /* --- 64x2 vector FP --- */

      /* binary */
      "Add64Fx2", "Sub64Fx2", "Mul64Fx2", "Div64Fx2", 
      "Max64Fx2", "Min64Fx2",
      "CmpEQ64Fx2", "CmpLT64Fx2", "CmpLE64Fx2", "CmpUN64Fx2", 

      /* unary */
      "Recip64Fx2", "Sqrt64Fx2", "RSqrt64Fx2",
// 471
      /* --- 64x2 lowest-lane-only scalar FP --- */

      /* In binary cases, upper half is copied from first operand.  In
         unary cases, upper half is copied from the operand. */

      /* binary */
      "Add64F0x2", "Sub64F0x2", "Mul64F0x2", "Div64F0x2", 
      "Max64F0x2", "Min64F0x2",
      "CmpEQ64F0x2", "CmpLT64F0x2", "CmpLE64F0x2", "CmpUN64F0x2", 

      /* unary */
      "Recip64F0x2", "Sqrt64F0x2", "RSqrt64F0x2",

      /* --- pack / unpack --- */

      /* 64 <-> 128 bit vector */
      "V128to64",     // :: V128 -> I64, low half
      "V128HIto64",   // :: V128 -> I64, high half
      "64HLtoV128",   // :: (I64,I64) -> V128
// 487
      "64UtoV128",
      "SetV128lo64",

      /* 32 <-> 128 bit vector */
      "32UtoV128",
      "V128to32",     // :: V128 -> I32", lowest lane
      "SetV128lo32",  // :: (V128",I32) -> V128

      /* ------------------ 128-bit SIMD Integer. ------------------ */

      /* BITWISE OPS */
      "NotV128",
      "AndV128", "OrV128", "XorV128", 

      /* VECTOR SHIFT (shift amt :: I8) */
      "ShlV128", "ShrV128",

      /* MISC (vector integer cmp != 0) */
      "CmpNEZ8x16", "CmpNEZ16x8", "CmpNEZ32x4", "CmpNEZ64x2",

      /* ADDITION (normal / unsigned sat / signed sat) */
      "Add8x16",   "Add16x8",   "Add32x4",  "Add64x2",
      "QAdd8Ux16", "QAdd16Ux8", "QAdd32Ux4", "QAdd64Ux2",
      "QAdd8Sx16", "QAdd16Sx8", "QAdd32Sx4", "QAdd64Sx2",
// 514
      /* SUBTRACTION (normal / unsigned sat / signed sat) */
      "Sub8x16",   "Sub16x8",   "Sub32x4",  "Sub64x2",
      "QSub8Ux16", "QSub16Ux8", "QSub32Ux4", "QSub64Ux2",
      "QSub8Sx16", "QSub16Sx8", "QSub32Sx4", "QSub64Sx2",

      /* MULTIPLICATION (normal / high half of signed/unsigned) */
      "Mul8x16", "Mul16x8", "Mul32x4",
              "MulHi16Ux8", "MulHi32Ux4",
              "MulHi16Sx8", "MulHi32Sx4",
      /* (widening signed/unsigned of even lanes, with lowest lane=zero) */
      "MullEven8Ux16", "MullEven16Ux8",
      "MullEven8Sx16", "MullEven16Sx8",
      /* FIXME: document these */
      "Mull8Ux8", "Mull8Sx8",
      "Mull16Ux4", "Mull16Sx4",
      "Mull32Ux2", "Mull32Sx2",
      /* Vector Saturating Doubling Multiply Returning High Half and
         Vector Saturating Rounding Doubling Multiply Returning High Half */
      /* These IROp's multiply corresponding elements in two vectors, double
         the results, and place the most significant half of the final results
         in the destination vector. The results are truncated or rounded. If
         any of the results overflow, they are saturated. */
// 543
      "QDMulHi16Sx8", "QDMulHi32Sx4",
      "QRDMulHi16Sx8", "QRDMulHi32Sx4",
      /* Doubling saturating multiplication (long) (I64", I64) -> V128 */
      "QDMulLong16Sx4", "QDMulLong32Sx2",
      /* Plynomial multiplication treats it's arguments as coefficients of
         polynoms over {0, 1}. */
      "PolynomialMul8x16", /* (V128", V128) -> V128 */
      "PolynomialMull8x8", /*   (I64", I64) -> V128 */

      /* PAIRWISE operations */
      /* PwFoo16x4( [a,b,c,d], [e,f,g,h] ) =
            [Foo16(a,b), Foo16(c,d), Foo16(e,f), Foo16(g,h)] */
      "PwAdd8x16", "PwAdd16x8", "PwAdd32x4",
      "PwAdd32Fx2",
      /* "Longening variant is unary. The resulting vector contains two times
         less elements than operand, but they are two times wider.
         Example:
            "PwAddL16Ux4( [a,b,c,d] ) = [a+b,c+d]
               where a+b and c+d are unsigned 32-bit values. */
      "PwAddL8Ux16", "PwAddL16Ux8", "PwAddL32Ux4",
      "PwAddL8Sx16", "PwAddL16Sx8", "PwAddL32Sx4",
// 561
      /* ABSOLUTE VALUE */
      "Abs8x16", "Abs16x8", "Abs32x4",

      /* AVERAGING: note: (arg1 + arg2 + 1) >>u 1 */
      "Avg8Ux16", "Avg16Ux8", "Avg32Ux4",
      "Avg8Sx16", "Avg16Sx8", "Avg32Sx4",

      /* MIN/MAX */
      "Max8Sx16", "Max16Sx8", "Max32Sx4",
      "Max8Ux16", "Max16Ux8", "Max32Ux4",
      "Min8Sx16", "Min16Sx8", "Min32Sx4",
      "Min8Ux16", "Min16Ux8", "Min32Ux4",

      /* COMPARISON */
      "CmpEQ8x16",  "CmpEQ16x8",  "CmpEQ32x4",
      "CmpGT8Sx16", "CmpGT16Sx8", "CmpGT32Sx4", "CmpGT64Sx2",
      "CmpGT8Ux16", "CmpGT16Ux8", "CmpGT32Ux4",
// 592
      /* COUNT ones / leading zeroes / leading sign bits (not including topmost
         bit) */
      "Cnt8x16",
      "Clz8Sx16", "Clz16Sx8", "Clz32Sx4",
      "Cls8Sx16", "Cls16Sx8", "Cls32Sx4",

      /* VECTOR x SCALAR SHIFT (shift amt :: Ity_I8) */
      "ShlN8x16", "ShlN16x8", "ShlN32x4", "ShlN64x2",
      "ShrN8x16", "ShrN16x8", "ShrN32x4", "ShrN64x2",
      "SarN8x16", "SarN16x8", "SarN32x4", "SarN64x2",

      /* VECTOR x VECTOR SHIFT / ROTATE */
      "Shl8x16", "Shl16x8", "Shl32x4", "Shl64x2",
      "Shr8x16", "Shr16x8", "Shr32x4", "Shr64x2",
      "Sar8x16", "Sar16x8", "Sar32x4", "Sar64x2",
      "Rol8x16", "Rol16x8", "Rol32x4",
// 626
      /* VECTOR x VECTOR SATURATING SHIFT */
      "QShl8x16", "QShl16x8", "QShl32x4", "QShl64x2",
      "QSal8x16", "QSal16x8", "QSal32x4", "QSal64x2",
      /* VECTOR x INTEGER SATURATING SHIFT */
      "QShlN8Sx16", "QShlN16Sx8", "QShlN32Sx4", "QShlN64Sx2",
      "QShlN8x16", "QShlN16x8", "QShlN32x4", "QShlN64x2",
      "QSalN8x16", "QSalN16x8", "QSalN32x4", "QSalN64x2",

      /* NARROWING -- narrow 2xV128 into 1xV128", hi half from left arg */
      /* Note: the 16{U,S} and 32{U,S} are the pre-narrow lane widths. */
      "QNarrow16Ux8", "QNarrow32Ux4",
      "QNarrow16Sx8", "QNarrow32Sx4",
      "Narrow16x8", "Narrow32x4",
      /* Shortening V128->I64", lo half from each element */
      "Shorten16x8", "Shorten32x4", "Shorten64x2",
      /* Saturating shortening from signed source to signed/unsigned destination */
      "QShortenS16Sx8", "QShortenS32Sx4", "QShortenS64Sx2",
      "QShortenU16Sx8", "QShortenU32Sx4", "QShortenU64Sx2",
      /* Saturating shortening from unsigned source to unsigned destination */
      "QShortenU16Ux8", "QShortenU32Ux4", "QShortenU64Ux2",
// 664
      /* WIDENING */
      /* Longening --- sign or zero extends each element of the argument
         vector to the twice original size. The resulting vector consists of
         the same number of elements but each element and the vector itself
         are two times wider.
         All operations are I64->V128.
         Example
            Longen32Sx2( [a, b] ) = [c, d]
               where c = 32Sto64(a) and d = 32Sto64(b) */
      "Longen8Ux8", "Longen16Ux4", "Longen32Ux2",
      "Longen8Sx8", "Longen16Sx4", "Longen32Sx2",

      /* INTERLEAVING -- interleave lanes from low or high halves of
         operands.  Most-significant result lane is from the left
         arg. */
      "InterleaveHI8x16", "InterleaveHI16x8",
      "InterleaveHI32x4", "InterleaveHI64x2",
      "InterleaveLO8x16", "InterleaveLO16x8", 
      "InterleaveLO32x4", "InterleaveLO64x2",
// 678
      /* Interleave odd/even lanes of operands.  Most-significant result lane
         is from the left arg. */
      "InterleaveOddLanes8x16", "InterleaveEvenLanes8x16",
      "InterleaveOddLanes16x8", "InterleaveEvenLanes16x8",
      "InterleaveOddLanes32x4", "InterleaveEvenLanes32x4",

      /* CONCATENATION -- build a new value by concatenating either
         the even or odd lanes of both operands. */
      "CatOddLanes8x16", "CatOddLanes16x8", "CatOddLanes32x4",
      "CatEvenLanes8x16", "CatEvenLanes16x8", "CatEvenLanes32x4",

      /* GET elements of VECTOR
         GET is binop (V128", I8) -> I<elem_size> */
      /* Note: the arm back-end handles only constant second argument. */
      "GetElem8x16", "GetElem16x8", "GetElem32x4", "GetElem64x2",

      /* DUPLICATING -- copy value to all lanes */
      "Dup8x16", "Dup16x8", "Dup32x4",
// 697
      /* EXTRACT -- copy 16-arg3 highest bytes from arg1 to 16-arg3 lowest bytes
         of result and arg3 lowest bytes of arg2 to arg3 highest bytes of
         result.
         It is a triop: (V128, V128, I8) -> V128 */
      /* Note: the ARM back end handles only constant arg3 in this operation. */
      "ExtractV128",

      /* REVERSE the order of elements in each Half-words, Words,
         Double-words */
      /* Examples:
            Reverse32_16x8([a,b,c,d,e,f,g,h]) = [b,a,d,c,f,e,h,g]
            Reverse64_16x8([a,b,c,d,e,f,g,h]) = [d,c,b,a,h,g,f,e] */
      "Reverse16_8x16",
      "Reverse32_8x16", "Reverse32_16x8",
      "Reverse64_8x16", "Reverse64_16x8", "Reverse64_32x4",
// 704
      /* PERMUTING -- copy src bytes to dst,
         as indexed by control vector bytes:
            for i in 0 .. 15 . result[i] = argL[ argR[i] ] 
         argR[i] values may only be in the range 0 .. 15, else behaviour
         is undefined. */
      "Perm8x16",

      /* Vector Reciprocal Estimate and Vector Reciprocal Square Root Estimate
         See floating-point equiwalents for details. */
      "Recip32x4", "Rsqrte32x4"
   };
// 707

/* ------------------ Expressions ------------------ */

const char *IRExpr_string[] = {
      "Binder",
      "GET",
      "GETI",
      "RdTmp",
      "Qop",
      "Triop",
      "Binop",
      "Unop",
      "LOAD",
      "Const",
      "MUX0X",
      "CCALL"
   };

/* ------------------ Jump kinds ------------------ */

const char *IRJumpKind_string[] = {
      "Boring", /* not interesting; just goto next */
      "Call",           /* guest is doing a call */
      "Ret",            /* guest is doing a return */
      "ClientReq",      /* do guest client req before continuing */
      "Yield",          /* client is yielding to thread scheduler */
      "EmWarn",         /* report emulation warning before continuing */
      "EmFail",         /* emulation critical (FATAL) error; give up */
      "NoDecode",       /* next instruction cannot be decoded */
      "MapFail",        /* Vex-provided address translation failed */
      "TInval",         /* Invalidate translations before continuing. */
      "NoRedir",        /* Jump to un-redirected guest addr */
      "SigTRAP",        /* current instruction synths SIGTRAP */
      "SigSEGV",        /* current instruction synths SIGSEGV */
      "SigBUS",         /* current instruction synths SIGBUS */
      /* Unfortunately, various guest-dependent syscall kinds.  They
	 all mean: do a syscall before continuing. */
      "Sys_syscall",    /* amd64 'syscall', ppc 'sc', arm 'svc #0' */
      "Sys_int32",      /* amd64/x86 'int $0x20' */
      "Sys_int128",     /* amd64/x86 'int $0x80' */
      "Sys_int129",     /* amd64/x86 'int $0x81' */
      "Sys_int130",     /* amd64/x86 'int $0x82' */
      "Sys_sysenter"    /* x86 'sysenter'.  guest_EIP becomes 
                             invalid at the point this happens. */
   };

/* ------------------ Statements ------------------ */

const char *IRStmt_string[] = {
      "NoOp", //=0x19000,
      "IMark",     /* META */
      "AbiHint",   /* META */
      "PUT",
      "PUTI",
      "WrTmp",
      "STORE",
      "CAS",
      "LLSC",
      "DIRTY",
      "MBE",       /* META (maybe) */
      "EXIT"
   };

const char* syscallnames[] = {
#ifdef VGO_freebsd
	"syscall",			/* 0 = syscall */
	"exit",			/* 1 = exit */
	"fork",			/* 2 = fork */
	"read",			/* 3 = read */
	"write",			/* 4 = write */
	"open",			/* 5 = open */
	"close",			/* 6 = close */
	"wait4",			/* 7 = wait4 */
	"compat.creat",		/* 8 = old creat */
	"link",			/* 9 = link */
	"unlink",			/* 10 = unlink */
	"obs_execv",			/* 11 = obsolete execv */
	"chdir",			/* 12 = chdir */
	"fchdir",			/* 13 = fchdir */
	"mknod",			/* 14 = mknod */
	"chmod",			/* 15 = chmod */
	"chown",			/* 16 = chown */
	"break",			/* 17 = break */
	"compat4.getfsstat",		/* 18 = freebsd4 getfsstat */
	"compat.lseek",		/* 19 = old lseek */
	"getpid",			/* 20 = getpid */
	"mount",			/* 21 = mount */
	"unmount",			/* 22 = unmount */
	"setuid",			/* 23 = setuid */
	"getuid",			/* 24 = getuid */
	"geteuid",			/* 25 = geteuid */
	"ptrace",			/* 26 = ptrace */
	"recvmsg",			/* 27 = recvmsg */
	"sendmsg",			/* 28 = sendmsg */
	"recvfrom",			/* 29 = recvfrom */
	"accept",			/* 30 = accept */
	"getpeername",			/* 31 = getpeername */
	"getsockname",			/* 32 = getsockname */
	"access",			/* 33 = access */
	"chflags",			/* 34 = chflags */
	"fchflags",			/* 35 = fchflags */
	"sync",			/* 36 = sync */
	"kill",			/* 37 = kill */
	"compat.stat",		/* 38 = old stat */
	"getppid",			/* 39 = getppid */
	"compat.lstat",		/* 40 = old lstat */
	"dup",			/* 41 = dup */
	"pipe",			/* 42 = pipe */
	"getegid",			/* 43 = getegid */
	"profil",			/* 44 = profil */
	"ktrace",			/* 45 = ktrace */
	"compat.sigaction",		/* 46 = old sigaction */
	"getgid",			/* 47 = getgid */
	"compat.sigprocmask",		/* 48 = old sigprocmask */
	"getlogin",			/* 49 = getlogin */
	"setlogin",			/* 50 = setlogin */
	"acct",			/* 51 = acct */
	"compat.sigpending",		/* 52 = old sigpending */
	"sigaltstack",			/* 53 = sigaltstack */
	"ioctl",			/* 54 = ioctl */
	"reboot",			/* 55 = reboot */
	"revoke",			/* 56 = revoke */
	"symlink",			/* 57 = symlink */
	"readlink",			/* 58 = readlink */
	"execve",			/* 59 = execve */
	"umask",			/* 60 = umask */
	"chroot",			/* 61 = chroot */
	"compat.fstat",		/* 62 = old fstat */
	"compat.getkerninfo",		/* 63 = old getkerninfo */
	"compat.getpagesize",		/* 64 = old getpagesize */
	"msync",			/* 65 = msync */
	"vfork",			/* 66 = vfork */
	"obs_vread",			/* 67 = obsolete vread */
	"obs_vwrite",			/* 68 = obsolete vwrite */
	"sbrk",			/* 69 = sbrk */
	"sstk",			/* 70 = sstk */
	"compat.mmap",		/* 71 = old mmap */
	"vadvise",			/* 72 = vadvise */
	"munmap",			/* 73 = munmap */
	"mprotect",			/* 74 = mprotect */
	"madvise",			/* 75 = madvise */
	"obs_vhangup",			/* 76 = obsolete vhangup */
	"obs_vlimit",			/* 77 = obsolete vlimit */
	"mincore",			/* 78 = mincore */
	"getgroups",			/* 79 = getgroups */
	"setgroups",			/* 80 = setgroups */
	"getpgrp",			/* 81 = getpgrp */
	"setpgid",			/* 82 = setpgid */
	"setitimer",			/* 83 = setitimer */
	"compat.wait",		/* 84 = old wait */
	"swapon",			/* 85 = swapon */
	"getitimer",			/* 86 = getitimer */
	"compat.gethostname",		/* 87 = old gethostname */
	"compat.sethostname",		/* 88 = old sethostname */
	"getdtablesize",			/* 89 = getdtablesize */
	"dup2",			/* 90 = dup2 */
	"#91",			/* 91 = getdopt */
	"fcntl",			/* 92 = fcntl */
	"select",			/* 93 = select */
	"#94",			/* 94 = setdopt */
	"fsync",			/* 95 = fsync */
	"setpriority",			/* 96 = setpriority */
	"socket",			/* 97 = socket */
	"connect",			/* 98 = connect */
	"compat.accept",		/* 99 = old accept */
	"getpriority",			/* 100 = getpriority */
	"compat.send",		/* 101 = old send */
	"compat.recv",		/* 102 = old recv */
	"compat.sigreturn",		/* 103 = old sigreturn */
	"bind",			/* 104 = bind */
	"setsockopt",			/* 105 = setsockopt */
	"listen",			/* 106 = listen */
	"obs_vtimes",			/* 107 = obsolete vtimes */
	"compat.sigvec",		/* 108 = old sigvec */
	"compat.sigblock",		/* 109 = old sigblock */
	"compat.sigsetmask",		/* 110 = old sigsetmask */
	"compat.sigsuspend",		/* 111 = old sigsuspend */
	"compat.sigstack",		/* 112 = old sigstack */
	"compat.recvmsg",		/* 113 = old recvmsg */
	"compat.sendmsg",		/* 114 = old sendmsg */
	"obs_vtrace",			/* 115 = obsolete vtrace */
	"gettimeofday",			/* 116 = gettimeofday */
	"getrusage",			/* 117 = getrusage */
	"getsockopt",			/* 118 = getsockopt */
	"#119",			/* 119 = resuba */
	"readv",			/* 120 = readv */
	"writev",			/* 121 = writev */
	"settimeofday",			/* 122 = settimeofday */
	"fchown",			/* 123 = fchown */
	"fchmod",			/* 124 = fchmod */
	"compat.recvfrom",		/* 125 = old recvfrom */
	"setreuid",			/* 126 = setreuid */
	"setregid",			/* 127 = setregid */
	"rename",			/* 128 = rename */
	"compat.truncate",		/* 129 = old truncate */
	"compat.ftruncate",		/* 130 = old ftruncate */
	"flock",			/* 131 = flock */
	"mkfifo",			/* 132 = mkfifo */
	"sendto",			/* 133 = sendto */
	"shutdown",			/* 134 = shutdown */
	"socketpair",			/* 135 = socketpair */
	"mkdir",			/* 136 = mkdir */
	"rmdir",			/* 137 = rmdir */
	"utimes",			/* 138 = utimes */
	"obs_4.2",			/* 139 = obsolete 4.2 sigreturn */
	"adjtime",			/* 140 = adjtime */
	"compat.getpeername",		/* 141 = old getpeername */
	"compat.gethostid",		/* 142 = old gethostid */
	"compat.sethostid",		/* 143 = old sethostid */
	"compat.getrlimit",		/* 144 = old getrlimit */
	"compat.setrlimit",		/* 145 = old setrlimit */
	"compat.killpg",		/* 146 = old killpg */
	"setsid",			/* 147 = setsid */
	"quotactl",			/* 148 = quotactl */
	"compat.quota",		/* 149 = old quota */
	"compat.getsockname",		/* 150 = old getsockname */
	"#151",			/* 151 = sem_lock */
	"#152",			/* 152 = sem_wakeup */
	"#153",			/* 153 = asyncdaemon */
	"nlm_syscall",			/* 154 = nlm_syscall */
	"nfssvc",			/* 155 = nfssvc */
	"compat.getdirentries",		/* 156 = old getdirentries */
	"compat4.statfs",		/* 157 = freebsd4 statfs */
	"compat4.fstatfs",		/* 158 = freebsd4 fstatfs */
	"#159",			/* 159 = nosys */
	"lgetfh",			/* 160 = lgetfh */
	"getfh",			/* 161 = getfh */
	"compat4.getdomainname",		/* 162 = freebsd4 getdomainname */
	"compat4.setdomainname",		/* 163 = freebsd4 setdomainname */
	"compat4.uname",		/* 164 = freebsd4 uname */
	"sysarch",			/* 165 = sysarch */
	"rtprio",			/* 166 = rtprio */
	"#167",			/* 167 = nosys */
	"#168",			/* 168 = nosys */
	"semsys",			/* 169 = semsys */
	"msgsys",			/* 170 = msgsys */
	"shmsys",			/* 171 = shmsys */
	"#172",			/* 172 = nosys */
	"freebsd6_pread",			/* 173 = freebsd6_pread */
	"freebsd6_pwrite",			/* 174 = freebsd6_pwrite */
	"setfib",			/* 175 = setfib */
	"ntp_adjtime",			/* 176 = ntp_adjtime */
	"#177",			/* 177 = sfork */
	"#178",			/* 178 = getdescriptor */
	"#179",			/* 179 = setdescriptor */
	"#180",			/* 180 = nosys */
	"setgid",			/* 181 = setgid */
	"setegid",			/* 182 = setegid */
	"seteuid",			/* 183 = seteuid */
	"#184",			/* 184 = lfs_bmapv */
	"#185",			/* 185 = lfs_markv */
	"#186",			/* 186 = lfs_segclean */
	"#187",			/* 187 = lfs_segwait */
	"stat",			/* 188 = stat */
	"fstat",			/* 189 = fstat */
	"lstat",			/* 190 = lstat */
	"pathconf",			/* 191 = pathconf */
	"fpathconf",			/* 192 = fpathconf */
	"#193",			/* 193 = nosys */
	"getrlimit",			/* 194 = getrlimit */
	"setrlimit",			/* 195 = setrlimit */
	"getdirentries",			/* 196 = getdirentries */
	"freebsd6_mmap",			/* 197 = freebsd6_mmap */
	"__syscall",			/* 198 = __syscall */
	"freebsd6_lseek",			/* 199 = freebsd6_lseek */
	"freebsd6_truncate",			/* 200 = freebsd6_truncate */
	"freebsd6_ftruncate",			/* 201 = freebsd6_ftruncate */
	"__sysctl",			/* 202 = __sysctl */
	"mlock",			/* 203 = mlock */
	"munlock",			/* 204 = munlock */
	"undelete",			/* 205 = undelete */
	"futimes",			/* 206 = futimes */
	"getpgid",			/* 207 = getpgid */
	"#208",			/* 208 = newreboot */
	"poll",			/* 209 = poll */
	"lkmnosys",			/* 210 = lkmnosys */
	"lkmnosys",			/* 211 = lkmnosys */
	"lkmnosys",			/* 212 = lkmnosys */
	"lkmnosys",			/* 213 = lkmnosys */
	"lkmnosys",			/* 214 = lkmnosys */
	"lkmnosys",			/* 215 = lkmnosys */
	"lkmnosys",			/* 216 = lkmnosys */
	"lkmnosys",			/* 217 = lkmnosys */
	"lkmnosys",			/* 218 = lkmnosys */
	"lkmnosys",			/* 219 = lkmnosys */
	"compat7.__semctl",		/* 220 = freebsd7 __semctl */
	"semget",			/* 221 = semget */
	"semop",			/* 222 = semop */
	"#223",			/* 223 = semconfig */
	"compat7.msgctl",		/* 224 = freebsd7 msgctl */
	"msgget",			/* 225 = msgget */
	"msgsnd",			/* 226 = msgsnd */
	"msgrcv",			/* 227 = msgrcv */
	"shmat",			/* 228 = shmat */
	"compat7.shmctl",		/* 229 = freebsd7 shmctl */
	"shmdt",			/* 230 = shmdt */
	"shmget",			/* 231 = shmget */
	"clock_gettime",			/* 232 = clock_gettime */
	"clock_settime",			/* 233 = clock_settime */
	"clock_getres",			/* 234 = clock_getres */
	"ktimer_create",			/* 235 = ktimer_create */
	"ktimer_delete",			/* 236 = ktimer_delete */
	"ktimer_settime",			/* 237 = ktimer_settime */
	"ktimer_gettime",			/* 238 = ktimer_gettime */
	"ktimer_getoverrun",			/* 239 = ktimer_getoverrun */
	"nanosleep",			/* 240 = nanosleep */
	"#241",			/* 241 = nosys */
	"#242",			/* 242 = nosys */
	"#243",			/* 243 = nosys */
	"#244",			/* 244 = nosys */
	"#245",			/* 245 = nosys */
	"#246",			/* 246 = nosys */
	"#247",			/* 247 = nosys */
	"ntp_gettime",			/* 248 = ntp_gettime */
	"#249",			/* 249 = nosys */
	"minherit",			/* 250 = minherit */
	"rfork",			/* 251 = rfork */
	"openbsd_poll",			/* 252 = openbsd_poll */
	"issetugid",			/* 253 = issetugid */
	"lchown",			/* 254 = lchown */
	"aio_read",			/* 255 = aio_read */
	"aio_write",			/* 256 = aio_write */
	"lio_listio",			/* 257 = lio_listio */
	"#258",			/* 258 = nosys */
	"#259",			/* 259 = nosys */
	"#260",			/* 260 = nosys */
	"#261",			/* 261 = nosys */
	"#262",			/* 262 = nosys */
	"#263",			/* 263 = nosys */
	"#264",			/* 264 = nosys */
	"#265",			/* 265 = nosys */
	"#266",			/* 266 = nosys */
	"#267",			/* 267 = nosys */
	"#268",			/* 268 = nosys */
	"#269",			/* 269 = nosys */
	"#270",			/* 270 = nosys */
	"#271",			/* 271 = nosys */
	"getdents",			/* 272 = getdents */
	"#273",			/* 273 = nosys */
	"lchmod",			/* 274 = lchmod */
	"netbsd_lchown",			/* 275 = netbsd_lchown */
	"lutimes",			/* 276 = lutimes */
	"netbsd_msync",			/* 277 = netbsd_msync */
	"nstat",			/* 278 = nstat */
	"nfstat",			/* 279 = nfstat */
	"nlstat",			/* 280 = nlstat */
	"#281",			/* 281 = nosys */
	"#282",			/* 282 = nosys */
	"#283",			/* 283 = nosys */
	"#284",			/* 284 = nosys */
	"#285",			/* 285 = nosys */
	"#286",			/* 286 = nosys */
	"#287",			/* 287 = nosys */
	"#288",			/* 288 = nosys */
	"preadv",			/* 289 = preadv */
	"pwritev",			/* 290 = pwritev */
	"#291",			/* 291 = nosys */
	"#292",			/* 292 = nosys */
	"#293",			/* 293 = nosys */
	"#294",			/* 294 = nosys */
	"#295",			/* 295 = nosys */
	"#296",			/* 296 = nosys */
	"compat4.fhstatfs",		/* 297 = freebsd4 fhstatfs */
	"fhopen",			/* 298 = fhopen */
	"fhstat",			/* 299 = fhstat */
	"modnext",			/* 300 = modnext */
	"modstat",			/* 301 = modstat */
	"modfnext",			/* 302 = modfnext */
	"modfind",			/* 303 = modfind */
	"kldload",			/* 304 = kldload */
	"kldunload",			/* 305 = kldunload */
	"kldfind",			/* 306 = kldfind */
	"kldnext",			/* 307 = kldnext */
	"kldstat",			/* 308 = kldstat */
	"kldfirstmod",			/* 309 = kldfirstmod */
	"getsid",			/* 310 = getsid */
	"setresuid",			/* 311 = setresuid */
	"setresgid",			/* 312 = setresgid */
	"obs_signanosleep",			/* 313 = obsolete signanosleep */
	"aio_return",			/* 314 = aio_return */
	"aio_suspend",			/* 315 = aio_suspend */
	"aio_cancel",			/* 316 = aio_cancel */
	"aio_error",			/* 317 = aio_error */
	"oaio_read",			/* 318 = oaio_read */
	"oaio_write",			/* 319 = oaio_write */
	"olio_listio",			/* 320 = olio_listio */
	"yield",			/* 321 = yield */
	"obs_thr_sleep",			/* 322 = obsolete thr_sleep */
	"obs_thr_wakeup",			/* 323 = obsolete thr_wakeup */
	"mlockall",			/* 324 = mlockall */
	"munlockall",			/* 325 = munlockall */
	"__getcwd",			/* 326 = __getcwd */
	"sched_setparam",			/* 327 = sched_setparam */
	"sched_getparam",			/* 328 = sched_getparam */
	"sched_setscheduler",			/* 329 = sched_setscheduler */
	"sched_getscheduler",			/* 330 = sched_getscheduler */
	"sched_yield",			/* 331 = sched_yield */
	"sched_get_priority_max",			/* 332 = sched_get_priority_max */
	"sched_get_priority_min",			/* 333 = sched_get_priority_min */
	"sched_rr_get_interval",			/* 334 = sched_rr_get_interval */
	"utrace",			/* 335 = utrace */
	"compat4.sendfile",		/* 336 = freebsd4 sendfile */
	"kldsym",			/* 337 = kldsym */
	"jail",			/* 338 = jail */
	"nnpfs_syscall",			/* 339 = nnpfs_syscall */
	"sigprocmask",			/* 340 = sigprocmask */
	"sigsuspend",			/* 341 = sigsuspend */
	"compat4.sigaction",		/* 342 = freebsd4 sigaction */
	"sigpending",			/* 343 = sigpending */
	"compat4.sigreturn",		/* 344 = freebsd4 sigreturn */
	"sigtimedwait",			/* 345 = sigtimedwait */
	"sigwaitinfo",			/* 346 = sigwaitinfo */
	"__acl_get_file",			/* 347 = __acl_get_file */
	"__acl_set_file",			/* 348 = __acl_set_file */
	"__acl_get_fd",			/* 349 = __acl_get_fd */
	"__acl_set_fd",			/* 350 = __acl_set_fd */
	"__acl_delete_file",			/* 351 = __acl_delete_file */
	"__acl_delete_fd",			/* 352 = __acl_delete_fd */
	"__acl_aclcheck_file",			/* 353 = __acl_aclcheck_file */
	"__acl_aclcheck_fd",			/* 354 = __acl_aclcheck_fd */
	"extattrctl",			/* 355 = extattrctl */
	"extattr_set_file",			/* 356 = extattr_set_file */
	"extattr_get_file",			/* 357 = extattr_get_file */
	"extattr_delete_file",			/* 358 = extattr_delete_file */
	"aio_waitcomplete",			/* 359 = aio_waitcomplete */
	"getresuid",			/* 360 = getresuid */
	"getresgid",			/* 361 = getresgid */
	"kqueue",			/* 362 = kqueue */
	"kevent",			/* 363 = kevent */
	"#364",			/* 364 = __cap_get_proc */
	"#365",			/* 365 = __cap_set_proc */
	"#366",			/* 366 = __cap_get_fd */
	"#367",			/* 367 = __cap_get_file */
	"#368",			/* 368 = __cap_set_fd */
	"#369",			/* 369 = __cap_set_file */
	"#370",			/* 370 = nosys */
	"extattr_set_fd",			/* 371 = extattr_set_fd */
	"extattr_get_fd",			/* 372 = extattr_get_fd */
	"extattr_delete_fd",			/* 373 = extattr_delete_fd */
	"__setugid",			/* 374 = __setugid */
	"#375",			/* 375 = nfsclnt */
	"eaccess",			/* 376 = eaccess */
	"afs3_syscall",			/* 377 = afs3_syscall */
	"nmount",			/* 378 = nmount */
	"#379",			/* 379 = kse_exit */
	"#380",			/* 380 = kse_wakeup */
	"#381",			/* 381 = kse_create */
	"#382",			/* 382 = kse_thr_interrupt */
	"#383",			/* 383 = kse_release */
	"__mac_get_proc",			/* 384 = __mac_get_proc */
	"__mac_set_proc",			/* 385 = __mac_set_proc */
	"__mac_get_fd",			/* 386 = __mac_get_fd */
	"__mac_get_file",			/* 387 = __mac_get_file */
	"__mac_set_fd",			/* 388 = __mac_set_fd */
	"__mac_set_file",			/* 389 = __mac_set_file */
	"kenv",			/* 390 = kenv */
	"lchflags",			/* 391 = lchflags */
	"uuidgen",			/* 392 = uuidgen */
	"sendfile",			/* 393 = sendfile */
	"mac_syscall",			/* 394 = mac_syscall */
	"getfsstat",			/* 395 = getfsstat */
	"statfs",			/* 396 = statfs */
	"fstatfs",			/* 397 = fstatfs */
	"fhstatfs",			/* 398 = fhstatfs */
	"#399",			/* 399 = nosys */
	"ksem_close",			/* 400 = ksem_close */
	"ksem_post",			/* 401 = ksem_post */
	"ksem_wait",			/* 402 = ksem_wait */
	"ksem_trywait",			/* 403 = ksem_trywait */
	"ksem_init",			/* 404 = ksem_init */
	"ksem_open",			/* 405 = ksem_open */
	"ksem_unlink",			/* 406 = ksem_unlink */
	"ksem_getvalue",			/* 407 = ksem_getvalue */
	"ksem_destroy",			/* 408 = ksem_destroy */
	"__mac_get_pid",			/* 409 = __mac_get_pid */
	"__mac_get_link",			/* 410 = __mac_get_link */
	"__mac_set_link",			/* 411 = __mac_set_link */
	"extattr_set_link",			/* 412 = extattr_set_link */
	"extattr_get_link",			/* 413 = extattr_get_link */
	"extattr_delete_link",			/* 414 = extattr_delete_link */
	"__mac_execve",			/* 415 = __mac_execve */
	"sigaction",			/* 416 = sigaction */
	"sigreturn",			/* 417 = sigreturn */
	"#418",			/* 418 = __xstat */
	"#419",			/* 419 = __xfstat */
	"#420",			/* 420 = __xlstat */
	"getcontext",			/* 421 = getcontext */
	"setcontext",			/* 422 = setcontext */
	"swapcontext",			/* 423 = swapcontext */
	"swapoff",			/* 424 = swapoff */
	"__acl_get_link",			/* 425 = __acl_get_link */
	"__acl_set_link",			/* 426 = __acl_set_link */
	"__acl_delete_link",			/* 427 = __acl_delete_link */
	"__acl_aclcheck_link",			/* 428 = __acl_aclcheck_link */
	"sigwait",			/* 429 = sigwait */
	"thr_create",			/* 430 = thr_create */
	"thr_exit",			/* 431 = thr_exit */
	"thr_self",			/* 432 = thr_self */
	"thr_kill",			/* 433 = thr_kill */
	"_umtx_lock",			/* 434 = _umtx_lock */
	"_umtx_unlock",			/* 435 = _umtx_unlock */
	"jail_attach",			/* 436 = jail_attach */
	"extattr_list_fd",			/* 437 = extattr_list_fd */
	"extattr_list_file",			/* 438 = extattr_list_file */
	"extattr_list_link",			/* 439 = extattr_list_link */
	"#440",			/* 440 = kse_switchin */
	"ksem_timedwait",			/* 441 = ksem_timedwait */
	"thr_suspend",			/* 442 = thr_suspend */
	"thr_wake",			/* 443 = thr_wake */
	"kldunloadf",			/* 444 = kldunloadf */
	"audit",			/* 445 = audit */
	"auditon",			/* 446 = auditon */
	"getauid",			/* 447 = getauid */
	"setauid",			/* 448 = setauid */
	"getaudit",			/* 449 = getaudit */
	"setaudit",			/* 450 = setaudit */
	"getaudit_addr",			/* 451 = getaudit_addr */
	"setaudit_addr",			/* 452 = setaudit_addr */
	"auditctl",			/* 453 = auditctl */
	"_umtx_op",			/* 454 = _umtx_op */
	"thr_new",			/* 455 = thr_new */
	"sigqueue",			/* 456 = sigqueue */
	"kmq_open",			/* 457 = kmq_open */
	"kmq_setattr",			/* 458 = kmq_setattr */
	"kmq_timedreceive",			/* 459 = kmq_timedreceive */
	"kmq_timedsend",			/* 460 = kmq_timedsend */
	"kmq_notify",			/* 461 = kmq_notify */
	"kmq_unlink",			/* 462 = kmq_unlink */
	"abort2",			/* 463 = abort2 */
	"thr_set_name",			/* 464 = thr_set_name */
	"aio_fsync",			/* 465 = aio_fsync */
	"rtprio_thread",			/* 466 = rtprio_thread */
	"#467",			/* 467 = nosys */
	"#468",			/* 468 = nosys */
	"#469",			/* 469 = __getpath_fromfd */
	"#470",			/* 470 = __getpath_fromaddr */
	"sctp_peeloff",			/* 471 = sctp_peeloff */
	"sctp_generic_sendmsg",			/* 472 = sctp_generic_sendmsg */
	"sctp_generic_sendmsg_iov",			/* 473 = sctp_generic_sendmsg_iov */
	"sctp_generic_recvmsg",			/* 474 = sctp_generic_recvmsg */
	"pread",			/* 475 = pread */
	"pwrite",			/* 476 = pwrite */
	"mmap",			/* 477 = mmap */
	"lseek",			/* 478 = lseek */
	"truncate",			/* 479 = truncate */
	"ftruncate",			/* 480 = ftruncate */
	"thr_kill2",			/* 481 = thr_kill2 */
	"shm_open",			/* 482 = shm_open */
	"shm_unlink",			/* 483 = shm_unlink */
	"cpuset",			/* 484 = cpuset */
	"cpuset_setid",			/* 485 = cpuset_setid */
	"cpuset_getid",			/* 486 = cpuset_getid */
	"cpuset_getaffinity",			/* 487 = cpuset_getaffinity */
	"cpuset_setaffinity",			/* 488 = cpuset_setaffinity */
	"faccessat",			/* 489 = faccessat */
	"fchmodat",			/* 490 = fchmodat */
	"fchownat",			/* 491 = fchownat */
	"fexecve",			/* 492 = fexecve */
	"fstatat",			/* 493 = fstatat */
	"futimesat",			/* 494 = futimesat */
	"linkat",			/* 495 = linkat */
	"mkdirat",			/* 496 = mkdirat */
	"mkfifoat",			/* 497 = mkfifoat */
	"mknodat",			/* 498 = mknodat */
	"openat",			/* 499 = openat */
	"readlinkat",			/* 500 = readlinkat */
	"renameat",			/* 501 = renameat */
	"symlinkat",			/* 502 = symlinkat */
	"unlinkat",			/* 503 = unlinkat */
	"posix_openpt",			/* 504 = posix_openpt */
	"gssd_syscall",			/* 505 = gssd_syscall */
	"jail_get",			/* 506 = jail_get */
	"jail_set",			/* 507 = jail_set */
	"jail_remove",			/* 508 = jail_remove */
	"closefrom",			/* 509 = closefrom */
	"__semctl",			/* 510 = __semctl */
	"msgctl",			/* 511 = msgctl */
	"shmctl",			/* 512 = shmctl */
	"lpathconf",			/* 513 = lpathconf */
	"cap_new",			/* 514 = cap_new */
	"cap_getrights",			/* 515 = cap_getrights */
	"cap_enter",			/* 516 = cap_enter */
	"cap_getmode",			/* 517 = cap_getmode */
	"pdfork",			/* 518 = pdfork */
	"pdkill",			/* 519 = pdkill */
	"pdgetpid",			/* 520 = pdgetpid */
	"#521",			/* 521 = pdwait4 */
	"pselect",			/* 522 = pselect */
	"getloginclass",			/* 523 = getloginclass */
	"setloginclass",			/* 524 = setloginclass */
	"rctl_get_racct",			/* 525 = rctl_get_racct */
	"rctl_get_rules",			/* 526 = rctl_get_rules */
	"rctl_get_limits",			/* 527 = rctl_get_limits */
	"rctl_add_rule",			/* 528 = rctl_add_rule */
	"rctl_remove_rule",			/* 529 = rctl_remove_rule */
	"posix_fallocate",			/* 530 = posix_fallocate */
	"#531",			/* 531 = posix_fadvise */
#endif
};

#endif
