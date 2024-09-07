/*
   SBA: Static Binary Analysis Framework                          
                                                                  
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.                 
*/

#ifndef CONFIG_H
#define CONFIG_H


/* framework */
#define SYSTEM             ELF_x86
#define ENDIAN             0   /* +---+-----------+ */
                               /* | 0 |   little  | */
                               /* | 1 |    big    | */
#define DLEVEL             0   /* +---+-----------+ */
                               /* | 0 | off       | */
                               /* | 1 | output    | */
                               /* | 2 | output+   | */
                               /* | 3 | debug     | */
                               /* | 4 | debug+    | */
                               /* | 5 | debug++   | */
#define PLEVEL             1   /* +---+-----------+ */
                               /* | 0 | off       | */
                               /* | 1 | framework | */
                               /* | 2 | state     | */
                               /* +---+-----------+ */
#define IMM                int32_t
#define  oo                ((IMM)100000000)
#define _oo                ((IMM)-100000000)


/* state */
#define STACK_OFFSET_MAX      1000
#define STACK_OFFSET_MIN      -10000
#define STATIC_OFFSET_MAX     50000000
#define STATIC_OFFSET_MIN     0
#define APPROX_RANGE_SIZE     20
#define DOMAIN_BOUNDS         AbsCstr


/* optional */
#define ENABLE_COMPATIBLE_INPUT           true
#define ENABLE_RESOLVE_ICF                true
#define ENABLE_DETECT_UNINIT              true
#define ENABLE_SUPPORT_CONSTRAINT         true
#define ENABLE_DETECT_UPDATED_FUNCTION    true
#define LIMIT_JTABLE                      5000
#define LIMIT_VISITED                     100000
#define LIMIT_REFRESH                     100
#define ABORT_UNLIFTED_INSN               false
#define ABORT_MISSING_FUNCTION_ENTRY      false
#define ABORT_MISSING_DIRECT_TARGET       false
#define ABORT_MISSING_INDIRECT_TARGET     false
#define ABORT_MISSING_FALLTHROUGH_TARGET  false
#define ABORT_MISSING_NEXT_INSN           false


/* constraint */
#if ENABLE_SUPPORT_CONSTRAINT
   #define UPDATE_VALUE(destination, source, state)                     \
      auto& flags = state.loc.block->flags;                             \
      auto& cstr = state.loc.block->cstr;                               \
      auto dest_id = destination->expr_id(state);                       \
      if (!dest_id.bad()) {                                             \
         auto src_id = source->expr_id(state);                          \
         flags.assign(dest_id, src_id);                                 \
         /* dataflow bounds */                                          \
         auto bin = (Binary*)(*source);                                 \
         /* 0 <= eax & 15 <= 15      */                                 \
         /* 0 <= eax & -65281 <= +oo */                                 \
         if (bin != nullptr) {                                          \
            cstr.assign(dest_id, src_id);                               \
            if (bin->op() == Binary::OP::AND) {                         \
               auto c0 = bin->operand_const(0);                         \
               auto c1 = bin->operand_const(1);                         \
               cstr.intersect(DOMAIN_BOUNDS(dest_id,                    \
                        Range(0, c1 != _oo && c1 > 0? c1:               \
                                (c0 != _oo && c0 > 0? c0: oo))));       \
            }                                                           \
            else if (bin->op() == Binary::OP::LSHIFTRT) {               \
               auto c1 = bin->operand_const(1);                         \
               if (c1 != _oo) {                                         \
                  IMM x = (8*(IMM)(source->mode_size()) - c1);          \
                  x = ((IMM)1 << x) - 1;                                \
                  cstr.intersect(DOMAIN_BOUNDS(dest_id, Range(0,x)));   \
               }                                                        \
            }                                                           \
         }                                                              \
         /* 0 <= ebx == extend(al) <= 256 */                            \
         else {                                                         \
            if (dest_id.reg_expr() && source->mode_size() == 1 &&       \
            destination->mode_size() > 1) {                             \
               auto r = cstr.bounds(src_id);                            \
               cstr.assign(dest_id, src_id);                            \
               cstr.intersect(DOMAIN_BOUNDS(dest_id, r & Range(0,255)));\
            }                                                           \
            else                                                        \
               cstr.assign(dest_id, src_id);                            \
         }                                                              \
         LOG3("update(flags):\n      " << flags.to_string());           \
         LOG3("update(cstr):\n      " << cstr.to_string());             \
      }
   #define CLOBBER_REG(r, block)                                        \
      auto& flags = block->flags;                                       \
      auto& cstr = block->cstr;                                         \
      AbsId expr(r,0);                                                  \
      flags.invalidate(expr);                                           \
      cstr.invalidate(expr);
   #if ENABLE_RESOLVE_ICF
      #define INDEX_RANGE_CONCRETE(aval, r)                             \
         ABSVAL(BaseStride,aval).bounds(r);
      #define INDEX_RANGE_CSTR(aval, src, state)                        \
         ABSVAL(BaseStride,aval).bounds(                                \
               state.loc.block->cstr.bounds(src->expr_id(state)));
      #define INDEX_RANGE(aval, r, src, state)                          \
         ABSVAL(BaseStride,aval).bounds(                                \
               r & state.loc.block->cstr.bounds(src->expr_id(state)));
      #define UPDATE_CONST_EXPR(x, c)                                   \
         x = c;
   #else
      #define INDEX_RANGE_CONCRETE(aval, r)
      #define INDEX_RANGE_CSTR(aval, expr, state)
      #define INDEX_RANGE(aval, r, expr, state)
      #define UPDATE_CONST_EXPR(x, c)
   #endif
#else
   #define UPDATE_VALUE(destination, source, block)
   #define CLOBBER_REG(r, block)
#endif


/* analyses */
#if ENABLE_DETECT_UNINIT
   #define CUSTOM_ANALYSIS_INFO_1                  \
      /* +---+-----------+ */                      \
      /* | 1 | mem deref | */                      \
      /* | 2 | cf target | */                      \
      /* | 4 | critical  | */                      \
      /* +---+-----------+ */                      \
      uint8_t uninit;
   #define CUSTOM_ANALYSIS_CLEAR_1                 \
      uninit = 0;
#else
   #define CUSTOM_ANALYSIS_INFO_1
   #define CUSTOM_ANALYSIS_CLEAR_1
#endif

#define CUSTOM_ANALYSIS_INFO                       \
   CUSTOM_ANALYSIS_INFO_1

#define CUSTOM_ANALYSIS_CLEAR()                    \
   CUSTOM_ANALYSIS_CLEAR_1


#endif
