/* Copyright (c) 2024, Oracle and/or its affiliates.
 */

#ifndef XCOM_EXTERNALS
#define XCOM_EXTERNALS

#include <cstdarg>
#include <cstring>
#include <string>
#include <vector>

#if TASK_DBUG_ON

#ifdef XCOM_DBGOUT
#error "XCOM_DBGOUT already defined!"
#else
#define XCOM_DBGOUT(x)                          \
  do {                                          \
    if (IS_XCOM_DEBUG_WITH(XCOM_DEBUG_TRACE)) { \
      GET_GOUT;                                 \
      ADD_F_GOUT("%f ", task_now());            \
      x;                                        \
      PRINT_GOUT;                               \
      FREE_GOUT;                                \
    }                                           \
  } while (0);
#endif  // XCOM_DBGOUT

#ifdef XCOM_IFDBG
#error "XCOM_IFDBG already defined!"
#else
#define XCOM_IFDBG(mask, body)          \
  {                                     \
    if (do_dbg(mask)) XCOM_DBGOUT(body) \
  }
#endif

#else

#define XCOM_DBGOUT(x) \
  do {                 \
  } while (0)
#define XCOM_IFDBG(mask, body)

#endif  // TASK_DBUG_ON

#endif  // XCOM_EXTERNALS
