
/*
 * Copyright (c) 2002-2005, Network Appliance, Inc. All rights reserved.
 *
 * This Software is licensed under one of the following licenses:
 *
 * 1) under the terms of the "Common Public License 1.0" a copy of which is
 *    in the file LICENSE.txt in the root directory. The license is also
 *    available from the Open Source Initiative, see
 *    http://www.opensource.org/licenses/cpl.php.
 *
 * 2) under the terms of the "The BSD License" a copy of which is in the file
 *    LICENSE2.txt in the root directory. The license is also available from
 *    the Open Source Initiative, see
 *    http://www.opensource.org/licenses/bsd-license.php.
 *
 * 3) under the terms of the "GNU General Public License (GPL) Version 2" a 
 *    copy of which is in the file LICENSE3.txt in the root directory. The 
 *    license is also available from the Open Source Initiative, see
 *    http://www.opensource.org/licenses/gpl-license.php.
 *
 * Licensee has the right to choose one of the above licenses.
 *
 * Redistributions of source code must retain the above copyright
 * notice and one of the license notices.
 *
 * Redistributions in binary form must reproduce both the above copyright
 * notice, one of the license notices in the documentation
 * and/or other materials provided with the distribution.
 */

#ifndef __DAPL_MDEP_USER_H__
#define __DAPL_MDEP_USER_H__

/* include files */

#include <ctype.h>

#ifndef WIN32_LEAN_AND_MEAN
# define WIN32_LEAN_AND_MEAN
#endif

# include <windows.h>
# include <process.h>
# include <stdio.h>
# include <string.h>
# include <winsock2.h>
# include <ws2tcpip.h>

/* Default Device Name */
#define DT_MdepDeviceName    "ibnic0v2"

/* Boolean */
typedef int     bool;

#define true (1)
#define false (0)

#ifndef __BASE_FILE__
#define __BASE_FILE__ __FILE__
#endif

#ifndef _INLINE_
#define _INLINE_ __inline
#endif

/* Mdep function defines */

#define DT_Mdep_spew(N, _X_) \
do { \
      if (DT_dapltest_debug >= (N)) \
        { \
          DT_Mdep_printf _X_; \
        } \
} while (0)

#define DT_Mdep_debug(_X_)  DT_Mdep_spew(1, _X_)

#define DT_Mdep_printf printf
#define DT_Mdep_flush() fflush(NULL)

/*
 * Release processor to reschedule
 */
#define DT_Mdep_yield() Sleep(0)

/*
 * Locks
 */

typedef HANDLE  DT_Mdep_LockType;
/* Wait object used for inter thread communication */

typedef HANDLE DT_WAIT_OBJECT;

/*
 * Thread types
 */
typedef HANDLE   DT_Mdep_ThreadHandleType;
typedef void     (*DT_Mdep_ThreadFunction) (void *param);
typedef void     DT_Mdep_Thread_Start_Routine_Return_Type;

#define DT_MDEP_DEFAULT_STACK_SIZE 65536

typedef struct
{
    void			(*function) (void *);
    void			*param;
    DT_Mdep_ThreadHandleType	thread_handle;
    unsigned int    		stacksize;
} Thread;

/*
 * System information
 *
 */

typedef struct
{
    unsigned long int		system;
    unsigned long int		user;
    unsigned long int		idle;
} DT_CpuStat;

/*
 * Timing
 */
#if defined(_WIN64) && !defined(ReadTimeStampCounter)

static _INLINE_ _ReadTimeStampCounter(void)
{
	LARGE_INTEGER	val;
	QueryPerformanceCounter( &val );
	return val.QuadPart;
}
#define ReadTimeStampCounter _ReadTimeStampCounter
#endif

typedef unsigned __int64 	DT_Mdep_TimeStamp;

static _INLINE_ DT_Mdep_TimeStamp
DT_Mdep_GetTimeStamp ( void )
{
#if !defined (_WIN64) && !defined (IA64)
    _asm rdtsc
#else

#ifndef ReadTimeStampCounter

#define ReadTimeStampCounter()  __rdtsc()

    DWORD64
    __rdtsc (VOID);

#endif

    return (DT_Mdep_TimeStamp) ReadTimeStampCounter();

#endif //endif !_WIN64, and !IA64
}

/*
 * Define types for Window compatibility
 */

typedef __int64          int64_t;
typedef unsigned __int64 uint64_t;
typedef __int32          int32_t;
typedef unsigned __int32 uint32_t;


#define bzero(x, y)  memset(x, 0, y)

/*
 * Define long format types to be used in *printf format strings.  We
 * use the C string constant concatenation ability to define 64 bit
 * formats, which unfortunatly are non standard in the C compiler
 * world. E.g. %llx for gcc, %I64x for Windows
 */
#define F64d   "%I64d"
#define F64u   "%I64u"
#define F64x   "%I64x"
#define F64X   "%I64X"

/*
 * Define notion of a LONG LONG 0
 */
#define LZERO 0UL

#endif /* __DAPL_MDEP_USER_H__ */
