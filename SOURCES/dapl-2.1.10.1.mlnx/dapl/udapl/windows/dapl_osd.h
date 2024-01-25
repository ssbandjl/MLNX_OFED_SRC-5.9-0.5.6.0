/*
 * Copyright (c) 2002-2003, Network Appliance, Inc. All rights reserved.
 *
 * This Software is licensed under either one of the following two licenses:
 *
 * 1) under the terms of the "Common Public License 1.0" a copy of which is
 *    in the file LICENSE.txt in the root directory. The license is also
 *    available from the Open Source Initiative, see
 *    http://www.opensource.org/licenses/cpl.php.
 * OR
 *
 * 2) under the terms of the "The BSD License" a copy of which is in the file
 *    LICENSE2.txt in the root directory. The license is also available from
 *    the Open Source Initiative, see
 *    http://www.opensource.org/licenses/bsd-license.php.
 *
 * Licensee has the right to choose either one of the above two licenses.
 *
 * Redistributions of source code must retain both the above copyright
 * notice and either one of the license notices.
 *
 * Redistributions in binary form must reproduce both the above copyright
 * notice, either one of the license notices in the documentation
 * and/or other materials provided with the distribution.
 */

/**********************************************************************
 * 
 * HEADER: dapl_osd.h
 *
 * PURPOSE: Operating System Dependent layer
 * Description:
 *	Provide OS dependent data structures & functions with
 *	a canonical DAPL interface. Designed to be portable
 *	and hide OS specific quirks of common functions.
 *
 * $Id: dapl_osd.h 33 2005-07-11 19:51:17Z ftillier $
 **********************************************************************/

#ifndef _DAPL_OSD_H_
#define _DAPL_OSD_H_

/*
 * This file is defined for Windows systems only, including it on any
 * other build will cause an error
 */
#if !defined(_WIN32) && !defined(_WIN64)
#error UNDEFINED OS TYPE
#endif /* WIN32 */

#include <stddef.h>
#include <complib/cl_types.h>
#include <_errno.h>
#pragma warning ( push, 3 )
#include <winioctl.h>
#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <process.h>
#include <stdlib.h>
#pragma warning ( pop )

#include "dapl_debug.h"

/* Export Header */
#ifdef EXPORT_DAPL_SYMBOLS	/* 1 when building DAPL DLL, 0 for clients */
#define DAPL_EXPORT __declspec( dllexport )
#else
#define DAPL_EXPORT __declspec( dllimport )
#endif

/* Useful debug definitions */
#ifndef STATIC
#define STATIC static
#endif /* STATIC */

#ifndef _INLINE_
#define _INLINE_ __inline
#endif /* _INLINE_ */

#define dapl_os_panic(str) 			\
	{					\
	     fprintf(stderr, "PANIC in %s:%i:%s\n", __FILE__, __LINE__); \
	     fprintf(stderr, str); 	\
             exit(1);				\
	}

#define openlog(...)
#define closelog(...)

/*
 * Atomic operations
 */

typedef volatile DAT_COUNT DAPL_ATOMIC;

/* atomic function prototypes */
STATIC __inline DAT_COUNT
dapl_os_atomic_inc (
	INOUT	DAPL_ATOMIC *v);

STATIC __inline DAT_COUNT
dapl_os_atomic_dec ( 
	INOUT	DAPL_ATOMIC *v);

STATIC __inline DAT_COUNT
dapl_os_atomic_assign (
    INOUT DAPL_ATOMIC *v,
    IN	DAT_COUNT match_value,
    IN	DAT_COUNT new_value );

#define dapl_os_atomic_read(v)	(*v)
#define dapl_os_atomic_set(v,i)	(*v = i)

int dapl_os_get_env_bool (
	char		*env_str );

int dapl_os_get_env_val (
	char		*env_str,
	int		def_val );


/* atomic functions */

/* dapl_os_atomic_inc
 *
 * get the current value of '*v', and then increment it.
 *
 * This is equivalent to an IB atomic fetch and add of 1,
 * except that a DAT_COUNT might be 32 bits, rather than 64
 * and it occurs in local memory.
 */

STATIC __inline DAT_COUNT
dapl_os_atomic_inc (
	INOUT	DAPL_ATOMIC *v)
{
	return InterlockedIncrement( v );
}


/* dapl_os_atomic_dec
 *
 * decrement the current value of '*v'. No return value is required.
 */

STATIC __inline DAT_COUNT
dapl_os_atomic_dec ( 
	INOUT	DAPL_ATOMIC *v)
{
	return InterlockedDecrement( v );
}


/* dapl_os_atomic_assign
 *
 * assign 'new_value' to '*v' if the current value
 * matches the provided 'match_value'.
 *
 * Make no assignment if there is no match.
 *
 * Return the current value in any case.
 *
 * This matches the IBTA atomic operation compare & swap
 * except that it is for local memory and a DAT_COUNT may
 * be only 32 bits, rather than 64.
 */

STATIC __inline DAT_COUNT
dapl_os_atomic_assign (
    INOUT DAPL_ATOMIC *v,
    IN	DAT_COUNT match_value,
    IN	DAT_COUNT new_value )
{
	return InterlockedCompareExchange((LPLONG)v, 
							  new_value,
							  match_value);
}


/*
 * Thread Functions
 */
typedef HANDLE  DAPL_OS_THREAD;

DAT_RETURN 
dapl_os_thread_create (
	IN  void			(*func)	(void *),
	IN  void			*data,
	OUT DAPL_OS_THREAD		*thread_id );


/*
 * Lock Functions
 */
typedef HANDLE  DAPL_OS_LOCK;

/* function prototypes */
/* lock functions */
STATIC __inline DAT_RETURN 
dapl_os_lock_init (
    IN	DAPL_OS_LOCK *m)
{
    *m = CreateMutex (0, FALSE, 0);

    return *m ? DAT_SUCCESS : (DAT_CLASS_ERROR | DAT_INSUFFICIENT_RESOURCES);
}

STATIC __inline DAT_RETURN 
dapl_os_lock (
    IN	DAPL_OS_LOCK *m)
{
    WaitForSingleObject (*m, INFINITE);

    return DAT_SUCCESS;
}

STATIC __inline DAT_RETURN 
dapl_os_unlock (
    IN	DAPL_OS_LOCK *m)
{
    ReleaseMutex (*m);

    return DAT_SUCCESS;
}

STATIC __inline DAT_RETURN 
dapl_os_lock_destroy (
    IN	DAPL_OS_LOCK *m)
{
    CloseHandle (*m);

    return DAT_SUCCESS;
}


/*
 * Wait Objects
 */

/*
 * The wait object invariant: Presuming a call to dapl_os_wait_object_wait
 * occurs at some point, there will be at least one wakeup after each call
 * to dapl_os_wait_object_signal.  I.e. Signals are not ignored, though
 * they may be coallesced.
 */

/* wait_object functions */

typedef HANDLE DAPL_OS_WAIT_OBJECT;

/* Initialize a wait object to an empty state
 */

STATIC __inline DAT_RETURN 
dapl_os_wait_object_init (
    IN DAPL_OS_WAIT_OBJECT *wait_obj)
{
    *wait_obj = CreateEvent(NULL,FALSE,FALSE,NULL);

    if ( *wait_obj == NULL )
    {
	return DAT_CLASS_ERROR | DAT_INTERNAL_ERROR;
    }

    return DAT_SUCCESS;
}


/* Wait on the supplied wait object, up to the specified time_out,
 * and reacquiring it after the wait ends.
 * A timeout of DAT_TIMEOUT_INFINITE will wait indefinitely.
 * Timeout should be specified in micro seconds.
 *
 * Functional returns:
 *	DAT_SUCCESS -- another thread invoked dapl_os_wait object_wakeup
 * 	DAT_INVALID_STATE -- someone else is already waiting in this wait
 * 	object.
 *			     only one waiter is allowed at a time.
 *	DAT_ABORT -- another thread invoked dapl_os_wait_object_destroy
 *	DAT_TIMEOUT -- the specified time limit was reached.
 */

STATIC __inline DAT_RETURN 
dapl_os_wait_object_wait (
    IN	DAPL_OS_WAIT_OBJECT *wait_obj, 
    IN  DAT_TIMEOUT timeout_val)
{
    DAT_RETURN 		status;
    DWORD		op_status;

    status = DAT_SUCCESS;

    if ( DAT_TIMEOUT_INFINITE == timeout_val )
    {
	op_status = WaitForSingleObject(*wait_obj, INFINITE);
    }
    else
    {
	/* convert to milliseconds */
	op_status = WaitForSingleObject(*wait_obj, timeout_val/1000);
    }

    if (op_status == WAIT_TIMEOUT)
    {
	status = DAT_CLASS_ERROR | DAT_TIMEOUT_EXPIRED;
    }
    else if ( op_status  == WAIT_FAILED)
    {
	status = DAT_CLASS_ERROR | DAT_INTERNAL_ERROR;
    }

    return status;
}

STATIC __inline DAT_RETURN 
dapl_os_wait_object_wakeup (
    IN	DAPL_OS_WAIT_OBJECT *wait_obj)
{
    DWORD		op_status;

    op_status = SetEvent(*wait_obj);
    if ( op_status == 0 )
    {
	return DAT_CLASS_ERROR | DAT_INTERNAL_ERROR;
    }

    return DAT_SUCCESS;
}

STATIC __inline DAT_RETURN 
dapl_os_wait_object_destroy (
    IN	DAPL_OS_WAIT_OBJECT *wait_obj)
{
    DWORD		op_status;
    DAT_RETURN		status = DAT_SUCCESS;

    op_status = CloseHandle(*wait_obj);

    if ( op_status == 0 )
    {
	status = DAT_CLASS_ERROR | DAT_INTERNAL_ERROR;
    }

    return status;
}


/*
 * Memory Functions
 */

extern HANDLE heap;

/* function prototypes */
STATIC __inline void *dapl_os_alloc (int size);

STATIC __inline void *dapl_os_realloc (void *ptr, int size);

STATIC __inline void dapl_os_free (void *ptr, int size);

STATIC __inline void * dapl_os_memzero (void *loc, int size);

STATIC __inline void * dapl_os_memcpy (void *dest, const void *src, int len);

STATIC __inline int dapl_os_memcmp (const void *mem1, const void *mem2, int len);

/*
 * Memory coherency functions
 * For i386/x86_64 Windows, there are no coherency issues - just return success.
 */
STATIC __inline  DAT_RETURN
dapl_os_sync_rdma_read (
    IN      const DAT_LMR_TRIPLET	*local_segments,
    IN      DAT_VLEN			num_segments)
{
    return DAT_SUCCESS;
}

STATIC __inline  DAT_RETURN
dapl_os_sync_rdma_write (
    IN      const DAT_LMR_TRIPLET	*local_segments,
    IN      DAT_VLEN			num_segments)
{
    return DAT_SUCCESS;
}


/* memory functions */


STATIC __inline void *dapl_os_alloc (int size)
{
	return HeapAlloc(heap, 0, size);
}

STATIC __inline void *dapl_os_realloc (void *ptr, int size)
{
    return HeapReAlloc(heap, 0, ptr, size);
}

STATIC __inline void dapl_os_free (void *ptr, int size)
{
	UNREFERENCED_PARAMETER(size);
	HeapFree(heap, 0, ptr);
}

STATIC __inline void * dapl_os_memzero (void *loc, int size)
{
    return memset (loc, 0, size);
}

STATIC __inline void * dapl_os_memcpy (void *dest, const void *src, int len)
{
    return memcpy (dest, src, len);
}

STATIC __inline int dapl_os_memcmp (const void *mem1, const void *mem2, int len)
{
    return memcmp (mem1, mem2, len);
}


STATIC __inline unsigned int dapl_os_strlen(const char *str)
{
    return ((unsigned int)strlen(str));
}

STATIC __inline char * dapl_os_strdup(const char *str)
{
	char *dup;

	dup = dapl_os_alloc(strlen(str) + 1);
	if (!dup)
		return NULL;
	strcpy(dup, str);
    return dup;
}


/*
 * Timer Functions
 */

typedef DAT_UINT64		DAPL_OS_TIMEVAL;
typedef struct dapl_timer_entry		DAPL_OS_TIMER;
typedef unsigned long 		DAPL_OS_TICKS;

/* function prototypes */

/*
 * Sleep for the number of micro seconds specified by the invoking
 * function
 */
STATIC __inline void dapl_os_sleep_usec (int sleep_time)
{
    Sleep(sleep_time/1000); // convert to milliseconds
}

STATIC __inline DAPL_OS_TICKS dapl_os_get_ticks (void);

STATIC __inline int dapl_os_ticks_to_seconds (DAPL_OS_TICKS ticks);

DAT_RETURN dapl_os_get_time (DAPL_OS_TIMEVAL *);
/* timer functions */

STATIC __inline DAPL_OS_TICKS dapl_os_get_ticks (void)
{
    return GetTickCount ();
}

STATIC __inline int dapl_os_ticks_to_seconds (DAPL_OS_TICKS ticks)
{
    ticks = ticks;
    /* NOT YET IMPLEMENTED IN USER-SPACE */
    return 0;
}


/*
 *
 * Name Service Helper functions
 *
 */
#ifdef IBHOSTS_NAMING
#define dapls_osd_getaddrinfo(name, addr_ptr) getaddrinfo(name,NULL,NULL,addr_ptr)
#define dapls_osd_freeaddrinfo(addr) freeaddrinfo (addr)

#endif /* IBHOSTS_NAMING */

/*
 * *printf format helpers. We use the C string constant concatenation
 * ability to define 64 bit formats, which unfortunatly are non standard
 * in the C compiler world. E.g. %llx for gcc, %I64x for Windows
 */
#define F64d   "%I64d"
#define F64u   "%I64u"
#define F64x   "%I64x"
#define F64X   "%I64X"

/*
 *  Conversion Functions
 */

STATIC __inline long int
dapl_os_strtol(const char *nptr, char **endptr, int base)
{
    return strtol(nptr, endptr, base);
}

#define dapl_os_getpid	(DAT_UINT32)GetCurrentProcessId
#define dapl_os_gettid	(DAT_UINT32)GetCurrentThreadId

/*
 *  Debug Helper Functions
 */

#define dapl_os_assert(expression)	CL_ASSERT(expression)

#define dapl_os_printf 			printf
#define dapl_os_vprintf(fmt,args)	vprintf(fmt,args)
#define dapl_os_syslog(fmt,args)	/* XXX Need log routine call */

#endif /*  _DAPL_OSD_H_ */

/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 8
 * End:
 */
