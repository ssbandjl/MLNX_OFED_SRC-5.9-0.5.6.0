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

#ifndef __DAPL_KERNEL_MDEP_H__
#define __DAPL_KERNEL_MDEP_H__

/* include files */

# include <linux/errno.h>
# include <linux/types.h>
# include <linux/kernel.h>
# include <linux/string.h>
# include <asm/atomic.h>
# include <linux/delay.h>
# include <linux/wait.h>
# include <dat2/kdat.h>
# include "kdapl_ioctl.h"
#ifndef UPCALL_FROM_IRQ
#include <linux/interrupt.h>		/* for spin_lock_bh */
#endif /* UPCALL_FROM_IRQ */

/* Default Device Name */
#define DT_MdepDeviceName    "ia0a"

/* Boolean */
typedef int     bool;

#define true (1)
#define false (0)

#ifndef __BASE_FILE__
#define __BASE_FILE__ __FILE__
#endif

#ifndef _INLINE_
#define _INLINE_  __inline__
#endif

/*
 * Locks
 */

typedef spinlock_t DT_Mdep_LockType;

/*
 * If UPCALL_FROM_IRQ is defined, the provider will invoke upcalls
 * directly from IRQ. Most providers invoke upcalls from the Linux
 * BH handler, the default here.
 *
 * Locks must be adapted to match the actual upcall context!
 */
#ifdef UPCALL_FROM_IRQ
#define SPINLOCK(lp)		spin_lock_irq (lp);
#define SPINUNLOCK(lp)		spin_unlock_irq (lp);
#else
#define SPINLOCK(lp)		spin_lock_bh (lp);
#define SPINUNLOCK(lp)		spin_unlock_bh (lp);
#endif


/* Wait object used for inter thread communication */

typedef wait_queue_head_t DT_WAIT_OBJECT;

/*
 * Thread types
 */
typedef int         DT_Mdep_ThreadHandleType;
typedef void      (*DT_Mdep_ThreadFunction) (void *param);
typedef void *      DT_Mdep_Thread_Start_Routine_Return_Type;
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

typedef unsigned long long int 		DT_Mdep_TimeStamp;

static _INLINE_ DT_Mdep_TimeStamp
DT_Mdep_GetTimeStamp ( void )
{
#if defined(__GNUC__) && defined(__PENTIUM__)
    DT_Mdep_TimeStamp x;
    __asm__ volatile (".byte 0x0f, 0x31" : "=A" (x));
    return x;
#else

#ifdef __ia64__
    unsigned long x;

    x = get_cycles ();
    return x;
#else
#error "Non-Pentium Linux - unimplemented"
#endif
#endif

}

#ifndef __ia64__
typedef int *            intptr_t;
typedef unsigned long    uintptr_t;
#endif

#define bzero(x, y)  memset(x, 0, y)

/*
 * Define long format types to be used in *printf format strings.  We
 * use the C string constant concatenation ability to define 64 bit
 * formats, which unfortunatly are non standard in the C compiler
 * world. E.g. %llx for gcc, %I64x for Windows
 */
#ifdef __x86_64__
#define F64d   "%ld"
#define F64u   "%lu"
#define F64x   "%lx"
#define F64X   "%lX"
#else
#define F64d   "%lld"
#define F64u   "%llu"
#define F64x   "%llx"
#define F64X   "%llX"
#endif

/*
 * Define notion of a LONG LONG 0
 */
#define LZERO 0ULL

/* Mdep function defines */

#define DT_Mdep_flush()
#endif
