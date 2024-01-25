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

#include "dapl_proto.h"
#include "kdapl_tdep.h"
#include <linux/slab.h>
#ifndef UPCALL_FROM_IRQ
#include <linux/interrupt.h>	/* for spin_lock_bh */
#endif				/* UPCALL_FROM_IRQ */

#include <linux/kernel_stat.h>	/* Getting Statistics */
#include <linux/smp.h>		/* Definitions of smp_num_cpus and cpu_logical_map(cpu)  */
#include <linux/sched.h>	/* jiffies */
#include <linux/version.h>

/*
 * Sleep specified number of milliseconds
 */

void DT_Mdep_Sleep(int msec)
{
	set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(msec * HZ / 1000);
}

void DT_Mdep_Schedule(void)
{
	schedule();
}

/*
 * Get system statistics including uptime and idle time
 */

bool DT_Mdep_GetCpuStat(DT_CpuStat * cpu_stat)
{
	unsigned long i, nice = 0;
	unsigned long jif = jiffies;
	int cpu, num_of_cpus;
	cpu_stat->user = 0;
	cpu_stat->system = 0;
	cpu_stat->idle = 0;
	num_of_cpus = 0;
	cpu = 0;

	// code for vanila 2.4 kernel
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)) && !defined RHAS3
	for (i = 0; i < smp_num_cpus; i++) {
		cpu = cpu_logical_map(i);
		cpu_stat->user += (unsigned long)kstat.per_cpu_user[cpu];
		nice += (unsigned long)kstat.per_cpu_nice[cpu];
		cpu_stat->system += (unsigned long)kstat.per_cpu_system[cpu];
	}
	// kernel 2.4 AS3.0
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)) && defined RHAS3
	cpu_stat->user = kstat_sum(accumulated_time.u_usec);
	cpu_stat->system = kstat_sum(accumulated_time.s_usec);
	nice = kstat_sum(accumulated_time.n_usec);
	// kernel 2.6
#elif LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
	for (i = 0; i < NR_CPUS; i++) {
		if (cpu_possible(i)) {
			cpu_stat->system += kstat_cpu(i).cpustat.system;
			cpu_stat->user += kstat_cpu(i).cpustat.user;
			nice += kstat_cpu(i).cpustat.nice;
			num_of_cpus = +1;
		}
	}
#endif
	cpu_stat->idle =
	    (unsigned long)(jif * num_of_cpus -
			    (cpu_stat->user + nice + cpu_stat->system));
	return true;
}

/*
 * Get current time in milliseconds (relative to some fixed point)
 */
unsigned long DT_Mdep_GetTime(void)
{
	struct timeval tv;

	do_gettimeofday(&tv);
	return ((unsigned long)(tv.tv_sec) * 1000L) +
	    (unsigned long)(tv.tv_usec) / 1000;
}

#if 0
unsigned long DT_Mdep_GetContextSwitchNum(void)
{
	return nr_context_switches();
}
#endif

/*
 * Memory allocate and free routines for control blocks (objects) - regular
 * memory, always zeroed.
 */
void *DT_Mdep_Malloc(size_t l_)
{
	void *rval;

	/*
	 * check memory leaking DT_Mdep_Lock(&Alloc_Count_Lock); alloc_count++;
	 * DT_Mdep_Unlock(&Alloc_Count_Lock);
	 */

	rval = kmalloc(l_, GFP_ATOMIC);

	if (rval) {
		memset(rval, 0, l_);
	}
	return (rval);
}

void DT_Mdep_Free(void *a_)
{
	/*
	 * check memory leaking DT_Mdep_Lock(&Alloc_Count_Lock); alloc_count--;
	 * DT_Mdep_Unlock(&Alloc_Count_Lock);
	 */

	kfree(a_);
}

/*
 * Lock support
 *
 * Lock object constructor
 */
bool DT_Mdep_LockInit(DT_Mdep_LockType * lock_ptr)
{
	spin_lock_init(lock_ptr);
	return true;
}

/*
 * Lock object destructor
 */
void DT_Mdep_LockDestroy(DT_Mdep_LockType * lock_ptr)
{
	/* nothing */
}

/*
 * Locks
 *
 */
void DT_Mdep_Lock(DT_Mdep_LockType * lock_ptr)
{
	SPINLOCK(lock_ptr);
}

/*
 * unlock
 */
void DT_Mdep_Unlock(DT_Mdep_LockType * lock_ptr)
{
	SPINUNLOCK(lock_ptr);
}

/*
 * Init Thread Attributes
 */
void DT_Mdep_Thread_Init_Attributes(Thread * thread_ptr)
{
	/* nothing */
}

/*
 * Destroy Thread Attributes
 */
void DT_Mdep_Thread_Destroy_Attributes(Thread * thread_ptr)
{
	/* nothing */
}

/*
 * Start the thread
 */
bool DT_Mdep_Thread_Start(Thread * thread_ptr)
{
	thread_ptr->thread_handle = kernel_thread((void *)
						  DT_Mdep_Thread_Start_Routine,
						  (void *)thread_ptr, 0);
	return (thread_ptr->thread_handle);
}

/*
 * Thread execution entry point function
 */
DT_Mdep_Thread_Start_Routine_Return_Type
DT_Mdep_Thread_Start_Routine(void *thread_handle)
{
	Thread *thread_ptr;
	thread_ptr = (Thread *) thread_handle;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	reparent_to_init();
#else
	daemonize(__func__);
#endif
	thread_ptr->function(thread_ptr->param);
	return 0;
}

/*
 * Thread detach routine.  Allows the pthreads
 * interface to clean up resources properly at
 * thread's end.
 */
void DT_Mdep_Thread_Detach(int thread_id)
{				/* AMM */
	/* nothing */
}

/*
 *  Allows a thread to get its own ID so it
 *  can pass it to routines wanting to act
 *  upon themselves.
 */

int DT_Mdep_Thread_SELF(void)
{				/* AMM */
	/* nothing */
	return (0);
}

/*
 *  Allow a thread to exit and cleanup resources.
 */

void DT_Mdep_Thread_EXIT(void *thread_handle)
{				/* AMM */
	/* nothing */
}

/*
 * DT_Mdep_wait_object_init
 *
 * Initialize a wait object
 *
 * Input:
 *	wait_obj
 *
 * Returns:
 *	0 if successful
 *	-1 if unsuccessful
 */
int DT_Mdep_wait_object_init(IN DT_WAIT_OBJECT * wait_obj)
{
	init_waitqueue_head(wait_obj);
	return 0;
}

/* Wait on the supplied wait object, up to the specified time_out.
 * A timeout of DAT_TIMEOUT_INFINITE will wait indefinitely.
 * Timeout should be specified in micro seconds.
 *
 * Functional returns:
 *	0 -- another thread invoked dapl_os_wait object_wakeup
 * 	-1 -- someone else is already waiting in this wait
 * 	object.
 *			     only one waiter is allowed at a time.
 *	-1 -- another thread invoked dapl_os_wait_object_destroy
 *	-1 -- the specified time limit was reached.
 */

int DT_Mdep_wait_object_wait(IN DT_WAIT_OBJECT * wait_obj, IN int timeout_val)
{
	int expire;
	int dat_status;

	dat_status = DAT_SUCCESS;
	if (DAT_TIMEOUT_INFINITE == timeout_val) {
		interruptible_sleep_on(wait_obj);
	} else {
		expire = timeout_val * HZ / 1000000;
		while (expire) {
			current->state = TASK_INTERRUPTIBLE;
			expire = schedule_timeout(expire);
		}
		dat_status = DAT_TIMEOUT_EXPIRED;
	}
	return dat_status;
}

/*
 * DT_Mdep_wait_object_wakeup
 *
 * Wakeup a thread waiting on a wait object
 *
 * Input:
 *      wait_obj
 *
 * Returns:
 *	0 if successful
 *	-1 if not successful
 */
int DT_Mdep_wait_object_wakeup(DT_WAIT_OBJECT * wait_obj)
{
	wake_up_interruptible(wait_obj);
	return 0;
}

/*
 * DT_Mdep_wait_object_destroy
 *
 * Destroy a wait object
 *
 * Input:
 *      wait_obj
 *
 * Returns:
 *	0 if successful
 *	-1 if not successful
 */
int DT_Mdep_wait_object_destroy(IN DT_WAIT_OBJECT * wait_obj)
{
	return 0;
}
