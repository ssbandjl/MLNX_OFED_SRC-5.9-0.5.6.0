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

#include "dapl_mdep.h"
#include "dapl_proto.h"

#include <sys/times.h>
#include <limits.h>
#include <sys/time.h>
#include <stdlib.h>			/* needed for getenv() */
#include <pthread.h>			/* needed for pthread_atfork() */
#include <signal.h>			/* needed for thread setup */

#include "dapl_test_data.h"	/* for alloc_count */


/*
 * Machine dependant initialization
 */

void
DT_Mdep_Init (void)
{
    /* nothing */
}

/*
 * Machine dependant deinitialization
 */

void
DT_Mdep_End (void)
{
    /* nothing */
}

/*
 * Generate name of IB device
 */

bool
DT_Mdep_GetDefaultDeviceName (char *dapl_name)
{
    strcpy (dapl_name, DT_MdepDeviceName);
    return true;
}

/*
 * Sleep specified number of milliseconds
 */

void
DT_Mdep_Sleep (int msec)
{
    struct timespec t;
    t.tv_sec = msec / 1000;	/* Whole seconds */
    t.tv_nsec = (msec % 1000) * 1000 * 1000;
    nanosleep (&t, 0);
}

void
DT_Mdep_Schedule (void)
{
    /* void  */
}
/*
 * Get system statistics including uptime and idle time
 */

bool
DT_Mdep_GetCpuStat (
    DT_CpuStat 			*cpu_stat )
{
    /* FIXME not implemented */
    return true;
}

/*
 * Get current time in milliseconds (relative to some fixed point)
 */
unsigned long
DT_Mdep_GetTime (void)
{
    struct tms      ts;
    clock_t         t = times (&ts);
    return (unsigned long) ((DAT_UINT64) t * 1000 / CLK_TCK);
}

double
DT_Mdep_GetCpuMhz (
    void )
{
    #error "Undefined Platform"
}


unsigned long
DT_Mdep_GetContextSwitchNum (void )
{
    #error "Undefined Platform"
}

/*
 * Memory allocate and free routines for control blocks (objects) - regular
 * memory, always zeroed.
 */
void           *
DT_Mdep_Malloc (size_t l_)
{
    void *rval;

    /*
     * check memory leaking DT_Mdep_Lock(&Alloc_Count_Lock); alloc_count++;
     * DT_Mdep_Unlock(&Alloc_Count_Lock);
     */

    rval = malloc (l_);

    if (rval)
    {
	memset (rval, 0, l_);
    }
    return ( rval );
}

void
DT_Mdep_Free (void *a_)
{
    /*
     * check memory leaking DT_Mdep_Lock(&Alloc_Count_Lock); alloc_count--;
     * DT_Mdep_Unlock(&Alloc_Count_Lock);
     */

    free (a_);
}

/*
 * Lock support
 *
 * Lock object constructor
 */
bool
DT_Mdep_LockInit (DT_Mdep_LockType * lock_ptr)
{
    return pthread_mutex_init (lock_ptr, 0) ? false : true;
}

/*
 * Lock object destructor
 */
void
DT_Mdep_LockDestroy (DT_Mdep_LockType * lock_ptr)
{
    pthread_mutex_destroy (lock_ptr);
}

/*
 * Lock
 */
void
DT_Mdep_Lock (DT_Mdep_LockType * lock_ptr)
{
    pthread_mutex_lock (lock_ptr);
}

/*
 * unlock
 */
void
DT_Mdep_Unlock (DT_Mdep_LockType * lock_ptr)
{
    pthread_mutex_unlock (lock_ptr);
}

/*
 * Init Thread Attributes
 */
void
DT_Mdep_Thread_Init_Attributes (Thread * thread_ptr)
{
    pthread_attr_init (&thread_ptr->attr);
    pthread_attr_setstacksize (&thread_ptr->attr, thread_ptr->stacksize);
    /* Create thread in detached state to free resources on termination;
    * this precludes doing a pthread_join, but we don't do it
    */
    pthread_attr_setdetachstate (&thread_ptr->attr, PTHREAD_CREATE_DETACHED);
}

/*
 * Destroy Thread Attributes
 */
void
DT_Mdep_Thread_Destroy_Attributes (Thread * thread_ptr)
{
    pthread_attr_destroy (&thread_ptr->attr);
}

/*
 * Start the thread
 */
bool
DT_Mdep_Thread_Start (Thread * thread_ptr)
{
    return pthread_create (&thread_ptr->thread_handle,
			  &thread_ptr->attr,
			  DT_Mdep_Thread_Start_Routine,
			  thread_ptr) == 0;
}

/*
 * Thread execution entry point function
 */
DT_Mdep_Thread_Start_Routine_Return_Type
DT_Mdep_Thread_Start_Routine (void *thread_handle)
{
    Thread         *thread_ptr;
    thread_ptr = (Thread *) thread_handle;

    thread_ptr->function (thread_ptr->param);
    return 0;
}

/*
 * Thread detach routine.  Allows the pthreads
 * interface to clean up resources properly at
 * thread's end.
 */
void DT_Mdep_Thread_Detach ( int thread_id )  /* AMM */
{
    pthread_detach ( thread_id);
}

/*
 *  Allows a thread to get its own ID so it
 *  can pass it to routines wanting to act
 *  upon themselves.
 */

int DT_Mdep_Thread_SELF (void)	/* AMM */
{

    return (pthread_self ());
}


/*
 *  Allow a thread to exit and cleanup resources.
 */

void  DT_Mdep_Thread_EXIT ( void * thread_handle )  /* AMM */
{
    pthread_exit ( thread_handle );
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
int
DT_Mdep_wait_object_init (
	IN DT_WAIT_OBJECT *wait_obj)
{

    wait_obj->signaled = DAT_FALSE;
    if ( 0 != pthread_cond_init ( &wait_obj->cv, NULL ) )
    {
	return (-1);
    }

    /* Always returns 0.  */
    pthread_mutex_init ( &wait_obj->lock, NULL );
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

int
DT_Mdep_wait_object_wait (
	IN	DT_WAIT_OBJECT *wait_obj,
	IN  int timeout_val)
{

    int 		dat_status;
    int 		pthread_status;
    struct timespec 	future;

    dat_status = 0;
    pthread_status = 0;

    if ( timeout_val != DAT_TIMEOUT_INFINITE )
    {
	struct timeval now;
	struct timezone tz;
	unsigned int microsecs;

	gettimeofday (&now, &tz);
	microsecs = now.tv_usec + (timeout_val % 1000000);
	if (microsecs > 1000000)
	{
	    now.tv_sec = now.tv_sec + timeout_val / 1000000 + 1;
	    now.tv_usec = microsecs - 1000000;
	}
	else
	{
	    now.tv_sec = now.tv_sec + timeout_val / 1000000;
	    now.tv_usec = microsecs;
	}

	/* Convert timeval to timespec */
	future.tv_sec = now.tv_sec;
	future.tv_nsec = now.tv_usec * 1000;

	pthread_mutex_lock (&wait_obj->lock);
	while ( wait_obj->signaled == DAT_FALSE && pthread_status == 0)
	{
	    pthread_status = pthread_cond_timedwait (
		    &wait_obj->cv, &wait_obj->lock, &future );

	    /*
		 * No need to reset &future if we go around the loop;
		 * It's an absolute time.
		 */
	}
	/* Reset the signaled status if we were woken up.  */
	if (pthread_status == 0)
	{
	    wait_obj->signaled = false;
	}
	pthread_mutex_unlock (&wait_obj->lock);
    }
    else
    {
	pthread_mutex_lock (&wait_obj->lock);
	while ( wait_obj->signaled == DAT_FALSE && pthread_status == 0)
	{
	    pthread_status = pthread_cond_wait (
		    &wait_obj->cv, &wait_obj->lock );
	}
	/* Reset the signaled status if we were woken up.  */
	if (pthread_status == 0)
	{
	    wait_obj->signaled = false;
	}
	pthread_mutex_unlock (&wait_obj->lock);
    }

    if (ETIMEDOUT == pthread_status)
    {
	return (-1);
    }
    else if ( 0 != pthread_status)
    {
	return (-1);
    }

    return 0;
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
int
DT_Mdep_wait_object_wakeup (
	DT_WAIT_OBJECT *wait_obj )
{
    pthread_mutex_lock ( &wait_obj->lock );
    wait_obj->signaled = true;
    pthread_mutex_unlock ( &wait_obj->lock );
    if ( 0 != pthread_cond_signal ( &wait_obj->cv ) )
    {
	return (-1);
    }

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
int
DT_Mdep_wait_object_destroy (
	IN	DT_WAIT_OBJECT *wait_obj)
{

    if ( 0 != pthread_cond_destroy ( &wait_obj->cv ) )
    {
	return (-1);
    }
    if ( 0 != pthread_mutex_destroy ( &wait_obj->lock ) )
    {
	return (-1);
    }

    return 0;


}

