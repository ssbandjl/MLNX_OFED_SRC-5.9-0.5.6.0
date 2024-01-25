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

#include <process.h>

#include "dapl_test_data.h"	/* for alloc_count */

/*
 * Machine dependant initialization
 */

void
DT_Mdep_Init (void)
{
    /* Initialize winsic2 */
    /*
     * Needs to be done in main(), it's too late here.
     */
    //    WORD            wv = MAKEWORD (1, 1);
    //    WSADATA         wsaData;
    //    WSAStartup (wv, &wsaData);
}

/*
 * Machine dependant deinitialization
 */

void
DT_Mdep_End (void)
{
    WSACleanup ();
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
    Sleep (msec);
}

/*
 * Get system statistics including uptime and idle time
 */
void
DT_Mdep_Schedule (void)
{
    /* nothing here */ 
}

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
    return GetTickCount ();
}

double
DT_Mdep_GetCpuMhz (
    void )
{
    LONG    retVal;
    HKEY    hKey;
    DWORD   cpuSpeed = 0;
    DWORD   dataSize = sizeof (DWORD);

    /* For windows need to query the registry to get the CPU
     * Information...-SVSV */
    retVal = RegOpenKeyEx (HKEY_LOCAL_MACHINE,
			  TEXT ("Hardware\\Description\\System\\CentralProcessor\\0"),
			  0,
			  KEY_QUERY_VALUE,
			  &hKey);

    if (retVal == ERROR_SUCCESS)
    {
	retVal = RegQueryValueEx (hKey,
				 TEXT ("~MHz"), NULL, NULL,
				 (LPBYTE)&cpuSpeed, &dataSize);

    }

    RegCloseKey (hKey);

    return cpuSpeed;
}


unsigned long
DT_Mdep_GetContextSwitchNum (void)
{
    return 0;
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
    *lock_ptr = CreateMutex (0, FALSE, 0);
    return *lock_ptr ? true : false;
}

/*
 * Lock object destructor
 */
void
DT_Mdep_LockDestroy (DT_Mdep_LockType * lock_ptr)
{
    CloseHandle (*lock_ptr);
}

/*
 * Lock
 */
void
DT_Mdep_Lock (DT_Mdep_LockType * lock_ptr)
{
    WaitForSingleObject (*lock_ptr, INFINITE);
}

/*
 * unlock
 */
void
DT_Mdep_Unlock (DT_Mdep_LockType * lock_ptr)
{
    ReleaseMutex (*lock_ptr);
}

/*
 * Init Thread Attributes
 */
void
DT_Mdep_Thread_Init_Attributes (Thread * thread_ptr)
{
    /* nothing */
}

/*
 * Destroy Thread Attributes
 */
void
DT_Mdep_Thread_Destroy_Attributes (Thread * thread_ptr)
{
    /* nothing */
}

/*
 * Start the thread
 */
bool
DT_Mdep_Thread_Start (Thread * thread_ptr)
{
    thread_ptr->thread_handle =
	    CreateThread (NULL,
			  0,
			  (LPTHREAD_START_ROUTINE)DT_Mdep_Thread_Start_Routine,
			  thread_ptr,
			  0,
			  NULL);
    if (thread_ptr->thread_handle == NULL)
    {
	return false;
    }
    return true;
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
}

/*
 * Thread detach routine.  Allows the pthreads
 * interface to clean up resources properly at
 * thread's end.
 */
void DT_Mdep_Thread_Detach (DT_Mdep_ThreadHandleType  thread_id )  /* AMM */
{
}

/*
 *  Allows a thread to get its own ID so it
 *  can pass it to routines wanting to act
 *  upon themselves.
 */

DT_Mdep_ThreadHandleType DT_Mdep_Thread_SELF (void)	/* AMM */
{
    return 0;
}


/*
 *  Allow a thread to exit and cleanup resources.
 */

void  DT_Mdep_Thread_EXIT ( void * thread_handle )  /* AMM */
{

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
int
DT_Mdep_wait_object_init (
	IN DT_WAIT_OBJECT *wait_obj)
{

    *wait_obj = CreateEvent (NULL, FALSE, FALSE, NULL);

    if ( *wait_obj == NULL )
    {
	return -1;
    }

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

    DAT_RETURN 		status;
    DWORD		op_status;

    status = DAT_SUCCESS;

    if ( DAT_TIMEOUT_INFINITE == timeout_val )
    {
	op_status = WaitForSingleObject (*wait_obj, INFINITE);
    }
    else
    {
	/* convert to milliseconds */
	op_status = WaitForSingleObject (*wait_obj, timeout_val/1000);
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
    DWORD		op_status;

    op_status = SetEvent (*wait_obj);
    if ( op_status == 0 )
    {
	return DAT_CLASS_ERROR | DAT_INTERNAL_ERROR;
    }

    return DAT_SUCCESS;
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

    DWORD		op_status;
    DAT_RETURN		status = DAT_SUCCESS;

    op_status = CloseHandle (*wait_obj);

    if ( op_status == 0 )
    {
	status = DAT_CLASS_ERROR | DAT_INTERNAL_ERROR;
    }

    return status;
}

