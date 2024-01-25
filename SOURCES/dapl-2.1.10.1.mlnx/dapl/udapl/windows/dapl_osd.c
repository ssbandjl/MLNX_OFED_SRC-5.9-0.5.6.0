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
 * MODULE: dapl_osd.c
 *
 * PURPOSE: Operating System Dependent layer
 * Description: 
 *	Provide OS dependent functions with a canonical DAPL
 *	interface. Designed to be portable and hide OS specific quirks
 *	of common functions.
 *		
 *
 * $Id: dapl_osd.c 33 2005-07-11 19:51:17Z ftillier $
 **********************************************************************/

/*
 * MUST have the Microsoft Platform SDK installed for Windows to build
 * and work properly
 */
#include "dapl.h"
#include "dapl_init.h"
#include "dapl_osd.h"
#include <sys/timeb.h>
#include <stdlib.h>			/* needed for getenv() */

HANDLE heap;

/*
 * DllMain
 *
 * Primary Windows entry point
 *
 * Input:
 *      hDllHandle     handle to DLL module
 *      fdwReason      reason for calling function
 *      lpReserved     reserved
 *
 * Returns:
 *	DAT_SUCCESS
 */

BOOL WINAPI
DllMain (
	 IN  HINSTANCE		hDllHandle,
	 IN  DWORD		fdwReason,
	 IN  LPVOID		lpReserved )
{
    UNREFERENCED_PARAMETER(lpReserved);

    switch( fdwReason ) 
    { 
        case DLL_PROCESS_ATTACH:
		heap = HeapCreate(0, 0, 0);
		if (heap == NULL) {
			return FALSE;
		}
	    /*
	     * We don't attach/detach threads that need any sort
	     * of initialization, so disable this ability to optimize
	     * the working set size of the DLL. Also allows us to
	     * remove two case statemens:
	     * DLL_THREAD_DETACH and DLL_THREAD_ATTACH
	     */
	    if ( (DisableThreadLibraryCalls( hDllHandle )) != 0)
            {
#if 0
            /*
             * Relocated to [dapl_init.c] ..._PROVIDER_INIT() as when called
             * from here calls to dapl_init/dapls_ib_init/ib_open_al() hang
             * in the DLL call context.
             */
                dapl_init ();
#endif
            }
            else
            {
                DWORD err = GetLastError();
                dapl_os_printf("DAPL Init Failed with code %u\n", err);
            }
            break;

        case DLL_PROCESS_DETACH:
            /* 
	     * Do library cleanup
	     */
#if 0
            /*
             * Relocated to [dapl_init.c] ..._PROVIDER_FINI() as the call to
             * dapl_fini/dapls_ib_release/ib_close_al() hangs in this DLL call
             * context.
             */
            dapl_fini ();
#endif
			HeapDestroy(heap);
            break;
    }
    return TRUE;  
}


#ifdef NOT_USED
/*
 * dapl_osd_init
 *
 * Do Windows specific initialization:
 *	- nothing at this time
 *
 * Input:
 *      none
 *
 * Returns:
 *	none
 */
void
dapl_osd_init ( )
{
    return;
}
#endif

/*
 * dapl_os_get_time
 *
 * Return 64 bit value of current time in microseconds.
 *
 * Input:
 *      loc       User location to place current time
 *
 * Returns:
 *	DAT_SUCCESS
 */

DAT_RETURN
dapl_os_get_time (
    OUT DAPL_OS_TIMEVAL * loc)
{
    struct _timeb	tb;
    
    _ftime ( &tb );

    *loc = ((DAT_UINT64) (tb.time * 1000000L) + (DAT_UINT64) tb.millitm * 1000);
    
    return DAT_SUCCESS;
}


/*
 * dapl_os_get_bool_env
 *
 * Return boolean value of passed in environment variable: 1 if present,
 * 0 if not
 *
 * Input:
 *      
 *
 * Returns:
 *	TRUE or FALSE
 */
int
dapl_os_get_env_bool (
	char		*env_str )
{
    char		*env_var;

    env_var = getenv (env_str);
    if (env_var != NULL)
    {
	return 1;
    }
    return 0;
}


/*
 * dapl_os_get_val_env
 *
 * Update val to  value of passed in environment variable if present
 *
 * Input:
 *      env_str
 *	def_val		default value if environment variable does not exist
 *
 * Returns:
 *	TRUE or FALSE
 */
int
dapl_os_get_env_val (
	char		*env_str,
	int		def_val )
{
    char		*env_var;

    env_var = getenv (env_str);
    if ( env_var != NULL )
    {
	def_val = strtol (env_var, NULL, 0);
    }

    return  def_val;
}


/*
 * dapls_os_thread_create
 *
 * Create a thread for dapl
 *
 * Input:
 *	func		function to invoke thread
 *	data		argument to pass to function
 *
 * Output
 *	thread_id	handle for thread
 *
 * Returns:
 *	DAT_SUCCESS
 */
DAT_RETURN 
dapl_os_thread_create (
	IN  void			(*func) (void *),
	IN  void 			*data,
	OUT DAPL_OS_THREAD		*thread_id )
{

    *thread_id = CreateThread(
			    NULL,        /* &thread security attrs    */
			    8 * 1024,    /* initial thread stack size */
			    (LPTHREAD_START_ROUTINE)func, /* &thread function */
			    data,	 /* argument for new thread   */
			    0,           /* creation flags            */
			    NULL);	 /* thread ID (ignore)        */

    if ( *thread_id == NULL )
    {
	return DAT_ERROR (DAT_INSUFFICIENT_RESOURCES, 0);
    }

    return DAT_SUCCESS;
}


/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 8
 * End:
 */
