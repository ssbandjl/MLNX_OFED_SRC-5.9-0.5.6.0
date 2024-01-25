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
 * MODULE: dat_osd.c
 *
 * PURPOSE: Operating System Dependent layer
 * Description: 
 *	Provide OS dependent functions with a canonical DAPL
 *	interface. Designed to be portable and hide OS specific quirks
 *	of common functions.
 *
 * $Id: dat_osd.c 33 2005-07-11 19:51:17Z ftillier $
 **********************************************************************/

#include "dat_osd.h"
#include "dat_init.h"


/*********************************************************************
 *                                                                   *
 * Constants                                                         *
 *                                                                   *
 *********************************************************************/

#define DAT_DBG_LEVEL_ENV 	"DAT_DBG_LEVEL"
#define DAT_DBG_DEST_ENV 	"DAT_DBG_DEST"


/*********************************************************************
 *                                                                   *
 * Enumerations                                                      *
 *                                                                   *
 *********************************************************************/

typedef int 			DAT_OS_DBG_DEST;

typedef enum
{
    DAT_OS_DBG_DEST_STDOUT  		= 0x1,
} DAT_OS_DBG_DEST_TYPE;


/*********************************************************************
 *                                                                   *
 * Global Variables                                                  *
 *                                                                   *
 *********************************************************************/

static DAT_OS_DBG_TYPE_VAL 	g_dbg_type = DAT_OS_DBG_TYPE_ERROR;
static DAT_OS_DBG_DEST 		g_dbg_dest = DAT_OS_DBG_DEST_STDOUT;


/***********************************************************************
 * Function: dat_os_dbg_set_level
 ***********************************************************************/

void
dat_os_dbg_init ( void )
{
    char *dbg_type;
    char *dbg_dest;

    dbg_type = dat_os_getenv (DAT_DBG_LEVEL_ENV);
    if ( dbg_type != NULL )
    {
        g_dbg_type = dat_os_strtol(dbg_type, NULL, 0);
    }

    dbg_dest = dat_os_getenv (DAT_DBG_DEST_ENV);
    if ( dbg_dest != NULL )
    {
        g_dbg_dest = dat_os_strtol(dbg_dest, NULL, 0);
    }
}


/***********************************************************************
 * Function: dat_os_dbg_print
 ***********************************************************************/

void 
dat_os_dbg_print (  
    DAT_OS_DBG_TYPE_VAL		type, 
    const char *		fmt, 
    ...)
{
    if ( (DAT_OS_DBG_TYPE_ERROR == type) || (type & g_dbg_type) )
    {
        va_list args;
                
        if ( DAT_OS_DBG_DEST_STDOUT & g_dbg_dest )
        {
            va_start(args, fmt);
            vfprintf(stdout, fmt, args);
        fflush(stdout);
            va_end(args);
        }
	/* no syslog() susport in Windows */
    }
}

HANDLE heap;

BOOL APIENTRY
DllMain(
	IN				HINSTANCE					h_module,
	IN				DWORD						ul_reason_for_call, 
	IN				LPVOID						lp_reserved )
{
	extern DAT_BOOLEAN udat_check_state ( void );

	UNREFERENCED_PARAMETER( lp_reserved );

	switch( ul_reason_for_call )
	{
	case DLL_PROCESS_ATTACH:
		heap = HeapCreate(0, 0, 0);
		if (heap == NULL)
			return FALSE;
		DisableThreadLibraryCalls( h_module );
		udat_check_state();
		break;

	case DLL_PROCESS_DETACH:
		dat_fini();
		HeapDestroy(heap);
	}

	return TRUE;
}

char *
dat_os_library_error(void)
{
    DWORD rc;
    LPVOID lpMsgBuf;

    if (errno == 0)
    	return NULL;

    // consider formatmessage()?
    rc = GetLastError();

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | 
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        rc,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) &lpMsgBuf,
        0, NULL );

    //LocalFree(lpMsgBuf); error condition - will exit anyway.

    return (char*)lpMsgBuf;
}

#ifndef INLINE_LIB_LOAD

DAT_RETURN
dat_os_library_load ( const char              *library_path,
                      DAT_OS_LIBRARY_HANDLE   *library_handle_ptr )
{
    DAT_OS_LIBRARY_HANDLE library_handle;
    DAT_RETURN rc = DAT_SUCCESS;

    if ( NULL != (library_handle = LoadLibrary(library_path)) )
    {
        if ( NULL != library_handle_ptr ) 
        { 
            *library_handle_ptr = library_handle; 
        }
    }
    else
    { 
	dat_os_dbg_print(DAT_OS_DBG_TYPE_ERROR,
                         "DAT: library %s  load failure\n",library_path);
	rc = DAT_INTERNAL_ERROR;
    }
    return rc;
}
#endif
