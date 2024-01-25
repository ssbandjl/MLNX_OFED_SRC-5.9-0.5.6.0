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
 * HEADER: dat_osd.h
 *
 * PURPOSE: Operating System Dependent layer
 * Description:
 *	Provide OS dependent data structures & functions with
 *	a canonical DAPL interface. Designed to be portable
 *	and hide OS specific quirks of common functions.
 *
 * $Id: dat_osd.h 33 2005-07-11 19:51:17Z ftillier $
 **********************************************************************/

#ifndef _DAT_OSD_H_
#define _DAT_OSD_H_

/*
 * This file is defined for Windows systems only, including it on any
 * other build will cause an error
 */
#if !defined(WIN32) && !defined(WIN64)
#error "UNDEFINED OS TYPE"
#endif /* WIN32/64 */

#include <dat2/udat.h>
#include <dat2/dat_registry.h>

#include <windows.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <_errno.h>

#ifndef STATIC
#define STATIC static
#endif /* STATIC */

#ifndef INLINE
#define INLINE __inline
#endif /* INLINE */

#ifndef __inline__
#define __inline__ __inline
#endif /* __inline */

/*********************************************************************
 *                                                                   *
 * Debuging                                                          *
 *                                                                   *
 *********************************************************************/

#define dat_os_assert(expr)	assert(expr)

typedef int 			DAT_OS_DBG_TYPE_VAL;

typedef enum
{
    DAT_OS_DBG_TYPE_ERROR 		= 0x1,
    DAT_OS_DBG_TYPE_GENERIC 		= 0x2,
    DAT_OS_DBG_TYPE_SR  		= 0x4,
    DAT_OS_DBG_TYPE_DR  		= 0x8,
    DAT_OS_DBG_TYPE_PROVIDER_API 	= 0x10,
    DAT_OS_DBG_TYPE_CONSUMER_API 	= 0x20,
    DAT_OS_DBG_TYPE_ALL 		= 0xff
} DAT_OS_DBG_TYPE_TYPE;

extern void
dat_os_dbg_init ( void );

extern void 
dat_os_dbg_print (  
    DAT_OS_DBG_TYPE_VAL		type, 
    const char *		fmt, 
    ...);


/*********************************************************************
 *                                                                   *
 * Utility Functions                                                 *
 *                                                                   *
 *********************************************************************/

#define DAT_ERROR(Type,SubType) ((DAT_RETURN)(DAT_CLASS_ERROR | Type | SubType))

typedef size_t 			DAT_OS_SIZE;
typedef HMODULE 		DAT_OS_LIBRARY_HANDLE;

#ifdef INLINE_LIB_LOAD

STATIC INLINE DAT_RETURN
dat_os_library_load (
    const char 			*library_path,
    DAT_OS_LIBRARY_HANDLE 	*library_handle_ptr)
{
    DAT_OS_LIBRARY_HANDLE 	library_handle;

    if ( NULL != (library_handle = LoadLibrary(library_path)) )
    {
        if ( NULL != library_handle_ptr ) 
        { 
            *library_handle_ptr = library_handle; 
        }
        return DAT_SUCCESS;
    }
    else
    { 
	dat_os_dbg_print(DAT_OS_DBG_TYPE_ERROR,
                         "DAT: library load failure\n");
	return DAT_INTERNAL_ERROR;
    }
}
#else

DAT_RETURN
dat_os_library_load (
    const char 			*library_path,
    DAT_OS_LIBRARY_HANDLE 	*library_handle_ptr);

#endif

extern char *dat_os_library_error(void);

#ifdef WIN32_LEAN_AND_MEAN
#define dat_os_library_sym		GetProcAddress
#else
STATIC INLINE
dat_os_library_sym (
    DAT_OS_LIBRARY_HANDLE library_handle,
    const char *sym)
{
    return GetProcAddress(library_handle, (LPCSTR)sym);
}
#endif /* WIN32_LEAN_AND_MEAN */

STATIC INLINE DAT_RETURN
dat_os_library_unload (
    const DAT_OS_LIBRARY_HANDLE library_handle)
{
    if ( 0 == FreeLibrary(library_handle) )
    {
	return DAT_INTERNAL_ERROR;
    }
    else 
    {
	return DAT_SUCCESS;
    }
}

STATIC INLINE char *
dat_os_getenv (
    const char *name)
{
    return getenv(name);
}

STATIC INLINE long int
dat_os_strtol (
    const char *nptr, 
    char **endptr, 
    int base)
{
    return strtol(nptr, endptr, base);
}

STATIC INLINE DAT_OS_SIZE
dat_os_strlen (
    const char *s )
{
    return strlen(s);
}

STATIC INLINE int
dat_os_strncmp (
    const char *s1, 
    const char *s2, 
    DAT_OS_SIZE n)
{
    return strncmp(s1, s2, n);
}

STATIC INLINE void * 
dat_os_strncpy (
    char *dest, 
    const char *src, 
    DAT_OS_SIZE len)
{
    return strncpy (dest, src, len);
}

STATIC INLINE DAT_BOOLEAN
dat_os_isblank( 
    int c)
{
    if ( (' ' == c) || ('\t' == c) ) { return DAT_TRUE; }
    else { return DAT_FALSE; }
}

STATIC INLINE DAT_BOOLEAN
dat_os_isdigit( 
    int c)
{
    if ( isdigit(c) ) { return DAT_TRUE; }
    else { return DAT_FALSE; }
}

STATIC INLINE void 
dat_os_usleep( 
    unsigned long usec)
{
    Sleep(usec/1000);
}


/*********************************************************************
 *                                                                   *
 * Memory Functions                                                  *
 *                                                                   *
 *********************************************************************/

extern HANDLE heap;

STATIC INLINE void *
dat_os_alloc (
    int size)
{
	return HeapAlloc(heap, 0, size);
}

STATIC INLINE void 
dat_os_free (
    void *ptr, 
    int size)
{
	UNREFERENCED_PARAMETER(size);
	HeapFree(heap, 0, ptr);
}

STATIC INLINE void * 
dat_os_memset (void *loc, int c, DAT_OS_SIZE size)
{
    return memset (loc, c, size);
}


/*********************************************************************
 *                                                                   *
 * File I/O                                                          *
 *                                                                   *
 *********************************************************************/

typedef FILE 			DAT_OS_FILE;
typedef fpos_t                  DAT_OS_FILE_POS;


STATIC INLINE DAT_OS_FILE *
dat_os_fopen (
    const char * path)
{
    /* always open files in read only mode*/
    return fopen(path, "r");
}

STATIC INLINE DAT_RETURN
dat_os_fgetpos ( 
    DAT_OS_FILE *file, 
    DAT_OS_FILE_POS *pos)
{
    if ( 0 == fgetpos(file, pos) )
    {
	return DAT_SUCCESS;
    }
    else
    {
	return DAT_INTERNAL_ERROR;
    }
}

STATIC INLINE DAT_RETURN
dat_os_fsetpos ( 
    DAT_OS_FILE *file, 
    DAT_OS_FILE_POS *pos)
{
    if ( 0 == fsetpos(file, pos) )
    {
	return DAT_SUCCESS;
    }
    else
    {
	return DAT_INTERNAL_ERROR;
    }
}

/* dat_os_fgetc() returns EOF on error or end of file. */
STATIC INLINE int
dat_os_fgetc ( 
    DAT_OS_FILE *file)
{
    return fgetc(file);
}

/* dat_os_ungetc() returns EOF on error or char 'c'.
 * Push char 'c' back into specified stream for subsequent read.
 */
STATIC INLINE int
dat_os_ungetc ( 
    DAT_OS_FILE *file, int c)
{
    return ungetc(c, file);
}

/* dat_os_fputc() returns EOF on error or char 'c'. */
STATIC INLINE int
dat_os_fputc ( 
    DAT_OS_FILE *file, int c)
{
    return fputc(c, file);
}

/* dat_os_fread returns the number of bytes read from the file. */
STATIC INLINE DAT_OS_SIZE
dat_os_fread (
    DAT_OS_FILE *file,
    char *buf, 
    DAT_OS_SIZE len)
{
    return fread(buf, sizeof(char), len, file);
}

STATIC INLINE DAT_RETURN 
dat_os_fclose (
    DAT_OS_FILE *file)
{
    if ( 0 == fclose(file) )
    {
	return DAT_SUCCESS;
    }
    else
    {
	return DAT_INTERNAL_ERROR;
    }
}


/*********************************************************************
 *                                                                   *
 * Locks                                                             *
 *                                                                   *
 *********************************************************************/

typedef HANDLE            DAT_OS_LOCK;

/* lock functions */
STATIC INLINE DAT_RETURN 
dat_os_lock_init (
    IN	DAT_OS_LOCK *m)
{
  *m = CreateMutex (0, FALSE, 0);
  if (*(HANDLE *)m == NULL)
  {
    return DAT_INTERNAL_ERROR;
  }
  return DAT_SUCCESS;
}

STATIC INLINE DAT_RETURN 
dat_os_lock (
    IN	DAT_OS_LOCK *m)
{
  WaitForSingleObject(*m, INFINITE);

  return DAT_SUCCESS;
}

STATIC INLINE DAT_RETURN 
dat_os_unlock (
    IN	DAT_OS_LOCK *m)
{
  ReleaseMutex (*m);

  return DAT_SUCCESS;
}

STATIC INLINE DAT_RETURN 
dat_os_lock_destroy (
    IN	DAT_OS_LOCK *m)
{
    CloseHandle (*m);

    return DAT_SUCCESS;
}


#endif /*  _DAT_OSD_H_ */

/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 8
 * End:
 */

