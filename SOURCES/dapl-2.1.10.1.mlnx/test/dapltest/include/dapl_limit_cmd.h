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

#ifndef __DAPL_LIMIT_CMD_H__
#define __DAPL_LIMIT_CMD_H__

#include "dapl_proto.h"

typedef enum
{
    LIM_IA,
    LIM_PZ,
#ifndef __KDAPLTEST__
    LIM_CNO,
#endif
    LIM_EVD,
    LIM_EP,
    LIM_RSP,
    LIM_PSP,
    LIM_LMR,
    LIM_RPOST,
    LIM_SIZE_LMR,
    /* add further tests here */

    LIM_NUM_TESTS   /* for array size & limit checks */
} Limit_Index;

//-------------------------------------
#pragma pack (2)
typedef struct
{
    char 		device_name[256];	/* -D */
    DAT_QOS		ReliabilityLevel;	/* -R */
    DAT_UINT32		width;			/* -w */
    DAT_UINT32		debug;			/* -d */
    DAT_UINT32		maximum;		/* -m */
    DAT_UINT32 		Test_List[ LIM_NUM_TESTS ];
    DAT_CONN_QUAL	port;			/* -n */
} Limit_Cmd_t;

#pragma pack ()

#endif
