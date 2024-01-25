/*
 * Copyright (c) 2002, Network Appliance, Inc. All rights reserved. 
 * 
 * This Software is licensed under the terms of the "IBM Common Public
 * License 1.0" a copy of which is in the file LICENSE.txt in the
 * root directory. The license is also available from the Open Source
 * Initiative, see  http://www.opensource.org/licenses/ibmpl.html.
 *
 */

/**********************************************************************
 * 
 * MODULE: dat_osd_sr.h
 *
 * PURPOSE: static registry (SR) platform specific inteface declarations
 *
 * $Id: dat_osd_sr.h 33 2005-07-11 19:51:17Z ftillier $
 **********************************************************************/

#ifndef _DAT_OSD_SR_H_
#define _DAT_OSD_SR_H_


#include "dat_osd.h"


/*********************************************************************
 *                                                                   *
 * Function Declarations                                             *
 *                                                                   *
 *********************************************************************/

/*
 * The static registry exports the same interface regardless of 
 * platform. The particular implementation of dat_sr_load() is 
 * found with other platform dependent sources.
 */

extern DAT_RETURN 
dat_sr_load (void);


#endif /* _DAT_OSD_SR_H_ */
