/*
 * Copyright (c) 2005-2007 Intel Corporation. All rights reserved.  
 * Copyright (c) 2002, Network Appliance, Inc. All rights reserved. 
 * 
 * This Software is licensed under the terms of the "Common Public
 * License" a copy of which is in the file LICENSE.txt in the root
 * directory. The license is also available from the Open Source
 * Initiative, see http://www.opensource.org/licenses/cpl.php.
 *
 */

/**********************************************************************
 * 
 * MODULE: dapl_ibal_util.c
 *
 * PURPOSE: Utility routines for access to IBAL APIs
 *
 * $Id: dapl_ibal_util.c 33 2005-07-11 19:51:17Z ftillier $
 *
 **********************************************************************/

#include "dapl.h"
#include "dapl_adapter_util.h"
#include "dapl_evd_util.h"
#include "dapl_cr_util.h"
#include "dapl_lmr_util.h"
#include "dapl_rmr_util.h"
#include "dapl_cookie.h"
#include "dapl_ring_buffer_util.h"

#ifdef DAT_EXTENSIONS
#include <dat2\dat_ib_extensions.h>
#endif

#ifndef NO_NAME_SERVICE
#include "dapl_name_service.h"
#endif /* NO_NAME_SERVICE */

#include "dapl_ibal_name_service.h"

#define DAPL_IBAL_MAX_CA 4
#define DAT_ADAPTER_NAME "InfiniHost (Tavor)"
#define DAT_VENDOR_NAME  "Mellanox Technolgy Inc."

/*
 *  Root data structure for DAPL_IIBA.
 */
dapl_ibal_root_t        dapl_ibal_root;
DAPL_HCA_NAME           dapl_ibal_hca_name_array [DAPL_IBAL_MAX_CA] = 
                            {"IbalHca0", "IbalHca1", "IbalHca2", "IbalHca3"};
ib_net64_t              *gp_ibal_ca_guid_tbl = NULL;

/*
 * DAT spec does not tie max_mtu_size with IB MTU
 *
static ib_net32_t dapl_ibal_mtu_table[6] = {0, 256, 512, 1024, 2048, 4096};
 */
    
int g_loopback_connection = 0;


static cl_status_t
dapli_init_root_ca_list(
    IN    dapl_ibal_root_t *root )
{
    cl_status_t status;

    cl_qlist_init (&root->ca_head);
    status = cl_spinlock_init (&root->ca_lock);

    if (status == CL_SUCCESS)
    {
        /*
         * Get the time ready to go but don't start here
         */
        root->shutdown = FALSE;
        root->initialized = TRUE;
    }
    else
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                       "--> DiIRCL: cl_spinlock_init returned %d\n", status );
        root->initialized = FALSE;
    }
    
    root->h_al = NULL;

    return (status);
}


static cl_status_t
dapli_destroy_root_ca_list(
    IN    dapl_ibal_root_t *root )
{

    root->initialized = FALSE;

    /* 
     * At this point the lock should not be necessary
     */
    if (!cl_is_qlist_empty (&root->ca_head) )
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                       "--> Destroying nonempty ca list (%s)\n", "DiDRCL");
    }
    cl_spinlock_destroy (&root->ca_lock);

    return CL_SUCCESS;
}


static void
dapli_shutdown_port_access(
    IN    dapl_ibal_ca_t    *ca )
{
    dapl_ibal_port_t    *p_port;

    TAKE_LOCK( ca->port_lock );
    {
        while ( ! cl_is_qlist_empty( &ca->port_head ) )
        {
            p_port = (dapl_ibal_port_t *)cl_qlist_remove_head( &ca->port_head );
            RELEASE_LOCK( ca->port_lock );
            {
                REMOVE_REFERENCE( &p_port->refs );
                REMOVE_REFERENCE( &p_port->ca->refs );

                dapl_os_free (p_port, sizeof (dapl_ibal_port_t));
            }
            TAKE_LOCK( ca->port_lock );
        }
    }
    RELEASE_LOCK( ca->port_lock );
}


static void dapli_shutdown_ca_access (void)
{
    dapl_ibal_ca_t  *ca;

    if ( dapl_ibal_root.initialized == FALSE )
    {
        goto destroy_root;
    }

    TAKE_LOCK (dapl_ibal_root.ca_lock);
    {
        while ( ! cl_is_qlist_empty (&dapl_ibal_root.ca_head) )
        {
            ca = (dapl_ibal_ca_t *)
                                 cl_qlist_remove_head (&dapl_ibal_root.ca_head);

            if (ca->p_ca_attr)
            {
                dapl_os_free (ca->p_ca_attr, sizeof (ib_ca_attr_t));
            }


            RELEASE_LOCK (dapl_ibal_root.ca_lock);
            {
                dapli_shutdown_port_access (ca);
                REMOVE_REFERENCE (&ca->refs);
            }
            TAKE_LOCK (dapl_ibal_root.ca_lock);
        }
    }
    RELEASE_LOCK (dapl_ibal_root.ca_lock);

destroy_root:
    /*
     * Destroy the root CA list and list lock
     */
    dapli_destroy_root_ca_list (&dapl_ibal_root);

    /*
     * Signal we're all done and wake any waiter
     */
    dapl_ibal_root.shutdown = FALSE;
}


dapl_ibal_evd_cb_t *
dapli_find_evd_cb_by_context(
    IN    void           *context,
    IN    dapl_ibal_ca_t *ca)
{
    dapl_ibal_evd_cb_t *evd_cb = NULL;

    TAKE_LOCK( ca->evd_cb_lock );

    evd_cb = (dapl_ibal_evd_cb_t *) cl_qlist_head( &ca->evd_cb_head );
    while ( &evd_cb->next != cl_qlist_end( &ca->evd_cb_head ) )
    {
        if ( context == evd_cb->context)
        {
            goto found;
        }

        /*
         *  Try again
         */
        evd_cb = (dapl_ibal_evd_cb_t *) cl_qlist_next( &evd_cb->next );
    }
    /*
     *  No joy
     */
    evd_cb = NULL;

found:

    RELEASE_LOCK( ca->evd_cb_lock );

    return ( evd_cb );
}


static cl_status_t
dapli_init_ca_evd_cb_list(
    IN    dapl_ibal_ca_t    *ca )
{
    cl_status_t    status;

    cl_qlist_init( &ca->evd_cb_head );
    status = cl_spinlock_init( &ca->evd_cb_lock );
    if ( status != CL_SUCCESS )
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR, "--> DiICECL: cl_spinlock_init returned %d\n", status);
    return ( status );
}


static cl_status_t
dapli_init_ca_port_list(
    IN    dapl_ibal_ca_t    *ca )
{
    cl_status_t    status;

    cl_qlist_init( &ca->port_head );
    status = cl_spinlock_init( &ca->port_lock );
    if ( status != CL_SUCCESS )
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                       "--> DiICPL: cl_spinlock_init returned %d\n", status );
    return ( status );
}

dapl_ibal_port_t  *
dapli_ibal_get_port (
    IN   dapl_ibal_ca_t    *p_ca,
    IN   uint8_t           port_num)
{
    cl_list_item_t    *p_active_port = NULL;
    
    TAKE_LOCK (p_ca->port_lock);
    for ( p_active_port = cl_qlist_head( &p_ca->port_head );
          p_active_port != cl_qlist_end ( &p_ca->port_head);
          p_active_port =  cl_qlist_next ( p_active_port ) )
    {
        if (((dapl_ibal_port_t *)p_active_port)->p_attr->port_num == port_num)
            break;	
    }
    RELEASE_LOCK (p_ca->port_lock);

    return (dapl_ibal_port_t *)p_active_port;
}


void
dapli_ibal_ca_async_error_callback( IN ib_async_event_rec_t  *p_err_rec )
{
    dapl_ibal_ca_t	*p_ca = (dapl_ibal_ca_t*)((void *)p_err_rec->context);
    dapl_ibal_evd_cb_t	*evd_cb;
    DAPL_IA		*ia_ptr;
			
    dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                       "--> DiCaAEC: CA error %d for context %p\n", 
                       p_err_rec->code, p_err_rec->context);

    if (p_ca == NULL)
    {
       	dapl_dbg_log (DAPL_DBG_TYPE_ERR, "--> DiCaAEC: invalid p_ca"
                              "(%p)in async event rec\n",p_ca);
    	return;
    }
	
    ia_ptr = (DAPL_IA*)p_ca->ia_ptr;
    if (ia_ptr == NULL)
    {
       	dapl_dbg_log (DAPL_DBG_TYPE_ERR,
                              "--> DiCaAEC: invalid ia_ptr in %p ca \n", p_ca );
	return;
    }

    if (ia_ptr->async_error_evd == NULL)
    {
        dapl_dbg_log (DAPL_DBG_TYPE_ERR,
                      "--> DiCqAEC: can't find async_error_evd on %s HCA\n", 
                      (ia_ptr->header.provider)->device_name );
        return;
    }

    /* find QP error callback using p_ca for context */
    evd_cb = dapli_find_evd_cb_by_context (ia_ptr->async_error_evd, p_ca);
    if ((evd_cb == NULL) || (evd_cb->pfn_async_err_cb == NULL))
    {
    	dapl_dbg_log (DAPL_DBG_TYPE_ERR,
                              "--> DiCaAEC: no ERROR cb on %p found \n", p_ca);
    	return;
    }

    /* maps to dapl_evd_un_async_error_callback(), context is async_evd */
    evd_cb->pfn_async_err_cb( (ib_hca_handle_t)p_ca, 
                              (ib_error_record_t*)&p_err_rec->code, 
                              ia_ptr->async_error_evd );

}


static dapl_ibal_port_t *
dapli_alloc_port(
    IN    dapl_ibal_ca_t    *ca,
    IN    ib_port_attr_t    *ib_port )
{
    dapl_ibal_port_t    *p_port = NULL;

    if (ca->h_ca == NULL )
    {
    	return NULL;
    }

    /*
     *  Allocate the port structure memory.  This will also deal with the
     *  copying ib_port_attr_t including GID and P_Key tables
     */
    p_port = dapl_os_alloc ( sizeof(dapl_ibal_port_t ) );

    if ( p_port )
    {
        dapl_os_memzero (p_port, sizeof(dapl_ibal_port_t ) );

        /*
         *  We're good to go after initializing reference.
         */
        INIT_REFERENCE( &p_port->refs, 1, p_port, NULL /* pfn_destructor */ );
		
		p_port->p_attr = ib_port;
    }
    return ( p_port );
}

static void
dapli_add_active_port(
    IN dapl_ibal_ca_t   *ca )
{
    dapl_ibal_port_t     *p_port;
    ib_port_attr_t       *p_port_attr;
    ib_ca_attr_t         *p_ca_attr;
    int                  i;

    p_ca_attr = ca->p_ca_attr;

    dapl_os_assert (p_ca_attr != NULL);

    for (i = 0; i < p_ca_attr->num_ports; i++)
    {
        p_port_attr = &p_ca_attr->p_port_attr[i];

        {
            p_port = dapli_alloc_port( ca, p_port_attr );
            if ( p_port )
            {
                TAKE_REFERENCE (&ca->refs);

                /*
                 *  Record / update attribues
                 */
                p_port->p_attr = p_port_attr;

                /*
                 *  Remember the parant CA keeping the reference we took above
                 */
                p_port->ca = ca;

                /*
                 *  We're good to go - Add the new port to the list on the CA
                 */
                LOCK_INSERT_TAIL( ca->port_lock, ca->port_head, p_port->next );
            }
            else
            {
                dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                               "--> %s: Could not allocate dapl_ibal_port_t\n",
                               "DiAAP");
            }
        }
	dapl_dbg_log( DAPL_DBG_TYPE_UTIL,
                      "--> DiAAP: Port %d logical link %s lid = %#x\n",
                      p_port_attr->port_num,
                      ( p_port_attr->link_state != IB_LINK_ACTIVE
                           ?  "DOWN": "UP" ),
                      CL_HTON16(p_port_attr->lid) );

    } /* for loop */
}

static dapl_ibal_ca_t *
dapli_alloc_ca(
    IN    ib_al_handle_t  h_al,
    IN    ib_net64_t      ca_guid)
{
    dapl_ibal_ca_t         *p_ca;
    ib_api_status_t        status;
    uint32_t               attr_size;

    /*
     *  Allocate the CA structure
     */
    p_ca = dapl_os_alloc( sizeof(dapl_ibal_ca_t) );
    dapl_os_memzero (p_ca, sizeof(dapl_ibal_ca_t) );

    if ( p_ca )
    {
        /*
         *  Now we pass dapli_ibal_ca_async_error_callback as the 
         *  async error callback
         */
        status = ib_open_ca( h_al,
                             ca_guid,
                             dapli_ibal_ca_async_error_callback,
                             p_ca,
                             &p_ca->h_ca );
        if ( status != IB_SUCCESS )
        {
            dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                           "--> DiAC: ib_open_ca returned %s\n",
                           ib_get_err_str(status));
            dapl_os_free (p_ca, sizeof (dapl_ibal_ca_t));
            return (NULL);
        }

        /*
         *  Get port list lock and list head initialized
         */
        if (( dapli_init_ca_port_list( p_ca ) != CL_SUCCESS ) ||
            ( dapli_init_ca_evd_cb_list( p_ca ) != CL_SUCCESS ))
        { 
            dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                           "--> %s: dapli_init_ca_port_list returned failed\n",
                           "DiAC");
            goto close_and_free_ca;
        }

        attr_size = 0;
        status = ib_query_ca (p_ca->h_ca, NULL, &attr_size);
        if (status != IB_INSUFFICIENT_MEMORY)
        {
            dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                          "--> DiAC: ib_query_ca returned failed status = %d\n",
                          status);
            goto close_and_free_ca;
        }

        p_ca->p_ca_attr = dapl_os_alloc ((int)attr_size);
        if (p_ca->p_ca_attr == NULL)
        {
            dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                           "--> %s: dapli_alloc_ca failed to alloc memory\n",
                           "DiAC");
            goto close_and_free_ca;
        }

        status = ib_query_ca (
                          p_ca->h_ca,
                          p_ca->p_ca_attr,
                          &attr_size);
        if (status != IB_SUCCESS)
        {
            dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                           "--> ib_query_ca returned failed status = %d\n",
                           status);
            dapl_os_free (p_ca->p_ca_attr, (int)attr_size);
            goto close_and_free_ca;
        }
       
        p_ca->ca_attr_size = attr_size;

        INIT_REFERENCE( &p_ca->refs, 1, p_ca, NULL /* pfn_destructor */ );

        dapli_add_active_port (p_ca);

        /*
         *  We're good to go
         */
        return ( p_ca );
    }
    else
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                       "--> %s: Error allocating CA structure\n","DiAC");
        return ( NULL );
    }

close_and_free_ca:
   /*
    *  Close the CA.
    */
   (void) ib_close_ca ( p_ca->h_ca, NULL /* callback */);
   dapl_os_free (p_ca, sizeof (dapl_ibal_ca_t));

    /*
     *  If we get here, there was an initialization failure
     */
    return ( NULL );
}


static dapl_ibal_ca_t *
dapli_add_ca (
    IN   ib_al_handle_t    h_al,
    IN   ib_net64_t        ca_guid )
{
    dapl_ibal_ca_t     *p_ca;

    /*
     *  Allocate a CA structure
     */
    p_ca = dapli_alloc_ca( h_al, ca_guid );
    if ( p_ca )
    {
        /*
         *  Add the new CA to the list
         */
        LOCK_INSERT_TAIL( dapl_ibal_root.ca_lock, 
                          dapl_ibal_root.ca_head, p_ca->next );
    }
    else
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                       "--> %s: Could not allocate dapl_ibal_ca_t "
                       " for CA guid " F64x "\n","DiAA",ca_guid);
    }

    return ( p_ca );
}


int32_t
dapls_ib_init (void)
{
    ib_api_status_t status;

    /*
     * Initialize the root structure
     */
    if ( dapli_init_root_ca_list (&dapl_ibal_root) == CL_SUCCESS )
    {
        /*
         * Register with the access layer
         */
        status = ib_open_al (&dapl_ibal_root.h_al);

        if (status == IB_SUCCESS)
        {
            intn_t             guid_count;

            status = ib_get_ca_guids ( dapl_ibal_root.h_al,
                                       NULL,
                                       &(size_t)guid_count );
            if (status != IB_INSUFFICIENT_MEMORY)
            {
                dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                               "--> %s: ib_get_ca_guids failed = %d\n",
                               __FUNCTION__,status);
                return -1;
            }

            if (guid_count == 0)
            {
                dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                               "--> %s: found NO HCA in the system\n",
                               __FUNCTION__);
                return -1;
            }

            if (guid_count > DAPL_IBAL_MAX_CA)
            {
                guid_count = DAPL_IBAL_MAX_CA;
            }

            gp_ibal_ca_guid_tbl = (ib_net64_t*)
                                  dapl_os_alloc ( (int)(guid_count * 
                                                  sizeof (ib_net64_t)) );

            if (gp_ibal_ca_guid_tbl == NULL)
            {
                dapl_dbg_log ( DAPL_DBG_TYPE_ERR, "--> %s() can not alloc "
                               "gp_ibal_ca_guid_tbl\n", __FUNCTION__);
                        
                return -1;
            }

            status = ib_get_ca_guids ( dapl_ibal_root.h_al, 
                                       gp_ibal_ca_guid_tbl, 
                                       &(size_t)guid_count );
                            

            if ( status != IB_SUCCESS )
            {
                dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                               "--> %s: ib_get_ca_guids failed '%s'\n", 
                               __FUNCTION__, ib_get_err_str(status) );
                return -1;
            }

            dapl_dbg_log ( DAPL_DBG_TYPE_UTIL, 
                           "--> %s: Success open AL & found %d HCA avail,\n",
                           __FUNCTION__, guid_count);
            return 0;
        }
        else
        {        
            dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                           "--> %s: ib_open_al() failed '%s'\n",
                           __FUNCTION__, ib_get_err_str(status) );
            /*
             * Undo CA list
             */
            dapli_destroy_root_ca_list (&dapl_ibal_root);
        }
    }
    return -1;
}


int32_t dapls_ib_release (void)
{
    dapl_ibal_root.shutdown = TRUE;

    dapli_shutdown_ca_access();

    /*
     * If shutdown not complete, wait for it
     */
    if (dapl_ibal_root.shutdown)
    {
        dapl_dbg_log (DAPL_DBG_TYPE_UTIL, 
                        "--> DsIR: timeout waiting for completion\n");
    }

    if ( dapl_ibal_root.h_al != NULL )
    {
        (void) ib_close_al (dapl_ibal_root.h_al);
	dapl_dbg_log (DAPL_DBG_TYPE_UTIL, "--> DsIR: ib_close_al() returns\n");
        dapl_ibal_root.h_al = NULL;
    }
#ifdef DBG
    dapl_dbg_log (DAPL_DBG_TYPE_UTIL, "--> %s: Exit\n",__FUNCTION__);
#endif

    return 0;
}


/*
 * dapls_ib_enum_hcas
 *
 * Enumerate all HCAs on the system
 *
 * Input:
 * 	none
 *
 * Output:
 *	hca_names	Array of hca names
 *	total_hca_count	
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *
 */
DAT_RETURN
dapls_ib_enum_hcas (
        IN   const char          *vendor,
        OUT  DAPL_HCA_NAME       **hca_names,
        OUT  DAT_COUNT           *total_hca_count )
{
    intn_t             guid_count;
    ib_api_status_t    ib_status;
    UNREFERENCED_PARAMETER(vendor);

    ib_status = ib_get_ca_guids (dapl_ibal_root.h_al, NULL, &(size_t)guid_count);
    if (ib_status != IB_INSUFFICIENT_MEMORY)
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                       "--> DsIEH: ib_get_ca_guids failed '%s'\n",
                       ib_get_err_str(ib_status) );
        return dapl_ib_status_convert (ib_status);
    }

    if (guid_count == 0)
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                       "--> %s: ib_get_ca_guids no HCA in the system\n",
                       "DsIEH");
        return (DAT_PROVIDER_NOT_FOUND);
    }

    if (guid_count > DAPL_IBAL_MAX_CA)
    {
        guid_count = DAPL_IBAL_MAX_CA;
    }

    gp_ibal_ca_guid_tbl = (ib_net64_t *)dapl_os_alloc ((int)(guid_count * sizeof (ib_net64_t)) );

    if (gp_ibal_ca_guid_tbl == NULL)
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                       "--> %s: can not alloc resources @line%d\n", "DsIEH",
                       __LINE__);
        return (DAT_INSUFFICIENT_RESOURCES);
    }

    ib_status = ib_get_ca_guids ( dapl_ibal_root.h_al,
                                  gp_ibal_ca_guid_tbl,
                                  &(size_t)guid_count);

    if (ib_status != IB_SUCCESS)
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                       "--> DsIEH: ib_get_ca_guids failed status = %s\n", 
                       ib_get_err_str(ib_status) );
        return dapl_ib_status_convert (ib_status);
    }

    *hca_names = (DAPL_HCA_NAME*)
                     dapl_os_alloc ((int)(guid_count * sizeof (DAPL_HCA_NAME)));

    if (*hca_names == NULL)
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                       "--> %s: can not alloc resources @line%d\n",
                       "DsIEH", __LINE__);
        return (DAT_INSUFFICIENT_RESOURCES);
    }

    dapl_os_memcpy (*hca_names, 
                    dapl_ibal_hca_name_array, 
                    (int)(guid_count * sizeof (DAPL_HCA_NAME)) );

    *total_hca_count = (DAT_COUNT)guid_count;

    {
        int i;

        for (i = 0; i < guid_count; i++)
            dapl_dbg_log (DAPL_DBG_TYPE_UTIL, "--> DsIEH: %d) hca_names = %s\n",
                          i, dapl_ibal_hca_name_array[i]);
    }

    return (DAT_SUCCESS);
}



IB_HCA_NAME
dapl_ib_convert_name(
    IN  char    *name)
{
    int                i;

    if (gp_ibal_ca_guid_tbl  == NULL)
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                       "--> DICN: found no HCA with name %s\n", name );
        return 0;
    }

    for (i = 0; i < DAPL_IBAL_MAX_CA; i++)
    {
        if (strcmp (name, dapl_ibal_hca_name_array[i]) == 0)
        {
            break;
        }
    }

    if (i >= DAPL_IBAL_MAX_CA)
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                       "--> DICN: can't find any HCA with name %s\n", name);
        return 0;
    }
   
    return (gp_ibal_ca_guid_tbl[i]);
}


/*
 * dapls_ib_open_hca
 *
 * Open HCA
 *
 * Input:
 *      *hca_name         pointer to provider device name
 *      *ib_hca_handle_p  pointer to provide HCA handle
 *
 * Output:
 *      none
 *
 * Return:
 *      DAT_SUCCESS
 *      DAT_INSUFFICIENT_RESOURCES
 *
 */
DAT_RETURN dapls_ib_open_hca ( IN  char         *hca_name,
                               IN  DAPL_HCA     *p_hca,
                               IN  DAPL_OPEN_FLAGS flags)
{
    dapl_ibal_ca_t     *p_ca;
    IB_HCA_NAME        ca_guid;

    dapl_dbg_log (DAPL_DBG_TYPE_UTIL," open_hca: %s - %p\n", hca_name, p_hca);

    if (gp_ibal_ca_guid_tbl  == NULL)
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR, "--> DsIOH: found no HCA with ca_guid"
                       F64x "\n", hca_name);
        return (DAT_PROVIDER_NOT_FOUND);
    }

    ca_guid = dapl_ib_convert_name(hca_name);

    p_ca = dapli_add_ca (dapl_ibal_root.h_al, ca_guid);

    if (p_ca == NULL)
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                     "--> DsIOH: can not create ca for '%s' guid " F64x "\n",
                     hca_name, ca_guid);
        return (DAT_INSUFFICIENT_RESOURCES);
    }

    p_hca->ib_hca_handle = (ib_hca_handle_t) p_ca;
    p_hca->ib_trans.d_hca = p_hca; // back-link

    /* initialize hca wait object for uAT event */
    dapl_os_wait_object_init(&p_hca->ib_trans.wait_object);

#if SOCK_CM
    {
	DAT_RETURN    dat_status;

	dat_status = dapli_init_sock_cm(p_hca);
	if ( dat_status != DAT_SUCCESS )
	{
		dapl_dbg_log (DAPL_DBG_TYPE_ERR,
				" %s() failed to init sock_CM\n", __FUNCTION__);
		return DAT_INTERNAL_ERROR;
	}

	/* initialize cr_list lock */
	dat_status = dapl_os_lock_init(&p_hca->ib_trans.lock);
	if (dat_status != DAT_SUCCESS)
	{
		dapl_dbg_log (DAPL_DBG_TYPE_ERR, " %s() failed to init lock\n",
				__FUNCTION__);
		return DAT_INTERNAL_ERROR;
	}

	/* initialize CM list for listens on this HCA */
	dapl_llist_init_head((DAPL_LLIST_HEAD*)&p_hca->ib_trans.list);
    }
#endif

    return (DAT_SUCCESS);
}


/*
 * dapls_ib_close_hca
 *
 * Open HCA
 *
 * Input:
 *      ib_hca_handle   provide HCA handle
 *
 * Output:
 *      none
 *
 * Return:
 *      DAT_SUCCESS
 *      DAT_INSUFFICIENT_RESOURCES
 *
 */
DAT_RETURN dapls_ib_close_hca ( IN  DAPL_HCA  *p_hca )
{
    dapl_ibal_ca_t     *p_ca;
   
    p_ca =  (dapl_ibal_ca_t *) p_hca->ib_hca_handle;
   
#if SOCK_CM
#endif
    /*
     * Remove it from the list
     */
    TAKE_LOCK (dapl_ibal_root.ca_lock);
    {
        cl_qlist_remove_item (&dapl_ibal_root.ca_head, &p_ca->next);
    }
    RELEASE_LOCK (dapl_ibal_root.ca_lock);

    dapli_shutdown_port_access (p_ca);
 
    /*
     * Remove the constructor reference
     */
    REMOVE_REFERENCE (&p_ca->refs);

    (void) ib_close_ca (p_ca->h_ca, ib_sync_destroy);

    cl_spinlock_destroy (&p_ca->port_lock);
    cl_spinlock_destroy (&p_ca->evd_cb_lock);

    if (p_ca->p_ca_attr)
        dapl_os_free (p_ca->p_ca_attr, sizeof (ib_ca_attr_t));

    p_hca->ib_hca_handle = IB_INVALID_HANDLE;
    dapl_os_free (p_ca, sizeof (dapl_ibal_ca_t));

    return (DAT_SUCCESS);
}



/*
 * dapl_ib_pd_alloc
 *
 * Alloc a PD
 *
 * Input:
 *	ia_handle		IA handle
 *	PZ_ptr			pointer to PZEVD struct
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *
 */
DAT_RETURN
dapls_ib_pd_alloc (
        IN  DAPL_IA                 *ia,
        IN  DAPL_PZ                 *pz)
{
    ib_api_status_t         ib_status;
    dapl_ibal_ca_t          *p_ca;

    p_ca = (dapl_ibal_ca_t *) ia->hca_ptr->ib_hca_handle;

    ib_status = ib_alloc_pd (
                              p_ca->h_ca,
                              IB_PDT_NORMAL,
                              ia,
                              &pz->pd_handle );

    return dapl_ib_status_convert (ib_status);
}


/*
 * dapl_ib_pd_free
 *
 * Free a PD
 *
 * Input:
 *	PZ_ptr			pointer to PZ struct
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *
 */
DAT_RETURN
dapls_ib_pd_free (
        IN  DAPL_PZ                 *pz)
{
    ib_api_status_t                 ib_status;

    ib_status = ib_dealloc_pd (pz->pd_handle, /* destroy_callback */ NULL);

    pz->pd_handle = IB_INVALID_HANDLE;

    return dapl_ib_status_convert (ib_status);
}


/*
 * dapl_ib_mr_register
 *
 * Register a virtual memory region
 *
 * Input:
 *	ia_handle		IA handle
 *	lmr			pointer to dapl_lmr struct
 *	virt_addr		virtual address of beginning of mem region
 *	length			length of memory region
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *
 */
DAT_RETURN
dapls_ib_mr_register (
        IN  DAPL_IA                 *ia,
        IN  DAPL_LMR                *lmr,
        IN  DAT_PVOID                virt_addr,
        IN  DAT_VLEN                length,
        IN  DAT_MEM_PRIV_FLAGS      privileges,
        IN  DAT_VA_TYPE             va_type)
{
    ib_api_status_t     ib_status;
    ib_mr_handle_t      mr_handle;
    ib_mr_create_t      mr_create;
    uint32_t            l_key, r_key; 

    if ( ia == NULL || ia->header.magic != DAPL_MAGIC_IA )
    {
        return DAT_INVALID_HANDLE;
    }

    /* IBAL does not support */
    if (va_type == DAT_VA_TYPE_ZB) {
        dapl_dbg_log(DAPL_DBG_TYPE_ERR,
    	             "--> va_type == DAT_VA_TYPE_ZB: NOT SUPPORTED\n");    
        return DAT_ERROR (DAT_NOT_IMPLEMENTED, DAT_NO_SUBTYPE);  
    }

    mr_create.vaddr         = (void *) virt_addr;
    mr_create.length        = (size_t)length;
    mr_create.access_ctrl   = dapl_lmr_convert_privileges (privileges);
    mr_create.access_ctrl   |= IB_AC_MW_BIND;
   
    if (lmr->param.mem_type == DAT_MEM_TYPE_SHARED_VIRTUAL)
    {
        ib_status = ib_reg_shmid (
                          ((DAPL_PZ *)lmr->param.pz_handle)->pd_handle,
                          (const uint8_t*)lmr->shmid,
                          &mr_create,
                          (uint64_t *)&virt_addr,
                          &l_key,
                          &r_key,
                          &mr_handle);
    }
    else 
    {
        ib_status = ib_reg_mem ( ((DAPL_PZ *)lmr->param.pz_handle)->pd_handle,
                                 &mr_create,
                                 &l_key,
                                 &r_key,
                                 &mr_handle );
    }
    
    if (ib_status != IB_SUCCESS)
    {
        return (dapl_ib_status_convert (ib_status));
    }
    
    /* DAT/DAPL expects context in host order */
    l_key = cl_ntoh32(l_key);
    r_key = cl_ntoh32(r_key);

    dapl_dbg_log (DAPL_DBG_TYPE_UTIL, "--> DsIMR: lmr (%p) lkey = 0x%x "
                  "r_key= %#x mr_handle %p vaddr 0x%LX len 0x%LX\n", 
                  lmr, l_key, r_key, mr_handle, virt_addr, length);

    lmr->param.lmr_context = l_key;
    lmr->param.rmr_context = r_key;
    lmr->param.registered_size = length;
    lmr->param.registered_address = (DAT_VADDR)virt_addr;
    lmr->mr_handle         = mr_handle;

    return (DAT_SUCCESS);
}


/*
 * dapl_ib_mr_deregister
 *
 * Free a memory region
 *
 * Input:
 *	lmr			pointer to dapl_lmr struct
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *
 */
DAT_RETURN
dapls_ib_mr_deregister (
        IN  DAPL_LMR                *lmr)
{
    ib_api_status_t                ib_status;

    ib_status = ib_dereg_mr (lmr->mr_handle);

    if (ib_status != IB_SUCCESS)
    {
        return dapl_ib_status_convert (ib_status);
    }

    lmr->param.lmr_context = 0;
    lmr->mr_handle         = IB_INVALID_HANDLE;

    return (DAT_SUCCESS);
}


/*
 * dapl_ib_mr_register_shared
 *
 * Register a virtual memory region
 *
 * Input:
 *	ia_handle		IA handle
 *	lmr			pointer to dapl_lmr struct
 *	virt_addr		virtual address of beginning of mem region
 *	length			length of memory region
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *
 */
DAT_RETURN
dapls_ib_mr_register_shared (
        IN  DAPL_IA                  *ia,
        IN  DAPL_LMR                 *lmr,
        IN  DAT_MEM_PRIV_FLAGS       privileges,
        IN  DAT_VA_TYPE              va_type )
{
    DAT_VADDR                   virt_addr;
    ib_mr_handle_t              mr_handle;
    ib_api_status_t             ib_status;
    ib_mr_handle_t              new_mr_handle;
    ib_access_t                 access_ctrl;
    uint32_t                    l_key, r_key; 
    ib_mr_create_t      mr_create;
    if ( ia == NULL || ia->header.magic != DAPL_MAGIC_IA )
    {
        return DAT_INVALID_HANDLE;
    }

    /* IBAL does not support?? */
    if (va_type == DAT_VA_TYPE_ZB) {
        dapl_dbg_log(DAPL_DBG_TYPE_ERR,
    	    " va_type == DAT_VA_TYPE_ZB: NOT SUPPORTED\n");    
        return DAT_ERROR (DAT_NOT_IMPLEMENTED, DAT_NO_SUBTYPE);  
    }

    virt_addr = dapl_mr_get_address (lmr->param.region_desc,
                                     lmr->param.mem_type);

    access_ctrl   = dapl_lmr_convert_privileges (privileges);
    access_ctrl  |= IB_AC_MW_BIND;

    mr_create.vaddr         = (void *) virt_addr;
    mr_create.access_ctrl   = access_ctrl;
    mr_handle = (ib_mr_handle_t) lmr->mr_handle;

    dapl_dbg_log (DAPL_DBG_TYPE_UTIL, 
                       "--> DsIMRS: orig mr_handle %p vaddr %p\n", 
                       mr_handle, virt_addr);

    if (lmr->param.mem_type == DAT_MEM_TYPE_SHARED_VIRTUAL)
    {
        ib_status = ib_reg_shmid ( ((DAPL_PZ *)lmr->param.pz_handle)->pd_handle,
                                   (const uint8_t*)lmr->shmid,
                                   &mr_create,
                                   &virt_addr,
                                   &l_key,
                                   &r_key,
                                   &new_mr_handle );
    }
    else
    { 

        ib_status = ib_reg_shared ( mr_handle,
                                   ((DAPL_PZ *)lmr->param.pz_handle)->pd_handle,
                                   access_ctrl,
                                   /* in/out */(DAT_UINT64 *)&virt_addr,
                                   &l_key,
                                   &r_key,
                                   &new_mr_handle );
    }

    if (ib_status != IB_SUCCESS)
    {
        return dapl_ib_status_convert (ib_status);
    }
    /*
     * FIXME - Vu
     *    What if virt_addr as an OUTPUT having the actual virtual address
     *    assigned to the register region
     */

    /* DAT/DAPL expects context to be in host order */
    l_key = cl_ntoh32(l_key);
    r_key = cl_ntoh32(r_key);

    dapl_dbg_log (DAPL_DBG_TYPE_UTIL, "--> DsIMRS: lmr (%p) lkey = 0x%x "
                  "new mr_handle %p vaddr %p\n",
                  lmr, l_key, new_mr_handle, virt_addr);

    lmr->param.lmr_context = l_key;
    lmr->param.rmr_context = r_key;
    lmr->param.registered_address = (DAT_VADDR) (uintptr_t) virt_addr;
    lmr->mr_handle         = new_mr_handle;

    return (DAT_SUCCESS);
}


/*
 * dapls_ib_mw_alloc
 *
 * Bind a protection domain to a memory window
 *
 * Input:
 *	rmr			Initialized rmr to hold binding handles
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *
 */
DAT_RETURN
dapls_ib_mw_alloc ( IN  DAPL_RMR    *rmr )
{
    ib_api_status_t     ib_status;
    uint32_t            r_key;
    ib_mw_handle_t      mw_handle;

    ib_status = ib_create_mw (
                  ((DAPL_PZ *)rmr->param.pz_handle)->pd_handle,
                  &r_key,
                  &mw_handle);

    if (ib_status != IB_SUCCESS)
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                       "--> DsIMA: create MW failed = %s\n",
                       ib_get_err_str(ib_status) );
        return dapl_ib_status_convert (ib_status);
    }

    rmr->mw_handle         = mw_handle;
    rmr->param.rmr_context = (DAT_RMR_CONTEXT) cl_ntoh32(r_key);

    dapl_dbg_log (DAPL_DBG_TYPE_UTIL, 
                       "--> DsIMA: mw_handle %p r_key = 0x%x\n", 
                        mw_handle, rmr->param.rmr_context);

    return (DAT_SUCCESS);
}


/*
 * dapls_ib_mw_free
 *
 * Release bindings of a protection domain to a memory window
 *
 * Input:
 *	rmr			Initialized rmr to hold binding handles
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *
 */
DAT_RETURN
dapls_ib_mw_free (
        IN  DAPL_RMR                         *rmr)
{
    ib_api_status_t         ib_status;

    dapl_dbg_log (DAPL_DBG_TYPE_UTIL, 
                       "--> DsIMF: mw_handle %p\n", rmr->mw_handle);

    ib_status = ib_destroy_mw (rmr->mw_handle);

    if (ib_status != IB_SUCCESS)
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR, "--> DsIMF: Free MW failed = %s\n",
                       ib_get_err_str(ib_status));
        return dapl_ib_status_convert (ib_status);
    }

    rmr->param.rmr_context = 0;
    rmr->mw_handle         = IB_INVALID_HANDLE;

    return (DAT_SUCCESS);
}

/*
 * dapls_ib_mw_bind
 *
 * Bind a protection domain to a memory window
 *
 * Input:
 *	rmr			Initialized rmr to hold binding handles
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *
 */
DAT_RETURN
dapls_ib_mw_bind (
        IN  DAPL_RMR                *rmr,
        IN  DAPL_LMR                *lmr,
        IN  DAPL_EP                 *ep,
        IN  DAPL_COOKIE             *cookie,
        IN  DAT_VADDR               virtual_address,
        IN  DAT_VLEN                length,
        IN  DAT_MEM_PRIV_FLAGS      mem_priv,
        IN  ib_bool_t               is_signaled)
{
    ib_api_status_t       ib_status;
    ib_bind_wr_t          bind_wr_prop;
    uint32_t              new_rkey;
    
    bind_wr_prop.local_ds.vaddr   = virtual_address;
    bind_wr_prop.local_ds.length  = (uint32_t)length;
    bind_wr_prop.local_ds.lkey    = cl_hton32(lmr->param.lmr_context);
    bind_wr_prop.current_rkey     = cl_hton32(rmr->param.rmr_context);
    bind_wr_prop.access_ctrl      = dapl_rmr_convert_privileges (mem_priv);
    bind_wr_prop.send_opt         = (is_signaled == TRUE) ? 
                                    IB_SEND_OPT_SIGNALED : 0;
    bind_wr_prop.wr_id            = (uint64_t) ((uintptr_t) cookie);
    bind_wr_prop.h_mr             = lmr->mr_handle;

    dapl_dbg_log (DAPL_DBG_TYPE_UTIL, "--> DsIMB: mr_handle %p, mw_handle %p "
                  "vaddr %#I64x length %#I64x\n", 
                  lmr->mr_handle, rmr->mw_handle, virtual_address, length);

    ib_status = ib_bind_mw (
                    rmr->mw_handle,
                    ep->qp_handle,
                    &bind_wr_prop,
                    &new_rkey);

    if (ib_status != IB_SUCCESS)
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR, "--> DsIMB: Bind MW failed = %s\n", 
                       ib_get_err_str(ib_status));
        return (dapl_ib_status_convert (ib_status));
    }

    rmr->param.rmr_context      = (DAT_RMR_CONTEXT) cl_ntoh32(new_rkey);

    dapl_dbg_log (DAPL_DBG_TYPE_UTIL,
			"--> DsIMB: new_rkey = 0x%x\n", rmr->param.rmr_context);

    return (DAT_SUCCESS);
}

/*
 * dapls_ib_mw_unbind
 *
 * Unbind a memory window
 *
 * Input:
 *	rmr			Initialized rmr to hold binding handles
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *
 */
DAT_RETURN
dapls_ib_mw_unbind (
	IN  DAPL_RMR		*rmr,
	IN  DAPL_EP		*ep,
	IN  DAPL_COOKIE		*cookie,
	IN  ib_bool_t		is_signaled)
{
    ib_api_status_t       ib_status;
    ib_bind_wr_t          bind_wr_prop;
    uint32_t              new_rkey;
    
    bind_wr_prop.local_ds.vaddr   = 0;
    bind_wr_prop.local_ds.length  = 0;
    bind_wr_prop.local_ds.lkey    = 0;
    bind_wr_prop.access_ctrl      = 0;
    bind_wr_prop.send_opt         = (is_signaled == TRUE) ? 
                                    IB_SEND_OPT_SIGNALED : 0;
    bind_wr_prop.wr_id            = (uint64_t) ((uintptr_t) cookie);

    dapl_dbg_log (DAPL_DBG_TYPE_UTIL, 
                       "--> DsIMU: mw_handle = %p\n", rmr->mw_handle);

    ib_status = ib_bind_mw (
                    rmr->mw_handle,
                    ep->qp_handle,
                    &bind_wr_prop,
                    &new_rkey);

    if (ib_status != IB_SUCCESS)
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR, "--> DsIMU: Unbind MW failed = %s\n", 
                ib_get_err_str(ib_status));
        return (dapl_ib_status_convert (ib_status));
    }

    rmr->param.rmr_context      = (DAT_RMR_CONTEXT) cl_ntoh32(new_rkey);

    dapl_dbg_log (DAPL_DBG_TYPE_UTIL, 
                  "--> DsIMU: unbind new_rkey 0x%x\n", rmr->param.rmr_context);

    return (DAT_SUCCESS);
}


/*
 * dapls_ib_setup_async_callback
 *
 * Set up an asynchronous callbacks of various kinds
 *
 * Input:
 *	ia_handle		IA handle
 *	handler_type		type of handler to set up
 *	callback_handle		handle param for completion callbacks
 *	callback		callback routine pointer
 *	context			argument for callback routine
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *	DAT_INVALID_PARAMETER
 *
 */
DAT_RETURN
dapls_ib_setup_async_callback (
        IN  DAPL_IA                     *ia_ptr,
        IN  DAPL_ASYNC_HANDLER_TYPE     handler_type,
        IN  DAPL_EVD                    *evd_ptr,
        IN  ib_async_handler_t          callback,
        IN  void                        *context )
{
    dapl_ibal_ca_t     *p_ca;
    dapl_ibal_evd_cb_t *evd_cb;

    dapl_dbg_log (DAPL_DBG_TYPE_UTIL,
                  " setup_async_cb: ia %p type %d hdl %p cb %p ctx %p\n",
                  ia_ptr, handler_type, evd_ptr, callback, context);

    p_ca = (dapl_ibal_ca_t *) ia_ptr->hca_ptr->ib_hca_handle;

    if (p_ca == NULL)
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR, "--> DsISAC: can't find %s HCA\n", 
                       (ia_ptr->header.provider)->device_name);
        return (DAT_INVALID_HANDLE);
    }
   
    if (handler_type != DAPL_ASYNC_CQ_COMPLETION)
    {
        evd_cb = dapli_find_evd_cb_by_context (context, p_ca);
           
        if (evd_cb == NULL)
        {
            /* 
             * No record for this evd. We allocate one
             */
            evd_cb = dapl_os_alloc (sizeof (dapl_ibal_evd_cb_t));
            dapl_os_memzero (evd_cb, sizeof(dapl_ibal_evd_cb_t));

            if (evd_cb == NULL)
            {
                dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                               "--> %s: can't alloc res\n","DsISAC"); 
                return (DAT_INSUFFICIENT_RESOURCES);
            }
        
            evd_cb->context          = context;
        
            /*
             *  Add the new EVD CB to the list
             */
            LOCK_INSERT_TAIL( p_ca->evd_cb_lock, 
                              p_ca->evd_cb_head,
                              evd_cb->next );
        }

        switch (handler_type)
        {
            case DAPL_ASYNC_UNAFILIATED:
                evd_cb->pfn_async_err_cb = callback;
                break;
            case DAPL_ASYNC_CQ_ERROR:
                evd_cb->pfn_async_cq_err_cb = callback;
                break;
            case DAPL_ASYNC_QP_ERROR:
                evd_cb->pfn_async_qp_err_cb = callback;
                break;
            default:
                break;
        }

    }

    return DAT_SUCCESS;
}


/*
 * dapls_ib_query_gid
 *
 * Query the hca for the gid of the 1st active port.
 *
 * Input:
 *	hca_handl		hca handle	
 *	ep_attr			attribute of the ep
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INVALID_HANDLE
 *	DAT_INVALID_PARAMETER
 */

DAT_RETURN
dapls_ib_query_gid( IN  DAPL_HCA	*hca_ptr,
		    IN  GID		*gid )
{
    dapl_ibal_ca_t    *p_ca;
    ib_ca_attr_t      *p_hca_attr;
    ib_api_status_t   ib_status;
    ib_hca_port_t     port_num;

    p_ca = (dapl_ibal_ca_t *) hca_ptr->ib_hca_handle;

    if (p_ca == NULL)
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
			"%s() invalid hca_ptr %p", __FUNCTION__, hca_ptr);
        return DAT_INVALID_HANDLE;
    }

    ib_status = ib_query_ca (
                          p_ca->h_ca,
                          p_ca->p_ca_attr,
                          &p_ca->ca_attr_size);
    if (ib_status != IB_SUCCESS)
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                       "%s() ib_query_ca returned failed status = %s\n", 
                       ib_get_err_str(ib_status));
        return dapl_ib_status_convert (ib_status);
    }

    p_hca_attr = p_ca->p_ca_attr;
    port_num = hca_ptr->port_num - 1;

    gid->gid_prefix = p_hca_attr->p_port_attr[port_num].p_gid_table->unicast.prefix;
    gid->guid = p_hca_attr->p_port_attr[port_num].p_gid_table->unicast.interface_id;
    return DAT_SUCCESS;
}


/*
 * dapls_ib_query_hca
 *
 * Query the hca attribute
 *
 * Input:
 *	hca_handl		hca handle	
 *	ep_attr			attribute of the ep
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INVALID_PARAMETER
 */

DAT_RETURN dapls_ib_query_hca (
	IN  DAPL_HCA                       *hca_ptr,
        OUT DAT_IA_ATTR                    *ia_attr,
        OUT DAT_EP_ATTR                    *ep_attr,
	OUT DAT_SOCK_ADDR6                 *ip_addr)
{
    ib_ca_attr_t      *p_hca_attr;
    dapl_ibal_ca_t    *p_ca;
    ib_api_status_t   ib_status;
    ib_hca_port_t     port_num;
    GID gid;
    DAT_SOCK_ADDR6	 *p_sock_addr;
    DAT_RETURN dat_status = DAT_SUCCESS;
    port_num = hca_ptr->port_num;

    p_ca = (dapl_ibal_ca_t *) hca_ptr->ib_hca_handle;

    if (p_ca == NULL)
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,  "--> %s: invalid handle %p",
                       "DsIQH", hca_ptr);
        return (DAT_INVALID_HANDLE);
    }

    ib_status = ib_query_ca (
                          p_ca->h_ca,
                          p_ca->p_ca_attr,
                          &p_ca->ca_attr_size);
    if (ib_status != IB_SUCCESS)
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                       "--> DsIQH: ib_query_ca returned failed status = %s\n", 
                       ib_get_err_str(ib_status));
        return (dapl_ib_status_convert (ib_status));
    }

    p_hca_attr = p_ca->p_ca_attr;

    if (ip_addr != NULL)
    {
    	p_sock_addr = dapl_os_alloc(sizeof(DAT_SOCK_ADDR6));
    	if ( !p_sock_addr )
    	{
    		dat_status = DAT_INSUFFICIENT_RESOURCES;
    		dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                                       " Query Hca alloc Err: status %d\n",
                                       dat_status);
    		return dat_status;
    	}
    	dapl_os_memzero(p_sock_addr, sizeof(DAT_SOCK_ADDR6));

    	gid.gid_prefix = p_hca_attr->p_port_attr[port_num-1].p_gid_table->unicast.prefix;
    	gid.guid = p_hca_attr->p_port_attr[port_num-1].p_gid_table->unicast.interface_id;
	
    	dat_status = dapls_ns_map_ipaddr( hca_ptr,
                                          gid,
                                          (DAT_IA_ADDRESS_PTR)p_sock_addr);
	
    	if ( dat_status != DAT_SUCCESS )
    	{
            dapl_dbg_log (DAPL_DBG_TYPE_ERR,
                          " SA Query for local IP failed= %d\n", dat_status );
			/* what to do next ? */
    	}
    	else
    	{
    	    dapl_dbg_log (DAPL_DBG_TYPE_CM, "SA query GID for IP: ");
            dapl_dbg_log ( DAPL_DBG_TYPE_CM, "%0d:%d:%d:%d\n", 
		(uint8_t)((DAT_IA_ADDRESS_PTR )p_sock_addr)->sa_data[2]&0xff,
		(uint8_t)((DAT_IA_ADDRESS_PTR )p_sock_addr)->sa_data[3]&0xff,
		(uint8_t)((DAT_IA_ADDRESS_PTR )p_sock_addr)->sa_data[4]&0xff,
		(uint8_t)((DAT_IA_ADDRESS_PTR )p_sock_addr)->sa_data[5]&0xff);
        }

        hca_ptr->hca_address = *p_sock_addr;

        /* if structure address not from our hca_ptr */
        if ( ip_addr  != &hca_ptr->hca_address )
        {
            *ip_addr = *p_sock_addr;
        }

	dapl_os_free (p_sock_addr, sizeof(DAT_SOCK_ADDR6));

    } /* ip_addr != NULL */

    if ( ia_attr != NULL )
    {
        dapl_os_memzero( ia_attr->adapter_name,
                         (int)sizeof(ia_attr->adapter_name ));
        dapl_os_memcpy(ia_attr->adapter_name,
                        DAT_ADAPTER_NAME, 
                        min ( (int)dapl_os_strlen(DAT_ADAPTER_NAME),
                              (int)(DAT_NAME_MAX_LENGTH)-1 ) );

        dapl_os_memzero ( ia_attr->vendor_name,
                          (int)sizeof(ia_attr->vendor_name) );
        dapl_os_memcpy ( ia_attr->vendor_name, 
                         DAT_VENDOR_NAME,
                        min ( (int)dapl_os_strlen(DAT_VENDOR_NAME),
                              (int)(DAT_NAME_MAX_LENGTH)-1 ) );
        
        /* FIXME : Vu
         *         this value should be revisited
         *         It can be set by DAT consumers
         */
        ia_attr->ia_address_ptr           = (DAT_PVOID)&hca_ptr->hca_address;
        ia_attr->hardware_version_major   = p_hca_attr->dev_id;
        ia_attr->hardware_version_minor   = p_hca_attr->revision;
        ia_attr->max_eps                  = p_hca_attr->max_qps;
        ia_attr->max_dto_per_ep           = p_hca_attr->max_wrs;
        ia_attr->max_rdma_read_per_ep     = p_hca_attr->max_qp_resp_res;
        ia_attr->max_evds                 = p_hca_attr->max_cqs;
        ia_attr->max_evd_qlen             = p_hca_attr->max_cqes;
        ia_attr->max_iov_segments_per_dto = p_hca_attr->max_sges;
        ia_attr->max_lmrs                 = p_hca_attr->init_regions;
        ia_attr->max_lmr_block_size       = p_hca_attr->init_region_size;
        ia_attr->max_rmrs                 = p_hca_attr->init_windows;
        ia_attr->max_lmr_virtual_address  = p_hca_attr->max_addr_handles;
        ia_attr->max_rmr_target_address   = p_hca_attr->max_addr_handles;
        ia_attr->max_pzs                  = p_hca_attr->max_pds;
        /*
         * DAT spec does not tie max_mtu_size with IB MTU
         *
        ia_attr->max_mtu_size             = 
                        dapl_ibal_mtu_table[p_hca_attr->p_port_attr->mtu];
        */
        ia_attr->max_mtu_size             = 
                        p_hca_attr->p_port_attr->max_msg_size;
        ia_attr->max_rdma_size            = 
                        p_hca_attr->p_port_attr->max_msg_size;
        ia_attr->num_transport_attr       = 0;
        ia_attr->transport_attr           = NULL;
        ia_attr->num_vendor_attr          = 0;
        ia_attr->vendor_attr              = NULL;
        ia_attr->max_iov_segments_per_rdma_read = p_hca_attr->max_sges;

#ifdef DAT_EXTENSIONS
        ia_attr->extension_supported = DAT_EXTENSION_IB;
        ia_attr->extension_version = DAT_IB_EXTENSION_VERSION;
#endif
	
	dapl_dbg_log(DAPL_DBG_TYPE_UTIL, 
		" --> DsIMU_qHCA: (ver=%x) ep %d ep_q %d evd %d evd_q %d\n", 
			ia_attr->hardware_version_major,
			ia_attr->max_eps, ia_attr->max_dto_per_ep,
			ia_attr->max_evds, ia_attr->max_evd_qlen );
	dapl_dbg_log(DAPL_DBG_TYPE_UTIL, 
		" --> DsIMU_qHCA: mtu %llu rdma %llu iov %d lmr %d rmr %d"
		" rdma_io %d\n", 
			ia_attr->max_mtu_size, ia_attr->max_rdma_size,
			ia_attr->max_iov_segments_per_dto, ia_attr->max_lmrs, 
			ia_attr->max_rmrs, ia_attr->max_rdma_read_per_ep );
    }

    if ( ep_attr != NULL )
    {
       (void) dapl_os_memzero(ep_attr, sizeof(*ep_attr)); 
        /*
         * DAT spec does not tie max_mtu_size with IB MTU
         *
        ep_attr->max_mtu_size     = 
                        dapl_ibal_mtu_table[p_hca_attr->p_port_attr->mtu];
         */
        ep_attr->max_mtu_size     = p_hca_attr->p_port_attr->max_msg_size;
        ep_attr->max_rdma_size    = p_hca_attr->p_port_attr->max_msg_size;
        ep_attr->max_recv_dtos    = p_hca_attr->max_wrs;
        ep_attr->max_request_dtos = p_hca_attr->max_wrs;
        ep_attr->max_recv_iov     = p_hca_attr->max_sges;
        ep_attr->max_request_iov  = p_hca_attr->max_sges;
        ep_attr->max_rdma_read_in = p_hca_attr->max_qp_resp_res;
        ep_attr->max_rdma_read_out= p_hca_attr->max_qp_resp_res;
	
	dapl_dbg_log(DAPL_DBG_TYPE_UTIL, 
		" --> DsIMU_qHCA: msg %llu dto %d iov %d rdma i%d,o%d\n", 
			ep_attr->max_mtu_size,
			ep_attr->max_recv_dtos, ep_attr->max_recv_iov,
			ep_attr->max_rdma_read_in, ep_attr->max_rdma_read_out);
    }
	return DAT_SUCCESS;
}


DAT_RETURN
dapls_ib_completion_poll ( IN DAPL_HCA                *p_hca,
                           IN DAPL_EVD                *p_evd,
                           IN ib_work_completion_t   *cqe_ptr )
{
    ib_api_status_t        ib_status;
    ib_work_completion_t   *cqe_filled;

    /*
     * FIXME - Vu
     *     Now we only poll for one cqe. We can poll for more than
     *     one completions later for better. However, this requires
     *     to change the logic in dapl_evd_dto_callback function
     *     to process more than one completion.
     */
    cqe_ptr->p_next = NULL;
    cqe_filled      = NULL;

    if  ( !p_hca->ib_hca_handle )
    {
        return DAT_INVALID_HANDLE;
    }

    ib_status = ib_poll_cq (p_evd->ib_cq_handle, &cqe_ptr, &cqe_filled);

    if ( ib_status == IB_INVALID_CQ_HANDLE )
    {
        ib_status = IB_NOT_FOUND;
    }

    return dapl_ib_status_convert (ib_status);
}


DAT_RETURN
dapls_ib_completion_notify ( IN ib_hca_handle_t         hca_handle,
                             IN DAPL_EVD                *p_evd,
                             IN ib_notification_type_t  type )
{
    ib_api_status_t        ib_status;
    DAT_BOOLEAN            solic_notify;

    if  ( !hca_handle )
    {
        return DAT_INVALID_HANDLE;
    }
    solic_notify = (type == IB_NOTIFY_ON_SOLIC_COMP) ? DAT_TRUE : DAT_FALSE; 
    ib_status = ib_rearm_cq ( p_evd->ib_cq_handle, solic_notify );

    return dapl_ib_status_convert (ib_status);
}

DAT_RETURN
dapls_evd_dto_wakeup (
	IN DAPL_EVD			*evd_ptr)
{
	return dapl_os_wait_object_wakeup(&evd_ptr->wait_object);
}

DAT_RETURN
dapls_evd_dto_wait (
	IN DAPL_EVD			*evd_ptr,
	IN uint32_t 			timeout)
{
	return dapl_os_wait_object_wait(&evd_ptr->wait_object, timeout);
}

/*
 * dapls_ib_get_async_event
 *
 * Translate an asynchronous event type to the DAT event.
 * Note that different providers have different sets of errors.
 *
 * Input:
 *	cause_ptr		provider event cause
 *
 * Output:
 * 	async_event		DAT mapping of error
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_NOT_IMPLEMENTED	Caller is not interested this event
 */

DAT_RETURN dapls_ib_get_async_event(
	IN  ib_async_event_rec_t	*cause_ptr,
	OUT DAT_EVENT_NUMBER		*async_event)
{
    ib_async_event_t		event_id;
    DAT_RETURN			dat_status;

    dat_status = DAT_SUCCESS;
    event_id = cause_ptr->code;

    dapl_dbg_log (DAPL_DBG_TYPE_WARN, "--> DsAE: event_id = %d%d\n", event_id);

    switch (event_id )
    {
        case IB_AE_SQ_ERROR:
        case IB_AE_SQ_DRAINED:
        case IB_AE_RQ_ERROR:
	{
	    *async_event = DAT_ASYNC_ERROR_EP_BROKEN;
	    break;
	}

	/* INTERNAL errors */
        case IB_AE_QP_FATAL:
	case IB_AE_CQ_ERROR:
	case IB_AE_LOCAL_FATAL:
	case IB_AE_WQ_REQ_ERROR:
	case IB_AE_WQ_ACCESS_ERROR:
	{
	    *async_event = DAT_ASYNC_ERROR_PROVIDER_INTERNAL_ERROR;
	    break;
	}

	/* CATASTROPHIC errors */
	case IB_AE_FLOW_CTRL_ERROR:
	case IB_AE_BUF_OVERRUN:
	{
	    *async_event = DAT_ASYNC_ERROR_IA_CATASTROPHIC;
	    break;
	}

	default:
	{
	    /*
	     * Errors we are not interested in reporting:
	     * IB_AE_QP_APM
	     * IB_AE_PKEY_TRAP
	     * IB_AE_QKEY_TRAP
	     * IB_AE_MKEY_TRAP
	     * IB_AE_PORT_TRAP
	     * IB_AE_QP_APM_ERROR
	     * IB_AE_PORT_ACTIVE
	     * ...
	     */
	    dat_status = DAT_NOT_IMPLEMENTED;
	}

    }
  
    return dat_status;
}

/*
 * dapls_ib_get_dto_status
 *
 * Return the DAT status of a DTO operation
 *
 * Input:
 *	cqe_ptr			pointer to completion queue entry
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	Value from ib_status_map table above
 */

DAT_DTO_COMPLETION_STATUS
dapls_ib_get_dto_status(
	IN ib_work_completion_t		*cqe_ptr)
{
    ib_uint32_t    ib_status;

    ib_status = DAPL_GET_CQE_STATUS (cqe_ptr);

    switch (ib_status)
    {
    case IB_COMP_ST_SUCCESS :
	return	DAT_DTO_SUCCESS;

    case IB_COMP_ST_LOCAL_LEN_ERR:
	return DAT_DTO_ERR_LOCAL_LENGTH;

    case IB_COMP_ST_LOCAL_OP_ERR:
	return DAT_DTO_ERR_LOCAL_EP;

    case IB_COMP_ST_LOCAL_PROTECT_ERR:
	return DAT_DTO_ERR_LOCAL_PROTECTION;

    case IB_COMP_ST_WR_FLUSHED_ERR:	
	return DAT_DTO_ERR_FLUSHED;

    case IB_COMP_ST_MW_BIND_ERR:
	return DAT_RMR_OPERATION_FAILED;

    case IB_COMP_ST_REM_ACC_ERR:
	return DAT_DTO_ERR_REMOTE_ACCESS;

    case IB_COMP_ST_REM_OP_ERR:
	return DAT_DTO_ERR_REMOTE_RESPONDER;

    case IB_COMP_ST_RNR_COUNTER:
	return DAT_DTO_ERR_RECEIVER_NOT_READY;

    case IB_COMP_ST_TRANSP_COUNTER:
	return DAT_DTO_ERR_TRANSPORT;

    case IB_COMP_ST_REM_REQ_ERR:
	return DAT_DTO_ERR_REMOTE_RESPONDER;

    case IB_COMP_ST_BAD_RESPONSE_ERR:
	return DAT_DTO_ERR_BAD_RESPONSE;

    case IB_COMP_ST_EE_STATE_ERR:
    case IB_COMP_ST_EE_CTX_NO_ERR:
    	return DAT_DTO_ERR_TRANSPORT;

    default:
#ifdef DAPL_DBG
    dapl_dbg_log (DAPL_DBG_TYPE_ERR,"%s() unknown IB_COMP_ST %d(0x%x)\n",
                  __FUNCTION__,ib_status,ib_status);
#endif
	return DAT_DTO_FAILURE;
    }
}


/*
 * Map all IBAPI DTO completion codes to the DAT equivelent.
 *
 * dapls_ib_get_dat_event
 *
 * Return a DAT connection event given a provider CM event.
 *
 * N.B.	Some architectures combine async and CM events into a
 *	generic async event. In that case, dapls_ib_get_dat_event()
 *	and dapls_ib_get_async_event() should be entry points that
 *	call into a common routine.
 *
 * Input:
 *	ib_cm_event	event provided to the dapl callback routine
 *	active		switch indicating active or passive connection
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_EVENT_NUMBER of translated provider value
 */

DAT_EVENT_NUMBER
dapls_ib_get_dat_event (
	IN    const ib_cm_events_t	ib_cm_event,
	IN    DAT_BOOLEAN		active)
{
    DAT_EVENT_NUMBER		dat_event_num = 0;
    UNREFERENCED_PARAMETER (active);

    switch ( ib_cm_event)
    {
      case IB_CME_CONNECTED:
          dat_event_num = DAT_CONNECTION_EVENT_ESTABLISHED;
          break;
      case IB_CME_DISCONNECTED:
           dat_event_num = DAT_CONNECTION_EVENT_DISCONNECTED;
           break;
      case IB_CME_DISCONNECTED_ON_LINK_DOWN:
           dat_event_num = DAT_CONNECTION_EVENT_DISCONNECTED;
           break;
      case IB_CME_CONNECTION_REQUEST_PENDING:
           dat_event_num = DAT_CONNECTION_REQUEST_EVENT;
           break;
      case IB_CME_CONNECTION_REQUEST_PENDING_PRIVATE_DATA:
           dat_event_num = DAT_CONNECTION_REQUEST_EVENT;
           break;
      case IB_CME_DESTINATION_REJECT:
           dat_event_num = DAT_CONNECTION_EVENT_NON_PEER_REJECTED;
           break;
      case IB_CME_DESTINATION_REJECT_PRIVATE_DATA:
           dat_event_num = DAT_CONNECTION_EVENT_PEER_REJECTED;
           break;
      case IB_CME_DESTINATION_UNREACHABLE:
           dat_event_num = DAT_CONNECTION_EVENT_UNREACHABLE;
           break;
      case IB_CME_TOO_MANY_CONNECTION_REQUESTS:
           dat_event_num = DAT_CONNECTION_EVENT_NON_PEER_REJECTED;
           break;
      case IB_CME_LOCAL_FAILURE:
      	   dat_event_num = DAT_CONNECTION_EVENT_BROKEN;
           break;
      case IB_CME_REPLY_RECEIVED:
      case IB_CME_REPLY_RECEIVED_PRIVATE_DATA:
      default:
           break;
    }
#if 0
    dapl_dbg_log (DAPL_DBG_TYPE_CM,
		  " dapls_ib_get_dat_event: event translation: (%s) "
		  "ib_event 0x%x dat_event 0x%x\n",
		  active ? "active" : "passive",
		  ib_cm_event,
		  dat_event_num);
#endif
    return dat_event_num;
}


/*
 * dapls_ib_get_dat_event
 *
 * Return a DAT connection event given a provider CM event.
 *
 * N.B.	Some architectures combine async and CM events into a
 *	generic async event. In that case, dapls_ib_get_cm_event()
 *	and dapls_ib_get_async_event() should be entry points that
 *	call into a common routine.
 *
 *	WARNING: In this implementation, there are multiple CM
 *	events that map to a single DAT event. Be very careful
 *	with provider routines that depend on this reverse mapping,
 *	they may have to accomodate more CM events than they
 *	'naturally' would.
 *
 * Input:
 *	dat_event_num	DAT event we need an equivelent CM event for
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	ib_cm_event of translated DAPL value
 */
ib_cm_events_t
dapls_ib_get_cm_event (
	IN    DAT_EVENT_NUMBER		dat_event_num)
{
    ib_cm_events_t	ib_cm_event = 0;

    switch (dat_event_num)
    {
        case DAT_CONNECTION_EVENT_ESTABLISHED:
             ib_cm_event = IB_CME_CONNECTED;
             break;
        case DAT_CONNECTION_EVENT_DISCONNECTED:
             ib_cm_event = IB_CME_DISCONNECTED;
             break;
        case DAT_CONNECTION_REQUEST_EVENT:
             ib_cm_event =  IB_CME_CONNECTION_REQUEST_PENDING;
             break;
        case DAT_CONNECTION_EVENT_NON_PEER_REJECTED:
             ib_cm_event = IB_CME_DESTINATION_REJECT;
             break;
        case DAT_CONNECTION_EVENT_PEER_REJECTED:
             ib_cm_event = IB_CME_DESTINATION_REJECT_PRIVATE_DATA;
             break;
        case DAT_CONNECTION_EVENT_UNREACHABLE:
             ib_cm_event = IB_CME_DESTINATION_UNREACHABLE;
             break;
        case DAT_CONNECTION_EVENT_BROKEN:
             ib_cm_event = IB_CME_LOCAL_FAILURE;
             break;
        default:
             break;
    }

    return ib_cm_event;
}



/*
 * dapls_set_provider_specific_attr
 *
 * Input:
 *	attr_ptr	Pointer provider specific attributes
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	void
 */

#ifdef DAT_EXTENSIONS
static DAT_NAMED_ATTR	ib_attrs[] = {
    {
    	"DAT_EXTENSION_INTERFACE", "TRUE"
    },
    {
    	DAT_IB_ATTR_FETCH_AND_ADD, "TRUE"
    },
    {
    	DAT_IB_ATTR_CMP_AND_SWAP, "TRUE"
    },
    {
    	DAT_IB_ATTR_IMMED_DATA, "TRUE"
    },
};
#define SPEC_ATTR_SIZE( x )	(sizeof( x ) / sizeof( DAT_NAMED_ATTR))
#else
static DAT_NAMED_ATTR	*ib_attrs = NULL;
#define SPEC_ATTR_SIZE( x )	0
#endif

void dapls_query_provider_specific_attr(
	IN	DAPL_IA				*ia_ptr,
	IN	DAT_PROVIDER_ATTR	*attr_ptr )
{
    attr_ptr->num_provider_specific_attr = SPEC_ATTR_SIZE(ib_attrs);
    attr_ptr->provider_specific_attr     = ib_attrs;
}


DAT_RETURN dapls_ns_map_gid (
	IN  DAPL_HCA		*hca_ptr,
	IN  DAT_IA_ADDRESS_PTR	remote_ia_address,
	OUT GID			*gid)
{
    return (dapls_ib_ns_map_gid (hca_ptr, remote_ia_address, gid));
}

DAT_RETURN dapls_ns_map_ipaddr (
	IN  DAPL_HCA		*hca_ptr,
	IN  GID			gid,
	OUT DAT_IA_ADDRESS_PTR	remote_ia_address)
{
    return (dapls_ib_ns_map_ipaddr (hca_ptr, gid, remote_ia_address));
}


#ifdef NOT_USED
/*
 * dapls_ib_post_recv - defered.until QP ! in init state.
 *
 * Provider specific Post RECV function
 */

DAT_RETURN 
dapls_ib_post_recv_defered (
	IN  DAPL_EP		   	*ep_ptr,
	IN  DAPL_COOKIE			*cookie,
	IN  DAT_COUNT	   		num_segments,
	IN  DAT_LMR_TRIPLET	   	*local_iov)
{
    ib_api_status_t     ib_status;
    ib_recv_wr_t	*recv_wr, *rwr;
    ib_local_ds_t       *ds_array_p;
    DAT_COUNT           i, total_len;

    if (ep_ptr->qp_state != IB_QPS_INIT)
    {
        dapl_dbg_log (DAPL_DBG_TYPE_EP, "--> DsPR: BAD QP state(%s), not init? "
                      "EP %p QP %p cookie %p, num_seg %d\n", 
                      ib_get_port_state_str(ep_ptr->qp_state), ep_ptr,
                      ep_ptr->qp_handle, cookie, num_segments);
	return (DAT_INSUFFICIENT_RESOURCES);
    }

    recv_wr = dapl_os_alloc (sizeof(ib_recv_wr_t)
                             + (num_segments*sizeof(ib_local_ds_t)));
    if (NULL == recv_wr)
    {
	return (DAT_INSUFFICIENT_RESOURCES);
    }

    dapl_os_memzero(recv_wr, sizeof(ib_recv_wr_t));
    recv_wr->wr_id        = (DAT_UINT64) cookie;
    recv_wr->num_ds       = num_segments;

    ds_array_p = (ib_local_ds_t*)(recv_wr+1);

    recv_wr->ds_array     = ds_array_p;

    //total_len = 0;

    for (total_len = i = 0; i < num_segments; i++, ds_array_p++)
    {
        ds_array_p->length = (uint32_t)local_iov[i].segment_length;
        ds_array_p->lkey  = cl_hton32(local_iov[i].lmr_context);
        ds_array_p->vaddr = local_iov[i].virtual_address;
        total_len        += ds_array_p->length;
    }

    if (cookie != NULL)
    {
	cookie->val.dto.size = total_len;

        dapl_dbg_log (DAPL_DBG_TYPE_EP,
                      "--> DsPR: EP = %p QP = %p cookie= %p, num_seg= %d\n", 
                      ep_ptr, ep_ptr->qp_handle, cookie, num_segments);
    }

    recv_wr->p_next = NULL;

    /* find last defered recv work request, link new on the end */
    rwr=ep_ptr->cm_post;
    if (rwr == NULL)
    {
        ep_ptr->cm_post = (void*)recv_wr;
        i = 1;
    }
    else
    {
        for(i=2; rwr->p_next; rwr=rwr->p_next) i++;
        rwr->p_next = recv_wr;
    }

    dapl_dbg_log (DAPL_DBG_TYPE_EP, "--> DsPR: %s() EP %p QP %p cookie %p "
                  "num_seg %d Tdefered %d\n", 
                  __FUNCTION__, ep_ptr, ep_ptr->qp_handle, cookie, num_segments,
                  i);

    return DAT_SUCCESS;
}
#endif

/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 8
 * End:
 */

