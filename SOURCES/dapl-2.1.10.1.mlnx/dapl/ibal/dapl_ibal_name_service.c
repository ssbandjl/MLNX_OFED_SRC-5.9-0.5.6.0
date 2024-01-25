/*
 * Copyright (c) 2007-2008 Intel Corporation. All rights reserved.
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
 * MODULE: dapl_ibal_name_service.c
 *
 * PURPOSE: IP Name service
 *
 * $Id$
 *
 **********************************************************************/

#include "dapl.h"
#include "dapl_adapter_util.h"
#include "dapl_evd_util.h"
#include "dapl_cr_util.h"
#include "dapl_sp_util.h"
#include "dapl_ep_util.h"
#include "dapl_ia_util.h"
#include "dapl_ibal_util.h"
#include "dapl_name_service.h"

#define IB_INFINITE_SERVICE_LEASE   0xFFFFFFFF
#define  DAPL_ATS_SERVICE_ID        ATS_SERVICE_ID //0x10000CE100415453
#define  DAPL_ATS_NAME              ATS_NAME
#define  HCA_IPV6_ADDRESS_LENGTH    16

extern dapl_ibal_root_t        dapl_ibal_root;


char *
dapli_get_ip_addr_str(DAT_SOCK_ADDR6 *ipa, char *buf)
{
    int rval;
    static char lbuf[24];
    char *str = (buf ? buf : lbuf);
  
    rval = ((struct sockaddr_in *)ipa)->sin_addr.s_addr;

    sprintf(str, "%d.%d.%d.%d",
                      (rval >> 0) & 0xff,
                      (rval >> 8) & 0xff,
                      (rval >> 16) & 0xff,
                      (rval >> 24) & 0xff);
    return str;
}



void AL_API
dapli_ib_sa_query_cb (IN ib_query_rec_t *p_query_rec )
{
    ib_api_status_t ib_status;

    if (IB_SUCCESS != p_query_rec->status)
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,"%s: SA query callback failed %s\n",
                       __FUNCTION__, ib_get_err_str(p_query_rec->status));
        return;
    }

    if (!p_query_rec->p_result_mad)
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                       "%s: SA query callback [no mad] @line %d\n",
                       __FUNCTION__, __LINE__);
        return;
    }

    switch (p_query_rec->query_type)
    {
        case IB_QUERY_PATH_REC_BY_GIDS:
        {
            ib_path_rec_t                *p_path_rec;

            p_path_rec = ib_get_query_path_rec (p_query_rec->p_result_mad, 0);
            if (p_path_rec) 
            {
                dapl_os_memcpy ((void * __ptr64) p_query_rec->query_context, 
                                (void *) p_path_rec,
                                sizeof (ib_path_rec_t));
                dapl_dbg_log (
                       DAPL_DBG_TYPE_CM | DAPL_DBG_TYPE_CALLBACK,
                       "sa_query_cb: path {slid: 0x%x, dlid: 0x%x}\n",
                       p_path_rec->slid, p_path_rec->dlid);
            }
            else
            {
                dapl_dbg_log ( DAPL_DBG_TYPE_ERR,"%s: return NULL? @line %d\n",
                               __FUNCTION__, __LINE__);
                return;
            }
            break;
        }

        case IB_QUERY_SVC_REC_BY_ID:
        {
            ib_service_record_t          *p_svc_rec;

            p_svc_rec = ib_get_query_svc_rec (p_query_rec->p_result_mad, 0);
            if (p_svc_rec) 
            {
                dapl_os_memcpy ((void * __ptr64) p_query_rec->query_context, 
                                (void *) p_svc_rec,
                                sizeof (ib_service_record_t));
                dapl_dbg_log (
                     DAPL_DBG_TYPE_CM | DAPL_DBG_TYPE_CALLBACK,
                     "%s: SER{0x%I64x, 0x%I64x}\n", __FUNCTION__,
                     cl_hton64 (p_svc_rec->service_gid.unicast.prefix),
                     cl_hton64 (p_svc_rec->service_gid.unicast.interface_id));
            }
            else
            {
                dapl_dbg_log ( DAPL_DBG_TYPE_ERR,"%s: return NULL? @line %d\n",
                               __FUNCTION__, __LINE__);
                return;
            }
            break;

        }

        case IB_QUERY_USER_DEFINED:
        {
            ib_user_query_t    *p_user_query;

            p_user_query=(ib_user_query_t * __ptr64) p_query_rec->query_context;

            if (p_user_query)
            {
                switch (p_user_query->attr_id)
                {
                    case IB_MAD_ATTR_SERVICE_RECORD:
                    {
                        ib_service_record_t          *p_svc_rec;

                        p_svc_rec = ib_get_query_svc_rec (
                                                  p_query_rec->p_result_mad, 0);
                        if (p_svc_rec) 
                        {
                            dapl_os_memcpy ((void *) p_user_query->p_attr, 
                                            (void *) p_svc_rec,
                                            sizeof (ib_service_record_t));
                            dapl_dbg_log (
                               DAPL_DBG_TYPE_CM | DAPL_DBG_TYPE_CALLBACK,
                               "%s: GID{0x" F64x ", 0x" F64x "} record count %d\n",
                              __FUNCTION__,
                              cl_hton64(p_svc_rec->service_gid.unicast.prefix),
                              cl_hton64(p_svc_rec->service_gid.unicast.interface_id),
                              p_query_rec->result_cnt);
                        }
                        else
                        {
                            dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                                           "%s: return NULL? @line %d\n",
                                           __FUNCTION__, __LINE__);
                            return;
                        }
                        break;

                    }
                    default:
                    {
                        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                                       "%s: USER_DEFINED %d\n",
                                       p_user_query->attr_id );
                        break;
                    }
                }
            }
            else
            {
                dapl_dbg_log ( DAPL_DBG_TYPE_ERR,"%s: return NULL? @line %d\n",
                               __FUNCTION__, __LINE__);
                return;
            }
            break;
        }

        default:
        {
            dapl_dbg_log ( DAPL_DBG_TYPE_ERR,"%s: unsupportedTYPE %d\n",
                           __FUNCTION__, p_query_rec->query_type);
            break;
        }

    }

    if ((ib_status = ib_put_mad (p_query_rec->p_result_mad)) != IB_SUCCESS)
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,"%s: can not free MAD %s\n", 
                       __FUNCTION__, ib_get_err_str(ib_status));
    } 
}


#ifndef NO_NAME_SERVICE

DAT_RETURN
dapls_ib_ns_map_gid (
        IN        DAPL_HCA                *hca_ptr,
        IN        DAT_IA_ADDRESS_PTR      p_ia_address,
        OUT       GID                     *p_gid)
{
    ib_user_query_t     user_query;
    dapl_ibal_ca_t      *p_ca;
    dapl_ibal_port_t    *p_active_port;
    ib_service_record_t service_rec;
    ib_api_status_t     ib_status;
    ib_query_req_t      query_req;
    DAT_SOCK_ADDR6      ipv6_addr;

    p_ca = (dapl_ibal_ca_t *) hca_ptr->ib_hca_handle;

    if (NULL == p_ca)
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                       "--> DsNMG: There is no HCA = %d\n", __LINE__);
        return (DAT_INVALID_HANDLE);
    }

    /*
     * We are using the first active port in the list for
     * communication. We have to get back here when we decide to support
     * fail-over and high-availability.
     */
    p_active_port = dapli_ibal_get_port ( p_ca, (uint8_t)hca_ptr->port_num );

    if (NULL == p_active_port)
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                       "--> DsNMG: Port %d is not available = %d\n",
                       hca_ptr->port_num, __LINE__);
        return (DAT_INVALID_STATE);
    }

    if (p_active_port->p_attr->lid == 0) 
    {
            dapl_dbg_log ( DAPL_DBG_TYPE_ERR, "--> DsNMG: Port %d has no LID "
                           "assigned; can not operate\n", 
                           p_active_port->p_attr->port_num);
            return (DAT_INVALID_STATE);
    }

    if (!dapl_os_memcmp (p_ia_address,
                         &hca_ptr->hca_address,
                         HCA_IPV6_ADDRESS_LENGTH))
    {
        /* We are operating in the LOOPBACK mode */
        p_gid->guid =p_active_port->p_attr->p_gid_table[0].unicast.interface_id;
        p_gid->gid_prefix =p_active_port->p_attr->p_gid_table[0].unicast.prefix;
        return DAT_SUCCESS;
    }

    if (p_active_port->p_attr->link_state != IB_LINK_ACTIVE)
    {
        /* 
         * Port is DOWN; can not send or recv messages
         */
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
			"--> DsNMG: Port %d is DOWN; can not send to fabric\n", 
			p_active_port->p_attr->port_num);
        return (DAT_INVALID_STATE);
    }

    dapl_os_memzero (&user_query, sizeof (ib_user_query_t));
    dapl_os_memzero (&service_rec, sizeof (ib_service_record_t));
    dapl_os_memzero (&query_req, sizeof (ib_query_req_t));
    dapl_os_memzero (&ipv6_addr, sizeof (DAT_SOCK_ADDR6));

    if (p_ia_address->sa_family == AF_INET)
    {
        dapl_os_memcpy (&ipv6_addr.sin6_addr.s6_addr[12], 
                        &((struct sockaddr_in *)p_ia_address)->sin_addr.s_addr, 
                        4);
#if defined(DAPL_DBG) || 1 // XXX
        {
            char ipa[20];

            dapl_dbg_log (DAPL_DBG_TYPE_CM, "--> DsNMG: Remote ia_address %s\n",
                          dapli_get_ip_addr_str(
                                           (DAT_SOCK_ADDR6*)p_ia_address, ipa));
        }
#endif

    }
    else
    {
        /*
         * Assume IPv6 address
         */
        dapl_os_assert (p_ia_address->sa_family == AF_INET6);
        dapl_os_memcpy (ipv6_addr.sin6_addr.s6_addr,
                        ((DAT_SOCK_ADDR6 *)p_ia_address)->sin6_addr.s6_addr, 
                        HCA_IPV6_ADDRESS_LENGTH);
#if defined(DAPL_DBG) || 1 // XXX
        {
            int i;
            uint8_t *tmp = ipv6_addr.sin6_addr.s6_addr;

            dapl_dbg_log ( DAPL_DBG_TYPE_CM, 
                           "--> DsNMG: Remote ia_address -  ");

            for ( i = 1; i < HCA_IPV6_ADDRESS_LENGTH; i++)
            {
                dapl_dbg_log ( DAPL_DBG_TYPE_CM, "%x:", 
                               tmp[i-1] );
            }
            dapl_dbg_log ( DAPL_DBG_TYPE_CM, "%x\n",
                           tmp[i-1] );
        }
#endif

    }

    /*
     * query SA for GID
     */
    //service_rec.service_id    = CL_HTON64 (DAPL_ATS_SERVICE_ID);
    dapl_os_memcpy ( service_rec.service_name,
                     ATS_NAME,
                     __min(sizeof(ATS_NAME),sizeof(ib_svc_name_t)) );
    dapl_os_memcpy (&service_rec.service_data8[0], 
                    ipv6_addr.sin6_addr.s6_addr,
                    HCA_IPV6_ADDRESS_LENGTH);
    service_rec.service_lease = IB_INFINITE_SERVICE_LEASE;
    service_rec.service_pkey  = IB_DEFAULT_PKEY;

    user_query.method         = IB_MAD_METHOD_GETTABLE;
    user_query.attr_id        = IB_MAD_ATTR_SERVICE_RECORD;
    user_query.comp_mask      = IB_SR_COMPMASK_SPKEY      |
				IB_SR_COMPMASK_SLEASE     |
				IB_SR_COMPMASK_SNAME      |
                                IB_SR_COMPMASK_SDATA8_0   |
                                IB_SR_COMPMASK_SDATA8_1   |
                                IB_SR_COMPMASK_SDATA8_2   |
                                IB_SR_COMPMASK_SDATA8_3   |
                                IB_SR_COMPMASK_SDATA8_4   |
                                IB_SR_COMPMASK_SDATA8_5   |
                                IB_SR_COMPMASK_SDATA8_6   |
                                IB_SR_COMPMASK_SDATA8_7   |
                                IB_SR_COMPMASK_SDATA8_8   |
                                IB_SR_COMPMASK_SDATA8_9   |
                                IB_SR_COMPMASK_SDATA8_10  |
                                IB_SR_COMPMASK_SDATA8_11  |
                                IB_SR_COMPMASK_SDATA8_12  |
                                IB_SR_COMPMASK_SDATA8_13  |
                                IB_SR_COMPMASK_SDATA8_14  |
                                IB_SR_COMPMASK_SDATA8_15;

    user_query.attr_size      = sizeof (ib_service_record_t);
    user_query.p_attr         = (void *)&service_rec;

    query_req.query_type      = IB_QUERY_USER_DEFINED;
    query_req.p_query_input   = (void *)&user_query;
    query_req.flags           = IB_FLAGS_SYNC;  /* this is a blocking call */
    query_req.timeout_ms      = 1 * 1000;       /* 1 second */
    query_req.retry_cnt       = 5;
    /* query SA using this port */
    query_req.port_guid       = p_active_port->p_attr->port_guid;
    query_req.query_context   = (void *) &user_query;
    query_req.pfn_query_cb    = dapli_ib_sa_query_cb;
	
    ib_status = ib_query (dapl_ibal_root.h_al, &query_req, NULL);
	
    if (ib_status != IB_SUCCESS) 
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,"ns_map_gid: status %s @line = %d\n", 
                ib_get_err_str(ib_status), __LINE__);
        return (dapl_ib_status_convert (ib_status));
    }
    else if (service_rec.service_gid.unicast.interface_id == 0)
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                       "--> %s: query SA found no record\n",__FUNCTION__); 
        return DAT_INVALID_PARAMETER;
    }
  
    /* 
     * return the GID
     */ 
    p_gid->guid       = service_rec.service_gid.unicast.interface_id;
    p_gid->gid_prefix = service_rec.service_gid.unicast.prefix;

    return DAT_SUCCESS;
}



DAT_RETURN
dapls_ib_ns_map_ipaddr (
        IN        DAPL_HCA                *hca_ptr,
        IN        GID                     gid,
        OUT       DAT_IA_ADDRESS_PTR      p_ia_address)
{
    ib_user_query_t     user_query;
    dapl_ibal_ca_t      *p_ca;
    dapl_ibal_port_t    *p_active_port;
    ib_service_record_t service_rec;
    ib_api_status_t     ib_status;
    ib_query_req_t        query_req;

    p_ca = (dapl_ibal_ca_t *) hca_ptr->ib_hca_handle;

    if (NULL == p_ca)
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                       "--> DsNMI: There is no HCA = %d\n", __LINE__);
        return (DAT_INVALID_HANDLE);
    }

    /*
     * We are using the first active port in the list for
     * communication. We have to get back here when we decide to support
     * fail-over and high-availability.
     */
    p_active_port = dapli_ibal_get_port ( p_ca, (uint8_t)hca_ptr->port_num );

    if (NULL == p_active_port)
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                       "--> DsNMI: Port %d is not available = %d\n",
                       hca_ptr->port_num, __LINE__);
        return (DAT_INVALID_STATE);
    }

    if (p_active_port->p_attr->lid == 0) 
    {
            dapl_dbg_log ( DAPL_DBG_TYPE_ERR, "--> DsNMI: Port %d has no LID "
                           "assigned; can not operate\n", 
                           p_active_port->p_attr->port_num);
            return (DAT_INVALID_STATE);
    }
    /*else 
    {
        // 
         // We are operating in the LOOPBACK mode
         //
        if ((gid.gid_prefix ==
             p_active_port->p_attr->p_gid_table[0].unicast.prefix) &&
            (gid.guid  == 
             p_active_port->p_attr->p_gid_table[0].unicast.interface_id))
        {
            dapl_os_memcpy (((DAT_SOCK_ADDR6 *)p_ia_address)->sin6_addr.s6_addr, 
                            hca_ptr->hca_address.sin6_addr.s6_addr,
                            HCA_IPV6_ADDRESS_LENGTH);
            return DAT_SUCCESS;
        }
        
    }*/

    if (p_active_port->p_attr->link_state != IB_LINK_ACTIVE)
    {
		/* 
         * Port is DOWN; can not send or recv messages
         */
		dapl_dbg_log ( DAPL_DBG_TYPE_ERR,"--> DsNMI: Port %d is DOWN; "
                               "can not send/recv to/from fabric\n", 
                               p_active_port->p_attr->port_num);
        return (DAT_INVALID_STATE);
    }

    dapl_os_memzero (&user_query, sizeof (ib_user_query_t));
    dapl_os_memzero (&service_rec, sizeof (ib_service_record_t));
    dapl_os_memzero (&query_req, sizeof (ib_query_req_t));

    /*
     * query SA for IPAddress
     */
    //service_rec.service_id    = CL_HTON64 (DAPL_ATS_SERVICE_ID);
	dapl_os_memcpy( service_rec.service_name,
                        ATS_NAME,
                        __min (sizeof(ATS_NAME), sizeof(ib_svc_name_t)));
    service_rec.service_gid.unicast.interface_id = gid.guid;
    service_rec.service_gid.unicast.prefix       = gid.gid_prefix;
    service_rec.service_pkey                     = IB_DEFAULT_PKEY;
    service_rec.service_lease                    = IB_INFINITE_SERVICE_LEASE;

    user_query.method                            = IB_MAD_METHOD_GETTABLE;
    user_query.attr_id                           = IB_MAD_ATTR_SERVICE_RECORD;

    user_query.comp_mask      = IB_SR_COMPMASK_SGID      |
				IB_SR_COMPMASK_SPKEY     |
				IB_SR_COMPMASK_SLEASE    |	
				IB_SR_COMPMASK_SNAME;

    user_query.attr_size      = sizeof (ib_service_record_t);
    user_query.p_attr         = (void *)&service_rec;

    query_req.query_type      = IB_QUERY_USER_DEFINED;
    query_req.p_query_input   = (void *)&user_query;
    query_req.flags           = IB_FLAGS_SYNC;  /* this is a blocking call */
    query_req.timeout_ms      = 1 * 1000;       /* 1 second */
    query_req.retry_cnt       = 5;
    /* query SA using this port */
    query_req.port_guid       = p_active_port->p_attr->port_guid;
    query_req.query_context   = (void *) &user_query;
    query_req.pfn_query_cb    = dapli_ib_sa_query_cb;

    ib_status = ib_query (dapl_ibal_root.h_al, &query_req, NULL);

    if (ib_status != IB_SUCCESS)
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                       "ns_map_ipaddr: exits status %s @line = %d\n", 
                       ib_get_err_str(ib_status), __LINE__);
        return (dapl_ib_status_convert (ib_status));
    }
  
    /* ***********************
     * return the IP_address
     *************************/ 
	dapl_os_memcpy (
                 (void *) &((struct sockaddr_in *)p_ia_address)->sin_addr.s_net,
                 (const void *)&service_rec.service_data8[ATS_IPV4_OFFSET], 4);
                    //HCA_IPV6_ADDRESS_LENGTH);
    ((DAT_SOCK_ADDR6 *)p_ia_address)->sin6_family = AF_INET;
	
    return (DAT_SUCCESS);
}


/*
 * dapls_ib_ns_create_gid_map()
 *
 * Register a ServiceRecord containing uDAPL_svc_id, IP address and GID to SA
 * Other nodes can look it up by quering the SA
 *
 * Input:
 *        hca_ptr        HCA device pointer
 *
 * Output:
 *         none
 *
 * Returns:
 *         DAT_SUCCESS
 *         DAT_INVALID_PARAMETER
 */
DAT_RETURN
dapls_ib_ns_create_gid_map (
        IN        DAPL_HCA       *hca_ptr)
{
    UNUSED_PARAM( hca_ptr );
    return (DAT_SUCCESS);
}


DAT_RETURN
dapls_ib_ns_remove_gid_map (
        IN        DAPL_HCA       *hca_ptr)
{
    UNUSED_PARAM( hca_ptr );
    return (DAT_SUCCESS);
}

#endif /* NO_NAME_SERVICE */
