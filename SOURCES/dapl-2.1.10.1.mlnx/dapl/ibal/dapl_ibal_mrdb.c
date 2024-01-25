
/*
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
 * MODULE: dapl_ibal_mrdb.c
 *
 * PURPOSE: Utility routines for access to IBAL APIs
 *
 * $Id: dapl_ibal_mrdb.c 33 2005-07-11 19:51:17Z ftillier $
 *
 **********************************************************************/

#include "dapl.h"
#include "dapl_adapter_util.h"
#include "dapl_ibal_kmod.h"
#include "dapl_ibal_mrdb.h"

DAT_RETURN dapls_mrdb_init (
	IN  DAPL_HCA			*hca_ptr)
{
    cl_status_t        cl_status;
    char               name[32];
    dapl_ibal_ca_t     *p_ca;
   
    p_ca = (dapl_ibal_ca_t *) hca_ptr->ib_hca_handle;

    if (p_ca == NULL)
    {
        dapl_dbg_log (DAPL_DBG_TYPE_ERR, "--> %s: p_ca is NULL\n","DsMI");
        return DAT_INVALID_PARAMETER;
    }

    sprintf (name, 
             "/dev/mvdapl%x", 
             (uint32_t) cl_ntoh64 (p_ca->p_ca_attr->ca_guid));

    cl_status = cl_open_device ( (cl_dev_name_t) name, &p_ca->mlnx_device);

    if (cl_status != CL_SUCCESS)
    {
       /* dapl_dbg_log ( DAPL_DBG_TYPE_UTIL, 
                      "--> DsMI: Init MRDB failed = 0x%x\n", cl_status); */
        p_ca->mlnx_device = 0;
    }

    return DAT_SUCCESS;
}


DAT_RETURN dapls_mrdb_exit (
	IN  DAPL_HCA			*hca_ptr)
{
    dapl_ibal_ca_t     *p_ca;
   
    p_ca = (dapl_ibal_ca_t *) hca_ptr->ib_hca_handle;

    if (p_ca == NULL)
    {
        dapl_dbg_log (DAPL_DBG_TYPE_ERR, "--> %s: p_ca is NULL\n","DsME");
        return DAT_INVALID_PARAMETER;
    }

    if (p_ca->mlnx_device)
    {
        cl_close_device (p_ca->mlnx_device);
    }

    return DAT_SUCCESS;
}


DAT_RETURN dapls_mrdb_record_insert (
	IN  DAPL_HCA			*hca_ptr,
	IN  DAT_LMR_COOKIE		shared_mem_id,
	OUT int				*p_ib_shmid)
{
    cl_status_t                  cl_status;
    mrdb_rec_insert_ioctl_t      ioctl_buf;
    uintn_t                      bytes_ret;
    dapl_ibal_ca_t               *p_ca;
   
    p_ca = (dapl_ibal_ca_t *) hca_ptr->ib_hca_handle;

    if (p_ca == NULL)
    {
        dapl_dbg_log (DAPL_DBG_TYPE_ERR, "--> %s: p_ca is NULL\n","DsMRI");
        return DAT_INVALID_PARAMETER;
    }

    bytes_ret = 0;
    cl_memclr (&ioctl_buf, sizeof (ioctl_buf));
    cl_memcpy (ioctl_buf.shared_mem_id, shared_mem_id, IBAL_LMR_COOKIE_SIZE);

    dapl_dbg_log (DAPL_DBG_TYPE_UTIL, 
                       "--> DsMRI: MVDAPL_MRDB_REC_INSERT mem_cookie %p\n",
                       shared_mem_id);
#if defined(DAPL_DBG)
    {
        int  i;
        char *c = (char *) shared_mem_id;

        dapl_dbg_log (DAPL_DBG_TYPE_UTIL, 
                           "--> DsMRI: mem_cookie: \n");

        for ( i = 0; i < IBAL_LMR_COOKIE_SIZE ; i++)
        {
            dapl_dbg_log (DAPL_DBG_TYPE_UTIL, 
                               "0x%x ", *(c+i));
        }
        dapl_dbg_log (DAPL_DBG_TYPE_UTIL, "\n");
                           
    }
#endif /* DAPL_DBG */
        
    cl_status = cl_ioctl_device ( p_ca->mlnx_device, 
                                  MVDAPL_MRDB_RECORD_INSERT,
                                  &ioctl_buf,
                                  sizeof (mrdb_rec_insert_ioctl_t), 
                                  &bytes_ret);
    if ((cl_status != CL_SUCCESS) ||
        (ioctl_buf.status == IB_INSUFFICIENT_MEMORY))
    {
        dapl_dbg_log (DAPL_DBG_TYPE_ERR, "--> DsMRI: Failed to IOCTL record_insert 0x%x\n", cl_status);
        return DAT_INSUFFICIENT_RESOURCES;
    }

    *p_ib_shmid = (int) ioctl_buf.inout_f;

    if (ioctl_buf.status == IB_ERROR)
    {
        dapl_dbg_log (DAPL_DBG_TYPE_UTIL, 
                      "--> DsMRI: There is a record with shmid 0x%x\n", 
                       *p_ib_shmid);
        return DAT_INVALID_STATE;
    }
    else
    {
        dapl_dbg_log (DAPL_DBG_TYPE_UTIL, 
                      "--> DsMRI: Insert new mrdb record with shmid 0x%x\n", 
                       *p_ib_shmid);
    }
                        
    return DAT_SUCCESS;
}

DAT_RETURN dapls_mrdb_record_dec (
	IN  DAPL_HCA			*hca_ptr,
	IN  DAT_LMR_COOKIE		shared_mem_id)
{
    cl_status_t               cl_status;
    mrdb_rec_dec_ioctl_t      ioctl_buf;
    uintn_t                   bytes_ret;
    dapl_ibal_ca_t            *p_ca;
   
    p_ca = (dapl_ibal_ca_t *) hca_ptr->ib_hca_handle;

    if (p_ca == NULL)
    {
        dapl_dbg_log (DAPL_DBG_TYPE_ERR, "--> %s: p_ca is NULL\n","DsMRD");
        return DAT_INVALID_PARAMETER;
    }

    bytes_ret = 0;
    cl_memclr (&ioctl_buf, sizeof (ioctl_buf));
    cl_memcpy (ioctl_buf.shared_mem_id, shared_mem_id, IBAL_LMR_COOKIE_SIZE);

    dapl_dbg_log (DAPL_DBG_TYPE_UTIL, 
                       "--> DsMRD: MVDAPL_MRDB_REC_DEC mem_cookie 0x%p\n",
                       shared_mem_id);
#if defined(DAPL_DBG)
    {
        int  i;
        char *c = (char *) shared_mem_id;

        dapl_dbg_log (DAPL_DBG_TYPE_UTIL, 
                           "--> DsMRD: mem_cookie: \n");

        for ( i = 0; i < IBAL_LMR_COOKIE_SIZE ; i++)
        {
            dapl_dbg_log (DAPL_DBG_TYPE_UTIL, 
                               "0x%x ", *(c+i));
        }
        dapl_dbg_log (DAPL_DBG_TYPE_UTIL, "\n");
                           
    }
#endif /* DAPL_DBG */
        
    cl_status = cl_ioctl_device ( p_ca->mlnx_device, 
                                  MVDAPL_MRDB_RECORD_DEC,
                                  &ioctl_buf,
                                  sizeof (mrdb_rec_dec_ioctl_t), 
                                  &bytes_ret);
    if ((cl_status != CL_SUCCESS) ||
        (ioctl_buf.status != IB_SUCCESS))
    {
        dapl_dbg_log (DAPL_DBG_TYPE_ERR, "--> DsMRD: IOCTL failed 'cause there is no record  %s\n",
                ib_get_err_str(ioctl_buf.status));
        return DAT_INVALID_STATE;
    }

    return DAT_SUCCESS;
}

DAT_RETURN dapls_mrdb_record_update (
	IN  DAPL_HCA			*hca_ptr,
	IN  DAT_LMR_COOKIE		shared_mem_id,
	IN  ib_mr_handle_t		mr_handle)
{
    cl_status_t                  cl_status;
    mrdb_rec_update_ioctl_t      ioctl_buf;
    uintn_t                      bytes_ret;
    dapl_ibal_ca_t               *p_ca;
   
    p_ca = (dapl_ibal_ca_t *) hca_ptr->ib_hca_handle;

    if (p_ca == NULL)
    {
        dapl_dbg_log (DAPL_DBG_TYPE_ERR, "--> %s: p_ca is NULL\n","DsMRU");
        return DAT_INVALID_PARAMETER;
    }

    bytes_ret = 0;
    cl_memclr (&ioctl_buf, sizeof (ioctl_buf));
    cl_memcpy (ioctl_buf.shared_mem_id, shared_mem_id, IBAL_LMR_COOKIE_SIZE);
    ioctl_buf.mr_handle            = mr_handle;

    dapl_dbg_log (DAPL_DBG_TYPE_UTIL, 
                       "--> DsMRU: MVDAPL_MRDB_REC_UPDATE mr_handle %p\n", mr_handle);
#if defined(DAPL_DBG)                   
    {
        int  i;
        char *c = (char *) shared_mem_id;

        dapl_dbg_log (DAPL_DBG_TYPE_UTIL, 
                           "--> DsMRU: mem_cookie: \n");

        for ( i = 0; i < IBAL_LMR_COOKIE_SIZE ; i++)
        {
            dapl_dbg_log (DAPL_DBG_TYPE_UTIL, 
                               "0x%x ", *(c+i));
        }
        dapl_dbg_log (DAPL_DBG_TYPE_UTIL, "\n");
                           
    }
#endif /* DAPL_DBG */

    cl_status = cl_ioctl_device ( p_ca->mlnx_device, 
                                  MVDAPL_MRDB_RECORD_UPDATE,
                                  &ioctl_buf,
                                  sizeof (mrdb_rec_update_ioctl_t), 
                                  &bytes_ret);
    if ((cl_status != CL_SUCCESS) ||
        (ioctl_buf.status != IB_SUCCESS))
    {
        dapl_dbg_log (DAPL_DBG_TYPE_ERR, "--> DsMRU: IOCTL update_record failed %s\n",
                ib_get_err_str(ioctl_buf.status));
        return DAT_INTERNAL_ERROR;
    }
                        
    return DAT_SUCCESS;
}


DAT_RETURN dapls_mrdb_record_query (
	IN  DAPL_HCA			*hca_ptr,
	IN  DAT_LMR_COOKIE		shared_mem_id,
	OUT int				*p_ib_shmid,
	OUT ib_mr_handle_t		*p_mr_handle)
{
    cl_status_t               cl_status;
    mrdb_rec_query_ioctl_t    ioctl_buf;
    uintn_t                   bytes_ret;
    dapl_ibal_ca_t            *p_ca;
   
    p_ca = (dapl_ibal_ca_t *) hca_ptr->ib_hca_handle;

    if (p_ca == NULL)
    {
        dapl_dbg_log (DAPL_DBG_TYPE_ERR, "--> %s: p_ca is NULL\n","DsMRQ");
        return DAT_INVALID_PARAMETER;
    }

    bytes_ret = 0;
    cl_memclr (&ioctl_buf, sizeof (ioctl_buf));

    cl_memcpy (ioctl_buf.shared_mem_id, shared_mem_id, IBAL_LMR_COOKIE_SIZE);

    dapl_dbg_log (DAPL_DBG_TYPE_UTIL, 
                       "--> DsMRQ: MVDAPL_MRDB_REC_QUERY mem_cookie 0x%p\n",
                       shared_mem_id);
	#if defined(DAPL_DBG)  
    {
        int  i;
        char *c = (char *) shared_mem_id;

        dapl_dbg_log (DAPL_DBG_TYPE_UTIL, 
                           "--> DsMRQ: mem_cookie: \n");

        for ( i = 0; i < IBAL_LMR_COOKIE_SIZE ; i++)
        {
            dapl_dbg_log (DAPL_DBG_TYPE_UTIL, 
                               "0x%x ", *(c+i));
        }
        dapl_dbg_log (DAPL_DBG_TYPE_UTIL, "\n");
                           
    }
	#endif   
        
    cl_status = cl_ioctl_device ( p_ca->mlnx_device, 
                                  MVDAPL_MRDB_RECORD_QUERY,
                                  &ioctl_buf,
                                  sizeof (mrdb_rec_query_ioctl_t), 
                                  &bytes_ret);
    if ((cl_status != CL_SUCCESS) ||
        (ioctl_buf.status != IB_SUCCESS))
    {
        dapl_dbg_log (DAPL_DBG_TYPE_ERR, "--> DsMRQ: IOCTL query_record failed %s\n",
                ib_get_err_str(ioctl_buf.status));
        return DAT_INTERNAL_ERROR;
    }
                       
    *p_mr_handle  = ioctl_buf.mr_handle; 
    *p_ib_shmid   = (int) ioctl_buf.inout_f; 

    dapl_dbg_log (DAPL_DBG_TYPE_UTIL, 
                       "--> DsMRQ: MVDAPL_MRDB_REC_QUERY mr_handle 0x%p shmid 0x%x\n", 
                       *p_mr_handle, *p_ib_shmid);

    return DAT_SUCCESS;
}


DAT_RETURN dapls_ib_get_any_svid (
	IN  DAPL_HCA			*hca_ptr,
	OUT DAT_CONN_QUAL		*p_svid)
{
    cl_status_t               cl_status;
    psp_get_any_svid_ioctl_t  ioctl_buf;
    uintn_t                   bytes_ret;
    dapl_ibal_ca_t            *p_ca;
   
    p_ca = (dapl_ibal_ca_t *) hca_ptr->ib_hca_handle;

    if (p_ca == NULL)
    {
        dapl_dbg_log (DAPL_DBG_TYPE_ERR, "--> %s: p_ca is NULL\n","DsPGAS");
        return DAT_INVALID_PARAMETER;
    }

    bytes_ret = 0;
    cl_memclr (&ioctl_buf, sizeof (ioctl_buf));

    cl_status = cl_ioctl_device ( p_ca->mlnx_device, 
                                  MVDAPL_GET_ANY_SVID,
                                  &ioctl_buf,
                                  sizeof (psp_get_any_svid_ioctl_t), 
                                  &bytes_ret);
    if ((cl_status != CL_SUCCESS) ||
        (ioctl_buf.status != IB_SUCCESS))
    {
        dapl_dbg_log (DAPL_DBG_TYPE_ERR, "--> DsMRQ: IOCTL query_record failed %s\n",
                ib_get_err_str(ioctl_buf.status));
        return DAT_INTERNAL_ERROR;
    }
                       
    *p_svid   = (DAT_CONN_QUAL) ioctl_buf.inout_f; 

    dapl_dbg_log (DAPL_DBG_TYPE_UTIL, 
                       "--> DsPGAS: new ServiceID 0x%x\n", 
                       *p_svid);

    return DAT_SUCCESS;
}


/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 8
 * End:
 */

