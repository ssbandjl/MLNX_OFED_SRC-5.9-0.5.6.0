# Copyright (C) Jan 2020 Mellanox Technologies Ltd. All rights reserved.   
#                                                                           
# This software is available to you under a choice of one of two            
# licenses.  You may choose to be licensed under the terms of the GNU       
# General Public License (GPL) Version 2, available from the file           
# COPYING in the main directory of this source tree, or the                 
# OpenIB.org BSD license below:                                             
#                                                                           
#     Redistribution and use in source and binary forms, with or            
#     without modification, are permitted provided that the following       
#     conditions are met:                                                   
#                                                                           
#      - Redistributions of source code must retain the above               
#        copyright notice, this list of conditions and the following        
#        disclaimer.                                                        
#                                                                           
#      - Redistributions in binary form must reproduce the above            
#        copyright notice, this list of conditions and the following        
#        disclaimer in the documentation and/or other materials             
#        provided with the distribution.                                    
#                                                                           
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,         
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF        
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND                     
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS       
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN        
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN         
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE          
# SOFTWARE.                                                                 
# --                                                                        


#######################################################
# 
# QueryData.py
# Python implementation of the Class QueryData
# Generated by Enterprise Architect
# Created on:      14-Aug-2019 10:12:02 AM
# Original author: talve
# 
#######################################################
from fetchers.ResourceDumpFetcher import ResourceDumpFetcher
from filters.SegmentsFilter import SegmentsFilter
from utils import constants


class QueryData:
    """this class is responsible for getting the menu segment.
    """

    @classmethod
    def get_query(cls, device_name, vhca_id):
        """this method is getting the query segments by using the CoreDumpFetcher and
        filter it by removing the none menu segments.
        """
        try:
            query_kwargs = {'segment': constants.RESOURCE_DUMP_SEGMENT_TYPE_MENU,
                            'vHCAid': vhca_id, 'index1': 0, 'index2': 0, 'numOfObj1': 0, 'numOfObj2': 0, 'depth': 0}
            query_segments = ResourceDumpFetcher(device_name).fetch_data(**query_kwargs)
            res = SegmentsFilter.get_segments(query_segments, constants.RESOURCE_DUMP_SEGMENT_TYPE_MENU)
            try:
                menu = res[0]
            except Exception as _:
                raise Exception("Menu segment wasn't found after filtering by menu type")
            return menu
        except Exception as e:
            raise Exception("Failed to fetch query data with exception: {0}".format(e))
