#!/bin/sh
#
# Copyright (c) 2002-2005, Network Appliance, Inc. All rights reserved.
# Copyright (c) 2014 Intel Corporation.  All rights reserved.
#
# This Software is licensed under one of the following licenses:
#
# 1) under the terms of the "Common Public License 1.0" a copy of which is
#    in the file LICENSE.txt in the root directory. The license is also
#    available from the Open Source Initiative, see
#    http://www.opensource.org/licenses/cpl.php.
#
# 2) under the terms of the "The BSD License" a copy of which is in the file
#    LICENSE2.txt in the root directory. The license is also available from
#    the Open Source Initiative, see
#    http://www.opensource.org/licenses/bsd-license.php.
#
# 3) under the terms of the "GNU General Public License (GPL) Version 2" a 
#    copy of which is in the file LICENSE3.txt in the root directory. The 
#    license is also available from the Open Source Initiative, see
#    http://www.opensource.org/licenses/gpl-license.php.
#
# Licensee has the right to choose one of the above licenses.
#
# Redistributions of source code must retain the above copyright
# notice and one of the license notices.
#
# Redistributions in binary form must reproduce both the above copyright
# notice, one of the license notices in the documentation
# and/or other materials provided with the distribution.
#
# Sample DAPLtest client Usage: cl.sh hostname [testname] [device]
#
# default device = ofa-v2-ib0
#

DT=dapltest
D=ofa-v2-ib0
L=1
X=
T=
E=

# need some help?
if [ "$1" == "-h" ] ; then
    T=
else
    S=$1
    if [ ! "$2" == "" ] ; then
        T=$2
        if [ ! "$3" == "" ] ; then
	    D=$3
        fi
    fi
fi

if [ ! "$X" == "" ] ; then
    DAT_OS_DBG_TYPE=$X
    DAT_DBG_TYPE=$X
    DAT_DBG_LEVEL=$X
    DAPL_DBG_LEVEL=$X
    DAPL_DBG_TYPE=$X
else
    DAT_DBG_TYPE=0x1
    DAT_DBG_LEVEL=1
fi

echo ""
echo "uDAPL client test $DT $T $D -> $S"
echo ""

# Endpoint and Thread stress
if [ "$T" == "epa" ] ; then
    T=10
    E=10
    LT=10
    LE=50
    for ((T=$T ; $T <= $LT ; $((T++)) )) ; do
    	for ((E=$E ; $E <= $LE ; $((E++)) )) ; do
           echo $T $E: Multi: Threads[$T] Endpoints[$E] Send/Recv test - 4096 iterations, 3 8K segs
           $DT -T T -s $S -D $D -i 4096 -t $T -w $E client SR 8192 3 server SR 8192 3
           if [ $? -ne 0 ] ;  then
		echo failed $X
		exit 1
           fi
        done
    done
    echo THREADS $LT and ENDPOINTS $LE loops completed.
    exit
fi

if [ "$T" == "conn" ] ; then
# Connectivity test - client sends one buffer with one 4KB segments, one time.
# add '-d' for debug output.
    $DT -T T -s $S -D $D -i 1 -t 1 -w 1 client SR 4096 server SR 4096
    exit
fi

if [ "$T" == "trans" ] ; then
    echo Transaction test - 8192 iterations, 1 thread, SR 4KB buffers
   $DT -T T -s $S -D $D -i 8192 -t 1 -w 1 client SR 4096 server SR 4096
    exit 
fi

if [ "$T" == "transm" ] ; then
    echo Multiple RW, RR, SR transactions, 4096 iterations
    $DT -T T -P -t 1 -w 1 -i 4096 -s $S -D $D client RW  4096 1 server RW  2048 4  server RR  1024 1 client RR 2048 1 client SR 1024 3 -f server SR 256 3 -f
    exit 
fi

if [ "$T" == "transmx" ] ; then
    echo Multiple RW, RR, SR transactions, 8192 iterations
    $DT -T T -P -t 1 -w 1 -i 8192 -s $S -D $D \
	client RW  32768 4 server RW  32768 4  \
	server RR  32768 1 client RR 32768 1 \
	client SR 16384 4 -f server SR 16384 4 -f
    exit 
fi

if [ "$T" == "transt" ] ; then
    echo Multi-threaded[4] Transaction test - 4096 iterations, 1 thread, SR 4KB buffers
   $DT -T T -s $S -D $D -i 4096 -t 4 -w 1 client SR 8192 3 server SR 8192 3
    exit
fi

if [ "$T" == "transme" ] ; then
    echo Multiple endpoints[4] transactions [RW, RR, SR], 4096 iterations
    $DT -T T -P -t 1 -w 4 -i 4096 -s $S -D $D client RW  4096 1 server RW  2048 4  server RR  1024 1 client RR 2048 1 client SR 1024 3 -f server SR 256 3 -f
    exit
fi

if [ "$T" == "transmet" ] ; then
    echo Multiple: threads[2] endpoints[4] transactions[RW, RR, SR], 4096 iterations
    $DT -T T -P -t 2 -w 4 -i 4096 -s $S -D $D client RW  4096 1 server RW  2048 4  server RR  1024 1 client RR 2048 1 client SR 1024 3 -f server SR 256 3 -f
    exit
fi

if [ "$T" == "transmete" ] ; then
    echo Multiple: threads[4] endpoints[4] transactions[RW, RR, SR], 8192 iterations
    $DT -T T -P -t 4 -w 4 -i 8192 -s $S -D $D client RW  4096 1 server RW  2048 4  server RR  1024 1 client RR 2048 1 client SR 1024 3 -f server SR 256 3 -f
    exit
fi

if [ "$T" == "threads" ] ; then
    echo Multi Threaded[6] Send/Recv test - 4096 iterations, 3 8K segs
    $DT -T T -s $S -D $D -i 4096 -t 6 -w 1 client SR 8192 3 server SR 8192 3
    exit
fi

if [ "$T" == "threadsm" ] ; then
    echo Multi: Threads[4] endpoints[4] Send/Recv test - 4096 iterations, 3 8K segs
    $DT -T T -s $S -D $D -i 4096 -t 4 -w 4 client SR 8192 3 server SR 8192 3
    exit
fi

if [ "$T" == "perf" ] ; then
    #echo Performance test
    $DT -T P -s $S -D $D -i 2048 -m b RW 4096 2
    exit
fi

if [ "$T" == "rdma-read" ] ; then
    $DT -T P -s $S -D $D -i 4096 RR 32768 1
    exit
fi

if [ "$T" == "rdma-write" ] ; then
    $DT -T P -s $S -D $D -i 4096 RW 32768 4
    exit
fi

if [ "$T" == "bw" ] ; then
    echo bandwidth 65K msgs
    $DT -T P -s $S -D $D -i 4096 -p 16 -m b RW 65536 2 
    exit
fi

if [ "$T" == "latb" ] ; then
    echo latency test - block for completion events
    $DT -T P -s $S -D $D -i 8192 -p 1 -m b RW 4 1
    exit
fi

if [ "$T" == "latp" ] ; then
    echo latency test - poll completion events
    $DT -T P -s $S -D $D -i 100000 -p 1 -m p RW 4 1
    exit
fi

if [ "$T" == "lim" ] ; then
    echo Resource limit tests
    $DT -T L -D $D -w 8 -m 100 limit_ia
    $DT -T L -D $D -w 8 -m 100 limit_pz
    $DT -T L -D $D -w 8 -m 100 limit_evd
    $DT -T L -D $D -w 8 -m 100 limit_ep
    $DT -T L -D $D -w 8 -m 100 limit_psp
    $DT -T L -D $D -w 8 -m 100 limit_lmr
    $DT -T L -D $D -w 8 -m 15 limit_rpost
    exit
fi

if [ "$T" == "regression" ] ; then
    echo $T testing in $L Loops
    # rdma-write, read, perf
    TST="trans perf threads threadsm transm transt transme transmet transmete rdma-write rdma-read bw latb latp "
    for ((n=1 ; $n <= $L ; $((n++)) )) ; do
        for X in $TST ; do
           $0 $1 $X $D
           if [ $? -ne 0 ] ;  then
		echo failed $X
		exit 1
           fi
        done
        echo $n $T loops completed.
    done
    $DT -T Q -s $S -D $D
    exit 0
fi

if [ "$T" == "stop" ] ; then
    $DT -T Q -s $S -D $D
    exit
fi

echo " usage: cl.sh hostname [testname [-D]]"
echo "   where testname"
echo "     stop - request DAPLtest server to exit."
echo "     conn - simple connection with limited dater transfer"
echo "     trans - single transaction test"
echo "     transm - transaction test: multiple transactions [RW SND, RDMA]"
echo "     transt - transaction test: multi-threaded, single transaction"
echo "     transme - transaction test: multi-endpoints per thread "
echo "     transmet - transaction test: multi: threads and endpoints per thread"
echo "     transmete - transaction test: multi threads == endpoints"
echo "     perf - Performance test"
echo "     threads - multi-threaded single transaction test."
echo "     threadsm - multi: threads and endpoints, single transaction test."
echo "     rdma-write - RDMA write"
echo "     rdma-read - RDMA read"
echo "     bw - bandwidth"
echo "     latb - latency tests, blocking for events"
echo "     latp - latency tests, polling for events"
echo "     lim - limit tests."
echo "     regression - loop over a collection of all tests."

exit 0
