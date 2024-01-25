#!/bin/sh
#
# Copyright (c) 2016 Intel Corporation.  All rights reserved.
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
# Test Suite to test uDAPL Providers and CCL Proxy on MICs and Hosts
#
# Sample Usage, all providers, one loop, fast: 
#
#    ./dtest_suite.sh -P ALL -l 1 -f
#

### --- user input section --- ###
server_list="cst-kc1 cst-kc1-mic0 cst-kc1-mic1"
client_list="cst-kc2 cst-kc2-mic0 cst-kc2-mic1 cst-kc1 cst-kc1-mic0 cst-kc1-mic1"
### ---  dtest test cases fine tune zone --- ###
# Note: value zero indicacte dtest will use the test default value
b_options="0 1 4096"
u_options="0 1"
w_options="0 1"
S_options="0 9"
B_options="0 1"
D_options="0 1"
W_options="0"
# test defaults
def_provider="ofa-v2-mlx4_0-1u"
dat_conf="/etc/dat.conf"
### --- End of user input section  --- ###

script_version="1.05"

# History log
# 1.05 - Disable data validation mode when using scif provider
#        From: Amir Hanania <amir.hanania@intel.com>
# 1.04 - Add data validation for dtest ping pong
#        Add option not to use CPU mask in performance test
#        From: Amir Hanania <amir.hanania@intel.com>
# 1.03 - Add dapl tests
#        From: Amir Hanania <amir.hanania@intel.com>
# 1.02 - Change performane test to use dtest -W case for latency.
#        Note: You must have a dtesr version that support -W to run performane test.
#        From: Amir Hanania <amir.hanania@intel.com>
# 1.01 - Add multi provider test
#        From: Amir Hanania <amir.hanania@intel.com>
# 1.00 - Initial Version 
#        From: Amir Hanania <amir.hanania@intel.com>
#        Test script to test dapl.
#	 Run dtest test in multiple options.
# Notes:
# 1. For performance test. Same dtest configuration is used twice.
#    Once with -W for latency and once without for BW.
#

user_provider=$def_provider
server_client_list=$server_list" "$client_list
host_list=`for i in $server_client_list; do echo $i | awk -F "-mic" '{ print $1 }'; done | sort | uniq`
provider_search_debug=0
dapl_test_user_input="y"
ran_one_dapltest=0
dapl_test_rep_max=100
dapl_test_rep=$dapl_test_rep_max
mfo_test=0
fast_test=0
fast_test_str=""
perf_test=0
no_inline_data=0
debug_info=0
v_for_test=""
user_string=""
ctrl_c=0
runs=0
max_run_time=0
dapl_mtu=0
loops=0
log_file_dir="dtest_perf_logs"
log_file="$log_file_dir/dtest_performance_"
unidirection_test=0
cpu_mask="no_cpu_mask"
user_b_options="none"
dog_file=/tmp/dog.log
dog_ser=/tmp/dog.ser
dog_cli=/tmp/dog.cli
pausing=1
i=1
while [ $i -lt 5000000 ]; do
  b_options_for_perf_test+=" $i"
  i=$(( $i*2 ))
done 
mkdir -p $log_file_dir

control_c()
# run if user hits control-c
{
        echo -en "\n*** ^c ***\n"
        if [ $ctrl_c -ne 0 ]; then
                echo -ne "\n*** Forced EXIT! ***\n\n"
                for s in $server_list; do
                  ssh root@$s "killall dtest" > /dev/null 2>&1
                  ssh root@$s "killall dapltest" > /dev/null 2>&1
                done
                for c in $client_list; do
                  ssh root@$c "killall dtest" > /dev/null 2>&1
                  ssh root@$c "killall dapltest" > /dev/null 2>&1
                done
                exit 1
        fi
        let "ctrl_c+=1"
        pausing=0
        echo -en "\n*** Will break after this test case ***\n\n"
}

# trap keyboard interrupt (control-c)
trap control_c SIGINT

exit_control()
{
  # if dog killed us. Clean up the dtest still working.
  for s in $server_list; do
    ssh root@$c "killall dtest" > /dev/null 2>&1
  done 
  for c in $client_list; do
    ssh root@$c "killall dtest" > /dev/null 2>&1
  done

  echo "2" > $dog_file
  sleep 2
  #kill dog
  # jobs -p | xargs kill
}
# trap exit to kill dog when script exit
#trap 'jobs -p | xargs kill' EXIT
trap exit_control EXIT

function dog(){
  while true; do
    val=`cat $dog_file`
    if [ $val -eq 2 ]; then
      exit
    fi
    if [ $val -eq 1 ]; then
      server=`cat $dog_ser`
      client=`cat $dog_cli`
      server_err=`ssh root@$server "cat /tmp/dtest_ser_run.log | grep -c ERR"`
      client_err=`ssh root@$client "cat /tmp/dtest_cli_run.log | grep -c ERR"`
      server_fail=`ssh root@$server "cat /tmp/dtest_ser_run.log | grep -c FAIL"`
      client_fail=`ssh root@$client "cat /tmp/dtest_cli_run.log | grep -c FAIL"`
      if [ $server_err -gt 0 ] || [ $client_err -gt 0 ] || [ $server_fail -gt 0 ] || [ $client_fail -gt 0 ]; then
        sleep 2
        echo -e "\n\n\twatchdog bark - validation test failed\n\n"
        killall ${0##*/}
      fi
      echo -n "." 
    fi
    sleep 1
  done
}

function wait_for_server_to_be_ready(){
  i=99
  echo -ne "Waiting to servers to come up... $i                                     \r"
  until [ $i -eq 0 ]; do
    up=0
    file_found="NOT found"
    ssh root@$server [ -f /tmp/dtest_ser_run.log ] && file_found="file found"
    if [ "$file_found" == "file found" ]; then
      up=`ssh root@$server "cat /tmp/dtest_ser_run.log | grep -c waiting"`
    fi
    if [ $up -eq 1 ]; then
           break;
    fi
    let "i = i - 1"
    echo -ne "Waiting to servers to come up... $i                                   \r"
    sleep 0.1
  done
}


u=0
w=0
B=0
b=0
S=0
D=0

function testcase(){
  # Setting the dtest options
  if [ $u -ne 0 ]; then
    u_for_test="-u"
  else
    u_for_test=""
  fi
  if [ $w -ne 0 ]; then
    w_for_test="-w"
  else
    w_for_test=""
  fi
  if [ $B -ne 0 ]; then
    B_for_test="-B $B"
  else
    B_for_test=""
  fi
  if [ $b -ne 0 ]; then
    b_for_test="-b $b"
  else
    b_for_test=""
  fi
  if [ $S -ne 0 ]; then
    S_for_test="-S $S"
  else
    S_for_test=""
  fi
  if [ $W -ne 0 ]; then
    W_for_test="-W"
  else
    W_for_test=""
  fi
  if [ $D -ne 0 ]; then
    if [ $do_not_validate_data_with_scif -eq 1 ]; then
      return 0
    fi
    D_for_test="-D -a -B 10"
  else
    D_for_test=""
  fi

  if [ $ctrl_c -ne 0 ]; then
    echo -ne "\n*** Stop test due to ctrl c ***\n\n"
    exit 1
  fi

  # in case the prev test failed. The files will be still there for debug. Delete them for the new run.
  ssh root@$server "rm /tmp/dtest_ser_run.log" > /dev/null 2>&1
  ssh root@$client "rm /tmp/dtest_cli_run.log" > /dev/null 2>&1

  if [ $D -eq 1 ]; then
    support_data_validation
    if [ $dtest_support_data_val -ne 1 ]; then
      return
    fi
  fi

  #Start the server
  echo "----------------------------------------------------------"
  echo "Test case: $W_for_test $D_for_test $u_for_test $w_for_test $B_for_test $b_for_test $S_for_test $v_for_test $user_string"
  echo -ne "Start $taskset_4_server dtest -P $provider server $server\r"
  ssh root@$server "$export_str $taskset_4_server dtest -P $provider $W_for_test $u_for_test $w_for_test $B_for_test $b_for_test $S_for_test $v_for_test $user_string $D_for_test >& /tmp/dtest_ser_run.log" &
  ser_pid=$!

  # Wait for server to be ready
  wait_for_server_to_be_ready

  if [ $i -eq 0 ]; then
    echo $server dtest failed - did not start
    ssh root@$server "killall dtest"
    ssh root@$client "killall dtest"
    exit 1
  fi

  # Start client
  echo -ne "Start $taskset_4_client dtest -P $provider client                                                                \r"
  ssh root@$client "$export_str $taskset_4_client dtest -P $provider -h $server $W_for_test $u_for_test $w_for_test $B_for_test $b_for_test $S_for_test $v_for_test $user_string $D_for_test >& /tmp/dtest_cli_run.log" &
  cli_pid=$!

  if [ $D -eq 1 ]; then
    echo $server > $dog_ser
    echo $client > $dog_cli
    echo "1" > $dog_file
  fi

  # Wait for Server and Client to be done
  wait $ser_pid $cli_pid

  if [ $D -eq 1 ]; then
    echo "0" > $dog_file
  fi

  # Check results from log files
  server_pass=`ssh root@$server "cat /tmp/dtest_ser_run.log | grep -c PASSED"`
  client_pass=`ssh root@$client "cat /tmp/dtest_cli_run.log | grep -c PASSED"`
  server_err=`ssh root@$server "cat /tmp/dtest_ser_run.log | grep -c ERR"`
  client_err=`ssh root@$client "cat /tmp/dtest_cli_run.log | grep -c ERR"`
  do_exit=0
  if [ $ctrl_c -ne 0 ]; then
    ssh root@$server "killall -9 dtest" > /dev/null 2>&1
    ssh root@$client "killall -9 dtest" > /dev/null 2>&1
    do_exit=1
  fi

  if [ $server_pass -ne 1 ] || [ $server_err -ne 0 ]; then
    echo "****** ERROR - $server server failed (with $client client) *******"
    echo "               log file:  /tmp/dtest_ser_run.log on $server"
    do_exit=1
  fi

  if [ $client_pass -ne 1 ] || [ $client_err -ne 0 ]; then
    echo "****** ERROR - $client client failed (with $server server) *******"
    echo "               log file: /tmp/dtest_cli_run.log on $client"
    do_exit=1
  fi

  if [ $do_exit -eq 1 ]; then
    echo
    exit 1
  fi

  # Print to screen or file the results if needed
  if [ $perf_test -eq 1 ]; then
    echo -ne "                                                                                                             \r"
    if [ $fast_test -eq 1 ]; then
      if [ $W -ne 0 ]; then
        # second run is latency test called with -W
        lat=`ssh root@$client cat /tmp/dtest_cli_run.log | grep PingPong | awk -F "latency " '{print $2}' | awk -F " us" '{ print $1 }'`
        res="$lat, Tx size=$res"
        echo "latency: $res"
        echo $res >> $log_file
      else
        # First test for BW
        res=`ssh root@$client cat /tmp/dtest_cli_run.log | grep direction | awk -F "00 x " '{ print $2 }'`
      fi
    else
      if [ $W -ne 0 ]; then
        # second run is latency test called with -W
        lat=`ssh root@$client cat /tmp/dtest_cli_run.log | grep PingPong | awk -F "latency " '{print $2}' | awk -F " us" '{ print $1 }'`
        echo -e "Byte size: $b\t\tlatency: $lat\t\tBW: $res"
        res=`echo $res | awk -F " MB" '{ print $1 }'`
        res=$(printf "%15s" $res)
        lat=$(printf "%10s" $lat)
        echo -e "$b\t\t$lat\t\t$res" >> $log_file
      else
        # First test for BW
        res=`ssh root@$client cat /tmp/dtest_cli_run.log | grep direction | awk -F "00 x $b, " '{ print $2 }'`
      fi
    fi
  fi
  ssh root@$server "rm /tmp/dtest_ser_run.log"
  ssh root@$client "rm /tmp/dtest_cli_run.log"

  echo "Test case passed                               "

  read  -t 0.01 -n 1 -s u_input
  ret=$?
  if [ $ret -eq 0 ] && [ "$u_input" == "p" ]; then
    pause_test
  fi
  if [ $ret -eq 0 ] && [ "$u_input" == "i" ]; then
    print_round_info
  fi

  return 0
}


function wait_for_it(){
  max_wait=900
  i=$max_wait
  sleep_for=0.1
  test_start_time=`date +%s`
  until [ $i -eq 0 ]; do
    echo -n "."
    sleep $sleep_for
    up=`ssh root@$wait_for_it_machine cat $wait_for_it_file | grep -c "$wait_for_it_string"`
    if [ $up -eq 1 ]; then
      break;
    fi
    let "i = i - 1"
    if [ $ctrl_c -ne 0 ]; then
      i=0
    fi
    if [ $i -eq $(( $max_wait - 20 )) ]; then
      sleep_for=1
    fi
    if [ $i -eq $(( $max_wait - 40 )) ]; then
      sleep_for=3
    fi
  done

  if [ $i -eq 0 ]; then
    if [ $ctrl_c -ne 0 ]; then
      echo -ne "\n\t*** Stop test due to ctrl c ***\n\n"
    else 
      echo " failed"
      echo -e "\n\n\tDid not find $wait_for_it_string string on machine: $wait_for_it_machine at file $wait_for_it_file - EXIT\n\n"
    fi
    ssh root@$server killall dapltest > /dev/null 2>&1
    ssh root@$client killall dapltest > /dev/null 2>&1
    exit
  fi
  test_end_time=`date +%s`
  test_run_time=$(($test_end_time-$test_start_time))
  echo " done in $test_run_time sec"
}

function pause_test(){
  echo -ne "Pausing - Press p to continue - "
  while [ $pausing -eq 1 ]; do
    echo -ne "P" 
    read  -t 0.01 -n 1 -s u_input
    ret=$?
    if [ $ret -eq 0 ] && [ "$u_input" == "p" ]; then
      echo
      break
    fi
    sleep 5
  done
}

function print_round_info(){
  now=`date +%s`
  run_time=$(($now-$start_time))
  ss=$(($run_time%60))
  mm=$(($run_time/60))
  mm=$(($mm%60))
  hh=$(($run_time/3600))
  echo "**************************************************************"
  echo -e "\tin round $runs - $hh h $mm m $ss s"
  echo "**************************************************************"
}


# Check if client and server dtest support data validation 
function support_data_validation() {
  dtest_support_data_val=0
  
  ssh root@$server "dtest -U >& /tmp/dtest_ser_run.log"
  ssh root@$client "dtest -U >& /tmp/dtest_cli_run.log"
  sleep .1
  ser_is_valid=`ssh root@$server cat /tmp/dtest_ser_run.log | grep -c "validate data"`
  if [ $ser_is_valid -ne 1 ]; then
    return 0
  fi
  cli_is_valid=`ssh root@$client cat /tmp/dtest_cli_run.log | grep -c "validate data"`
  if [ $cli_is_valid -ne 1 ]; then
    return 0
  fi
  dtest_support_data_val=1
}


# Run dtest in all data size ping pong test with data validation mode between client and server
function server_client_data_validation_test(){

  echo -e "\n\n\n\t**** dtest data validation test\t\tprovider: $provider\t\tserver: $server $taskset_4_server\t\tclient: $client $taskset_4_client ****\n"
  support_data_validation
  if [ $dtest_support_data_val -ne 1 ]; then
    echo -e "\t**** $client or $server dtest does not support data validation - skipping ****"
    return
  fi

  echo -e "        Start $taskset_4_server dtest -P $provider -D -a on server $server"
  ssh root@$server "$export_str $taskset_4_server dtest -P $provider -D -a -B 100 >& /tmp/dtest_ser_run.log" &
  ser_pid=$!
  wait_for_server_to_be_ready

  echo -e "        Start $taskset_4_client dtest -P $provider -D -a on client $client"
  ssh root@$client "$export_str $taskset_4_client dtest -P $provider -h $server -D -a -B 100 >& /tmp/dtest_cli_run.log" &
  cli_pid=$!
  # just wait a bit for files on server and clien be ready before waking up the dog
  sleep 1

  echo $server > $dog_ser
  echo $client > $dog_cli
  echo "1" > $dog_file

  # Wait for Server and Client to be done
  wait $ser_pid $cli_pid

  echo "0" > $dog_file
  echo
  # Check results from log files
  server_pass=`ssh root@$server "cat /tmp/dtest_ser_run.log | grep -c PASSED"`
  client_pass=`ssh root@$client "cat /tmp/dtest_cli_run.log | grep -c PASSED"`
  server_err=`ssh root@$server "cat /tmp/dtest_ser_run.log | grep -c ERR"`
  client_err=`ssh root@$client "cat /tmp/dtest_cli_run.log | grep -c ERR"`
  do_exit=0
  if [ $ctrl_c -ne 0 ]; then
    ssh root@$server "killall -9 dtest" > /dev/null 2>&1
    ssh root@$client "killall -9 dtest" > /dev/null 2>&1
    do_exit=1
  fi

  if [ $server_pass -ne 1 ] || [ $server_err -ne 0 ]; then
    echo "****** ERROR - $server server failed (with $client client) *******"
    echo "               log file:  /tmp/dtest_ser_run.log on $server"
    do_exit=1
  fi

  if [ $client_pass -ne 1 ] || [ $client_err -ne 0 ]; then
    echo "****** ERROR - $client client failed (with $server server) *******"
    echo "               log file: /tmp/dtest_cli_run.log on $client"
    do_exit=1
  fi

  if [ $do_exit -eq 1 ]; then
    echo
    exit 1
  fi

  echo -e "\n\tdtest data validation test\t\tserver: $server\t\tclient: $client\t\tprovider: $provider\t\tTEST PASSED\n\n"

}


# Run dapltest between client and server
function server_client_dapl_test(){
  ofa_post=""
  dapl_test_rep=$dapl_test_rep_max
  if [ $ctrl_c -ne 0 ]; then
    echo -ne "\n*** Stop test due to ctrl c ***\n\n"
    exit 1
  fi

  echo "----------------------------------------------------------"
  echo -ne "\t**** dapltest\t\tprovider: $provider\t\tserver: $server\t\tclient: $client "

  # in case the prev test failed. The files will be still there for debug. Delete them for the new run.
  ssh root@$server "rm /tmp/dapltest_ser_run.log" > /dev/null 2>&1
  ssh root@$client "rm /tmp/dapltest_cli_run.log" > /dev/null 2>&1

  # 1. skip if roc
  # 2. check that provider is ofa or scm
  is_roe=`echo $provider | grep -c roe`
  if [ $is_roe -eq 1 ]; then
    good_provider_for_dapltest=0
    echo -e " - provider $provider not supported - skipping ****"
    echo "----------------------------------------------------------"
    return 0
  fi
  is_ofa=`ssh root@$server cat $dat_conf | grep $provider | grep -c libdaplofa`
  is_scm=`ssh root@$server cat $dat_conf | grep $provider | grep -c libdaploscm`
  if [ $is_ofa -eq 0 ] && [ $is_scm -eq 0 ]; then
    good_provider_for_dapltest=0
    echo -e " - provider $provider not supported - skipping ****"
    echo "----------------------------------------------------------"
    return 0
  fi
  if [ $is_ofa -eq 1 ]; then
    dat_line=`ssh root@$server cat $dat_conf | grep $provider`
    ofa_post=`echo $dat_line | grep lofa | awk '{ print $1 }' | awk -F "ofa-v2" '{ print $2 }'`
  fi
  ran_one_dapltest=1

  # start server
  wait_for_it_machine=$server
  wait_for_it_file="/tmp/dapltest_ser_run.log"
  wait_for_it_string="Dapltest: Service Point Ready"
  echo -e " ****\n----------------------------------------------------------"
  echo -e "dapltest\tprovider: $provider\tserver: $server\tclient: $client"
  echo -ne "start dapltest server..."
  ssh root@$server "dapltest -T S -D $provider >& /tmp/dapltest_ser_run.log" &
  wait_for_it

  # tests
  wait_for_it_machine=$client
  wait_for_it_file="/tmp/dapltest_cli_run.log"
  wait_for_it_string="Total WQE"
  # test 1
  echo -ne "start dapltest client test 1 ..."
  ssh root@$client "dapltest -T T -s $server$ofa_post -D $provider -i $dapl_test_rep -t 1 -w 1 client SR 256 server SR 256 >& /tmp/dapltest_cli_run.log" &
  wait_for_it

  if [ $fast_test -eq 0 ]; then
    # test 2
    if [ $dapl_test_rep -ne 1 ] && [ $test_run_time -ge 4 ]; then
      dapl_test_rep=$(($dapl_test_rep/$test_run_time/8))
      if [ $dapl_test_rep -eq 0 ]; then
        dapl_test_rep=1
      fi
      echo Reduce rep to $dapl_test_rep
    fi
    echo -ne "start dapltest client test 2 ..."
    ssh root@$client "rm /tmp/dapltest_cli_run.log" > /dev/null 2>&1
    ssh root@$client "dapltest -T T -s $server$ofa_post -D $provider -i $dapl_test_rep -t 1 -w 1 client SR 256 server RW 4096 server SR 256 >& /tmp/dapltest_cli_run.log" &
    wait_for_it

    # test 3
    echo -ne "start dapltest client test 3 ..."
    ssh root@$client "rm /tmp/dapltest_cli_run.log" > /dev/null 2>&1
    ssh root@$client "dapltest -T T -s $server$ofa_post -D $provider -i $dapl_test_rep -t 1 -w 1 client SR 256 server RR 4096 server SR 256 >& /tmp/dapltest_cli_run.log" &
    wait_for_it

    # test 4
    echo -ne "start dapltest client test 4 ..."
    ssh root@$client "rm /tmp/dapltest_cli_run.log" > /dev/null 2>&1
    ssh root@$client "dapltest -T T -s  $server$ofa_post -D $provider -i $dapl_test_rep -t 1 -w 1 client SR 256 server RW 4096 server SR 256 client SR 256 server RW 4096 server SR 256 client SR 4096 server SR 256 >& /tmp/dapltest_cli_run.log" &
    wait_for_it

    # test 5
    if [ $dapl_test_rep -ne 1 ] && [ $test_run_time -ge 2 ]; then
      dapl_test_rep=$(($dapl_test_rep/8))
      if [ $dapl_test_rep -eq 0 ]; then
        dapl_test_rep=1
      fi
      echo Reduce rep to $dapl_test_rep
    fi
    echo -ne "start dapltest client test 5 ..."
    ssh root@$client "rm /tmp/dapltest_cli_run.log" > /dev/null 2>&1
    ssh root@$client "dapltest -T T -s $server$ofa_post -D $provider -i $dapl_test_rep -t 1 -w 8 client SR 256 server RW 4096 server SR 256 client SR 256 server RW 4096 server SR 256 client SR 4096 server SR 256 >& /tmp/dapltest_cli_run.log" &
    wait_for_it

    if [ $dapl_test_rep -ne 1 ] && [ $test_run_time -ge 2 ]; then
      dapl_test_rep=$(($dapl_test_rep/4))
      if [ $dapl_test_rep -eq 0 ]; then
        dapl_test_rep=1
      fi
      echo Reduce rep to $dapl_test_rep
    fi
    # test 6
    echo -ne "start dapltest client test 6 ..."
    ssh root@$client "rm /tmp/dapltest_cli_run.log" > /dev/null 2>&1
    ssh root@$client "dapltest -T T -s $server$ofa_post -D $provider -i $dapl_test_rep -t 4 -w 8 client SR 256 server RW 4096 server SR 256 client SR 256 server RW 4096 server SR 256 client SR 4096 server SR 256 >& /tmp/dapltest_cli_run.log" &
    wait_for_it
  fi

  # stop server
  echo -n "stop dapltest server..."
  ssh root@$client "rm /tmp/dapltest_cli_run.log" > /dev/null 2>&1
  ssh root@$client "dapltest -T Q -s $server$ofa_post -D $provider >& /tmp/dapltest_cli_run.log" &
  cli_pid=$!

  wait_for_it_machine=$server
  wait_for_it_file="/tmp/dapltest_ser_run.log"
  wait_for_it_string="Exiting"
  echo -n "wait for dapltest server to stop..."
  wait_for_it

  # Wait for Server and Client to be done
  wait $cli_pid

  # clean up
  ssh root@$server "rm /tmp/dapltest_ser_run.log" > /dev/null 2>&1
  ssh root@$client "rm /tmp/dapltest_cli_run.log" > /dev/null 2>&1

  echo -e "\tdapltest\t\tserver: $server\t\tclient: $client\t\tprovider: $provider\t\tTESTS PASSED"
  echo -e "----------------------------------------------------------\n"
}


# Run all the test cases between two machines.
function server_host_test(){
  taskset_4_server=""
  taskset_4_client=""
  if [ $perf_test -eq 1 ]; then
    is_mic=`echo $server | grep -c mic`
    if [ $is_mic -eq 0 ] && [ "$cpu_mask" != "no_cpu_mask" ]; then
      taskset_4_server="taskset $cpu_mask "
    fi
    is_mic=`echo $client | grep -c mic`
    if [ $is_mic -eq 0 ] && [ "$cpu_mask" != "no_cpu_mask" ]; then
      taskset_4_client="taskset $cpu_mask "
    fi

    echo -e "\n**** dtest: provider: $provider      \tserver: $server \tclient: $client ****\n"  >> $log_file
    if [ $fast_test -eq 0 ]; then
      echo -e "\nBytes\t\t   Latency\t\t\t MB/s"  >> $log_file
    fi
  fi

  if [ "$dapl_test_user_input" != "o" ]; then
    echo -e "\n\n\n\t**** dtest\t\tprovider: $provider\t\tserver: $server $taskset_4_server\t\tclient: $client $taskset_4_client ****"

    #set var value to zero in order to use dtest default value for that option.
    for u in $u_options; do
      for w in $w_options; do
        for b in $b_options; do
          for S in $S_options; do
            for B in $B_options; do
              for D in $D_options; do
                for W in $W_options; do # Always keep last. See Note 1.
                  # Run one test case between Client and Server.
                  testcase
                  ret=$?
                  if [ $ret -ne 0 ]; then
                    echo TEST FAILED
                    exit 1
                  fi
                  sleep 1
                done
              done
            done
          done
        done
      done
    done

    echo -e "\n\tdtest\t\tserver: $server\t\tclient: $client\t\tprovider: $provider\t\tTEST PASSED\n\n"

    if [ $perf_test -ne 1 ] && [ $do_not_validate_data_with_scif -eq 0 ] && [ $fast_test -ne 1 ]; then
      server_client_data_validation_test
    fi
  fi

  if [ "$dapl_test_user_input" != "n" ] && [ $good_provider_for_dapltest -eq 1 ] && [ $fast_test -ne 1 ]; then
    server_client_dapl_test
  fi

}

function help(){
  echo -e "\n\tRun dtest and dapltest accross cluster - from each client to each server\n"
  echo -e "\t\tServer list: $server_list"
  echo -e "\t\tClient list: $client_list\n"
  echo -e "\t-P <PROVIDER NAME> : Provider name or 'ALL' for all prividers (default $def_provider)"
  echo -e "\t-f: Fast test"
  echo -e "\t-l <NUM> : How many test loops to run. Def forever"
  echo -e "\t-t <NUM> : How many minutes to run. Def forever"
  echo -e "\t-p <CPUs mask> or \"no_cpu_mask\": Performance test"
  echo -e "\t\tMask in 0xHEX format. should match host's /sys/class/mic/mic0/device/local_cpus"
  echo -e "\t\tFor no CPU mask enter \"no_cpu_mask\""
  echo -e "\t\tConsider also: taskset mpxyd, set mcm_affinity to 2 in /etc/mpxyd.conf, performance mode at the host scaling_governor"
  echo -e "\t\tConsider also to change DAPL MTU (-M optoin)"
  echo -e "\t-w: Write only test"
  echo -e "\t-u: uni-direction only test"
  echo -e "\t-d <n|y|o> : dapl test options. \"n\": No dapl tests. \"y\": Run dapl tests. \"o\": Run Only dapl tests (no dtest). Def: Run dapl_test"
  echo -e "\t-M <NUM> : DAPL MTU"
  echo -e "\t-b <NUM> : data size. Can be: one size, many sizes as a string or type \`all\` for all sizes power of 2"
  echo -e "\t-U: \"user string\". user dtest option string ( -w -b -u and -S dtest options )"
  echo -e "\t-z: use zero for -w -b -u and -S dtest options (zero mean test default value)"
  echo -e "\t-i: No inline data test"
  echo -e "\t-m: Force MFO test"
  echo -e "\t-D: DAPL debug print in log files"
  echo -e "\t-v: dtest verbose mode"
  echo -e "\t-q: qib test over mlx4 (same as -m and -i options)"
  echo -e "\t-V: Print the script version"
  echo -e "\t-h: help"
  echo -e "\n\tWhile test is running:"
  echo -e "\t^c: Exit gracefully"
  echo -e "\t^c^c: Forced exit"
  echo -e "\ti: Print round number and time duration"
  echo -e "\n\n"
  exit 1
}


function log(){
  if [ $provider_search_debug -eq 1 ]; then  
    echo -e "$@"
  else
    echo -n "."
  fi
}


function providers_search(){ 
  echo -e "\nSearching for devices"
  first_host=1
  for host in $host_list; do
    # make sure host dat file exist
    dat_conf_found="NOT found"
    ssh root@$host "[ -f $dat_conf ]" && dat_conf_found="dat_conf_found"
    if [ "$dat_conf_found" == "dat_conf_found" ]; then
      log "$dat_conf found on $host"
    else
      echo -e "\n\t$dat_conf was not found on $host.\n\n"
      exit 1
    fi

    #ib devices list
    dev_list=`ssh root@$host ibv_devices | tail -n +3 | awk '{ print $1 }'`
    for dev in $dev_list; do
      # for each device
      log Found $dev device
      port_cnt=`ssh root@$host ibv_devinfo -d $dev | grep phys_port_cnt | awk '{print$2 }'`
      log "  $dev phys_port_cnt: $port_cnt"
      for port in $(seq 1 $port_cnt); do
        # for each post
        log "    checking $dev port $port status"
        up=`ssh root@$host ibv_devinfo -d $dev -i $port | grep state | grep -c PORT_ACTIVE`
        if [ $up -ne 1 ]; then
          log "    $dev port $i is not active"
          continue
        fi
        log "    $dev port $port is active"
        log "    add it to the list"
        # get a list of providers that this device can use
        providers+=`ssh root@$host cat $dat_conf | grep "$dev $port" | awk '{ print $1 }'`
        providers+=" "
      done 
    done

    #add network ib devices
    net_dev_list=` ssh root@$host netstat -i | grep -v "no statistics available" | tail -n +3 | awk '{ print $1 }'`
    for net_dev in $net_dev_list; do
      # for each net device
      log Found $net_dev net device
      is_ib=`ssh root@$host ip addr show $net_dev | grep -c infiniband`
      if [ $is_ib -ne 1 ]; then
        log "  $net_dev net device is not ib device"
        continue
      fi
      log "    $net_dev is infiniband device"
      has_ip_addr=`ssh root@$host ip addr show $net_dev | grep inet | grep -vc inet6`
      if [ $has_ip_addr -ne 1 ]; then
        log "  $net_dev net device has no ip addr"
        continue
      fi
      log "    $net_dev net device has IP address"
      log "    add it to the list"
      # get a list of providers that this device can use
      providers+=`ssh root@$host cat $dat_conf | grep "$net_dev 0" | awk '{ print $1 }'`
      providers+=" "
    done

    log; log -n "$host povider list: "; for i in $providers; do log -n "$i "; done; log
    if [ $first_host -eq 1 ]; then
      # just save providers from first host
      hosts_providers_list=$providers
      first_host=0
    else
      # Merge providers from prev hosts with the one from the new host
      # Keep only the providers that are on both lists
      log hosts p from prev hosts: $hosts_providers_list
      hosts_providers_list+=$providers
      hosts_providers_list=`for p in $hosts_providers_list; do echo $p; done | sort | uniq -d`
      log hosts p after merge: $hosts_providers_list
    fi 
    providers=""
  done
  cnt=0
  echo -e "\nPovider list:"
  for i in $hosts_providers_list; do
    echo $i
    let cnt+=1
  done
  if [ $cnt -eq 0 ]; then
    echo -e "no devices where found\n\n"
    exit
  fi
  echo -e "Total $cnt providers\n\n"
}


# check if the "server-client-provider" combination is OK
# Set server_client_provider_is_not_valid_combo to one if not a valid combo
function check_provider_server_client_combo(){
  server_client_provider_is_not_valid_combo=0
  #check the following:
  # 1. scif providers can only run on the same machine.
  is_scif=`echo $provider | grep -c scif`
  if [ $is_scif -eq 1 ]; then
    server_host=`echo $server | awk -F "-mic" '{ print $1 }'`
    client_host=`echo $client | awk -F "-mic" '{ print $1 }'`
    if [ $server_host == $client_host ]; then
      return
    else
      server_client_provider_is_not_valid_combo=1
      return
    fi
  fi
  # 2. MIC qib can only run mcm provider
  is_ser_mic=`echo $server | grep -c mic`
  is_cli_mic=`echo $client | grep -c mic`
  if [ $is_ser_mic -eq 1 ] || [ $is_cli_mic -eq 1 ]; then
    # MIC Server or Client
    is_qib_provider=`echo $provider | grep -c qib`
    if [ $is_qib_provider -eq 1 ]; then
      # Server or Client is MIC AND qib provider - make sure provider is MCM
      is_mcm=`echo $provider | grep -c m`
      if [ $is_mcm -eq 1 ]; then
        return
      else
        server_client_provider_is_not_valid_combo=1
        return
      fi
    fi
  fi
  # 3. check if MICs ib interface is UP
  is_ib_provider=`echo $provider | grep -ce -ib`
  if [ $is_ib_provider -eq 1 ]; then
    interface=`echo $provider | awk -F "ofa-v2-" '{ print $2 }'`
    if [ $is_ser_mic -eq 1 ]; then
      up=`ssh root@$server ifconfig | grep -c $interface`
      if [ $up -eq 1 ]; then
        return
      else
        server_client_provider_is_not_valid_combo=1
        return
      fi
    fi
    if [ $is_cli_mic -eq 1 ]; then
      up=`ssh root@$client ifconfig | grep -c $interface`
      if [ $up -eq 1 ]; then
        return
      else
        server_client_provider_is_not_valid_combo=1
        return
      fi
    fi
  fi
}






while getopts uviVzDmfwhiql:t:P:U:p:d:M:b: option
do
  case "${option}"
  in
  P) user_provider=${OPTARG};;
  m) no_inline_data=1 ; mfo_test=1;;
  f) fast_test=1; loops=1; fast_test_str=" fast test";;
  p) cpu_mask=${OPTARG}; perf_test=1; W_options="0 1";;
  U) user_string=${OPTARG}; b_options="0"; u_options="0"; S_options="0"; w_options="0"; B_options="0";;
  z) b_options="0"; u_options="0"; S_options="0"; w_options="0"; B_options="0";;
  w) w_options="1";;
  u) unidirection_test=1; u_options="1";;
  D) debug_info=1;;
  d) dapl_test_user_input=${OPTARG};;
  v) v_for_test=" -v ";;
  i) no_inline_data=1;;
  q) no_inline_data=1 ; mfo_test=1;;
  t) max_run_time=${OPTARG};;
  M) dapl_mtu=${OPTARG};;
  l) loops=${OPTARG};;
  b) user_b_options=${OPTARG};;
  V) echo -e "\n\t${0##*/} version $script_version\n\n"; exit;;
  h) help;;
  esac
done

if [ $fast_test -eq 1 ]; then
  b_options="0"; u_options="0"; S_options="0"; w_options="0"; B_options="0"; D_options="0";
fi

if [ $perf_test -eq 1 ]; then
  b_options=$b_options_for_perf_test; u_options="0"; S_options="0"; loops=1; w_options="1"; B_options="0"; user_string="$user_string -p";dapl_test_user_input="n"; D_options="0";
  legit_input=`echo $cpu_mask | grep -ci 0x`
  if [ $legit_input -ne 1 ] && [ "$cpu_mask" != "no_cpu_mask" ]; then
    echo -e "\n\t< 0xCPUs_mask > or \"no_cpu_mask\" in option -p is missing - input=$cpu_mask - Exit\n\n"
    exit
  fi
fi

if [ $fast_test -eq 1 ] && [ $perf_test -eq 1 ]; then
  b_options="0"
fi

if [ $unidirection_test -eq 1 ]; then
  u_options="1"
fi

if [ "$user_b_options" != "none" ]; then
  if [ "$user_b_options" == "all" ]; then
      b_options=$b_options_for_perf_test
  else
    b_options="$user_b_options"
  fi
fi

if [ "$dapl_test_user_input" != "n" ] && [ "$dapl_test_user_input" != "y" ] && [ "$dapl_test_user_input" != "o" ]; then
  echo -e "\n\tdapl test option must be n/y/o - Exit\n\n"
  exit
fi

# check mpxyd is running on host machines.
for host in $host_list; do
  up=`ssh root@$host "ps ax | grep -c mpxyd"`
  if [ $up -ne 3 ]; then
    echo -e "\n\tERROR - mpxyd is not running on $host\n\n"
         exit
  fi
  if [ $no_inline_data -eq 1 ]; then
    up=`ssh root@$host cat /var/log/mpxyd.log | grep -c "RDMA IB inline threshold 0"`
    if [ $up -ne 1 ]; then
      echo on host $host you need to run mpxyd with mcm_ib_inline 0 in /etc/mpxyd.conf file for no inline data test
      exit 1
    fi
  fi
done

if [ $user_provider == "ALL" ] || [ $user_provider == "all" ]; then
  providers_search
else
  hosts_providers_list=$user_provider
fi

echo -e "\nServer list: $server_list"
echo -e "Client list: $client_list"
echo -e "Host list:"
for i in $host_list; do
  echo $i
done
echo

if [ $mfo_test -eq 1 ]; then
  export_str="export DAPL_MAX_INLINE=0 ; export DAPL_MCM_MFO=1 ; "
  echo -ne "\n\t\t**** Running MFO test case \t\t$export_str ****\n\n"
elif [ $no_inline_data -eq 1 ]; then
  export_str="export DAPL_MAX_INLINE=0 ; "
  echo -ne "\n\t\t**** Running no inline data test case \t\t$export_str ****\n\n"
else
  export_str=""
fi

if [ $debug_info -eq 1 ]; then
  export_str="$export_str export DAPL_DBG_TYPE=0xffffffff ; "
  echo -ne "\n\t\t**** Running in debug mode\t\texport value: $export_str ****\n\n"
fi
if [ $dapl_mtu -ne 0 ]; then
  export_str="$export_str export DAPL_IB_MTU=$dapl_mtu ; "
  echo -ne "\n\t\t**** Setting DAPL_IB_MTU to $dapl_mtu \t\texport value: $export_str ****\n\n"
fi

if [ $loops -ne 0 ]; then
  echo -e "\n\tRunning$fast_test_str for $loops iterations"
fi

if [ $max_run_time -ne 0 ]; then
  echo -e "\n\tRunning$fast_test_str for $max_run_time minutes"
fi

if [ $loops -eq 0 ] && [ $max_run_time -eq 0 ]; then
  echo -ne "\n\tRunning$fast_test_str forever\n\n"
fi

if [ $perf_test -eq 1 ]; then
  if [ $unidirection_test -eq 1 ]; then
    log_file+="unidirection_test-"
  else
    log_file+="bidirection_test-"
  fi
  log_file+=`date +%F-%H-%M-%S`
  echo -e "\n\tRunning performance test with cpu mask: $cpu_mask\n\tOutput file: $log_file"
  echo "Server list: $server_list" > $log_file
  echo "Client list: $client_list" >> $log_file
  echo "CPU mask: $cpu_mask" >> $log_file
  if [ $dapl_mtu -ne 0 ]; then
    echo "DAPL_IB_MTU: $dapl_mtu" >> $log_file
  else
    echo "DAPL_IB_MTU: Default value" >> $log_file
  fi
  if [ $unidirection_test -eq 1 ]; then
    echo "Test type: unidirection test" >> $log_file
  else
    echo "Test type:bidirection test" >> $log_file
  fi
  for host in $host_list; do
    op_poll=`ssh root@$host cat /var/log/mpxyd.log | grep -c "OP thread polling enabled"`
    if [ $op_poll -ne 1 ]; then
      echo "OP thread polling on $host: disabled" >> $log_file
      echo -e "\tOP thread polling on $host: disabled"
    else
      echo "OP thread polling on $host: enabled" >> $log_file
      echo -e "\tOP thread polling on $host: enabled"
    fi    
  done
  echo -e "\n\n"
fi
echo "0" > $dog_file
dog &

sleep 1
start_time=`date +%s`

while [ 1 ]; do
  now=`date +%s`
  run_time=$(($now-$start_time))
  ss=$(($run_time%60))
  mm=$(($run_time/60))
  total_run_time_in_min=$mm
  mm=$(($mm%60))
  hh=$(($run_time/3600))
  dd=$(($hh/24))
  hh=$(($hh%24))
  pp=$(printf "%d days %d hours %d min and %d sec" $dd $hh $mm $ss)

  echo
  echo
  echo "**************************************************************"
  echo "**************************************************************"
  echo Run time: $pp
  if [ $max_run_time -ne 0  ] && [ $total_run_time_in_min -ge $max_run_time ]; then
    echo -e "Ran for the $max_run_time minute requested by the user - Exiting\n\n"
    break;
  fi
  if [ $loops -ne 0  ] && [ $runs -eq $loops ]; then
    echo -e "Ran for the $loops iterations requested by the user - Exiting\n\n"
    break;
  fi
  runs=$(( $runs + 1 ))
  echo Starting round $runs
  date
  echo "**************************************************************"
  echo "**************************************************************"
  echo

  # Runinng
  for provider in $hosts_providers_list; do
    do_not_validate_data_with_scif=`echo $provider | grep -c scif`
    good_provider_for_dapltest=1
    for server in $server_list; do
      for client in $client_list; do
        check_provider_server_client_combo
        if [ $server_client_provider_is_not_valid_combo -ne 0 ]; then
          #echo -e "***** ***** skipping test case: Server:$server Client:$client provider:$provider ***** *****"
          continue
        fi
        # Run all test cases between Client and Server.
        server_host_test
      done
    done

  if [ "$dapl_test_user_input" == "o" ] && [ $ran_one_dapltest -eq 0 ]; then
    echo -e "\n\n\n\n\t\t***** ***** WARNING: only dapltest was set up but no dapltest was done with $provider provider $export_str ***** *****\n\n"
  else
    echo -e "\n\n\n\n\t\t***** ***** server client tests with $provider provider $export_str - TEST PASSED ***** *****\n\n"
  fi
  done
done
