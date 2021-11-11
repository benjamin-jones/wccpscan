#!/bin/bash

while read cip;
do
  echo "Trying $cip..." | tee -a wccp_enum_list.txt
  ./wccpenum.py -s $1 -t $cip 2>/dev/null | egrep "VALID SERVICE ID" | tee -a wccp_enum_list.txt 
  sleep 10
done < ip_list.txt
