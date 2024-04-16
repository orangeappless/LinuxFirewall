#!/bin/bash

EXTERNAL_ADDRESS="192.168.1.80"
INTERNAL_HOST_INTERNAL_ADDRESS="192.168.10.2"

OUTPUT="test_fw_results.txt"

#1: Drop invalid TCP port
echo "Test Case #1: Drop invalid TCP port" 2>&1 | tee -a $OUTPUT
echo "This SHOULD show packet loss" 2>&1 | tee -a $OUTPUT
hping3 -c 5 $EXTERNAL_ADDRESS -S -p 333 2>&1 | tee -a $OUTPUT
echo "" 2>&1 | tee -a $OUTPUT
echo "============================================================================================================================" 2>&1 | tee -a $OUTPUT
echo "" 2>&1 | tee -a $OUTPUT

#2: Accept valid TCP port
echo "Test Case #2: Accept valid TCP port" 2>&1 | tee -a $OUTPUT
echo "This SHOULD NOT show packet loss" 2>&1 | tee -a $OUTPUT
hping3 -c 5 $EXTERNAL_ADDRESS -S -p 80 2>&1 | tee -a $OUTPUT
echo "" 2>&1 | tee -a $OUTPUT
echo "============================================================================================================================" 2>&1 | tee -a $OUTPUT
echo "" 2>&1 | tee -a $OUTPUT

#3: Drop invalid UDP port
echo "Test Case #3: Drop invalid UDP port" 2>&1 | tee -a $OUTPUT
echo "This SHOULD show packet loss" 2>&1 | tee -a $OUTPUT
hping3 -c 5 $EXTERNAL_ADDRESS -2 -p 333 2>&1 | tee -a $OUTPUT
echo "" 2>&1 | tee -a $OUTPUT
echo "============================================================================================================================" 2>&1 | tee -a $OUTPUT
echo "" 2>&1 | tee -a $OUTPUT

#4: Accept allowed UDP port
echo "Test Case #4: Accept valid UDP port" 2>&1 | tee -a $OUTPUT
echo "This SHOULD NOT show packet loss" 2>&1 | tee -a $OUTPUT
hping3 -c 5 $EXTERNAL_ADDRESS -2 -p 67 2>&1 | tee -a $OUTPUT
echo "" 2>&1 | tee -a $OUTPUT
echo "============================================================================================================================" 2>&1 | tee -a $OUTPUT
echo "" 2>&1 | tee -a $OUTPUT

#5: Drop TCP from source IP matching internal IP
echo "Test Case #5: Drop TCP packets from source IP matching internal host IP" 2>&1 | tee -a $OUTPUT
echo "This SHOULD show packet loss" 2>&1 | tee -a $OUTPUT
hping3 -c 5 $EXTERNAL_ADDRESS -S -a $INTERNAL_HOST_INTERNAL_ADDRESS -p 80 2>&1 | tee -a $OUTPUT
echo "" 2>&1 | tee -a $OUTPUT
echo "============================================================================================================================" 2>&1 | tee -a $OUTPUT
echo "" 2>&1 | tee -a $OUTPUT

#6: Drop UDP from source IP matching internal IP
echo "Test Case #6: Drop UDP packets from source IP matching internal host IP" 2>&1 | tee -a $OUTPUT
echo "This SHOULD show packet loss" 2>&1 | tee -a $OUTPUT
hping3 -c 5 $EXTERNAL_ADDRESS -2 -a $INTERNAL_HOST_INTERNAL_ADDRESS -p 67 2>&1 | tee -a $OUTPUT
echo "" 2>&1 | tee -a $OUTPUT
echo "============================================================================================================================" 2>&1 | tee -a $OUTPUT
echo "" 2>&1 | tee -a $OUTPUT

#7: Drop packets with both SYN and FIN set
echo "Test Case #7: Drop packets with both SYN and FIN set" 2>&1 | tee -a $OUTPUT
echo "This SHOULD show packet loss" 2>&1 | tee -a $OUTPUT
hping3 -c 5 $EXTERNAL_ADDRESS -S -F -p 443 2>&1 | tee -a $OUTPUT
echo "" 2>&1 | tee -a $OUTPUT
echo "============================================================================================================================" 2>&1 | tee -a $OUTPUT
echo "" 2>&1 | tee -a $OUTPUT

#8: Drop Telnet
echo "Test Case #8: Drop Telnet" 2>&1 | tee -a $OUTPUT
echo "This SHOULD show packet loss" 2>&1 | tee -a $OUTPUT
hping3 -c 5 $EXTERNAL_ADDRESS -S -p 23 2>&1 | tee -a $OUTPUT
echo "" 2>&1 | tee -a $OUTPUT
echo "============================================================================================================================" 2>&1 | tee -a $OUTPUT
echo "" 2>&1 | tee -a $OUTPUT

#9: Drop from source ports less than 1024 to destination port 80
echo "Test Case #9: Drop from source ports less than 1024 to destination port 80" 2>&1 | tee -a $OUTPUT
echo "This SHOULD show packet loss" 2>&1 | tee -a $OUTPUT
hping3 -c 5 $EXTERNAL_ADDRESS -S -s 1000 -p 80 2>&1 | tee -a $OUTPUT
echo "" 2>&1 | tee -a $OUTPUT
echo "============================================================================================================================" 2>&1 | tee -a $OUTPUT
echo "" 2>&1 | tee -a $OUTPUT

#10: Drop TCP packets from source port 0
echo "Test Case #10: Drop TCP packets from source port 0" 2>&1 | tee -a $OUTPUT
echo "This SHOULD show packet loss" 2>&1 | tee -a $OUTPUT
hping3 -c 5 $EXTERNAL_ADDRESS -S -s 0 -k -p 80 2>&1 | tee -a $OUTPUT
echo "" 2>&1 | tee -a $OUTPUT
echo "============================================================================================================================" 2>&1 | tee -a $OUTPUT
echo "" 2>&1 | tee -a $OUTPUT

#11: Drop TCP packets to destination port 0
echo "Test Case #11: Drop TCP packets to destination port 0" 2>&1 | tee -a $OUTPUT
echo "This SHOULD show packet loss" 2>&1 | tee -a $OUTPUT
hping3 -c 5 $EXTERNAL_ADDRESS -S -p 0 2>&1 | tee -a $OUTPUT
echo "" 2>&1 | tee -a $OUTPUT
echo "============================================================================================================================" 2>&1 | tee -a $OUTPUT
echo "" 2>&1 | tee -a $OUTPUT

#12: Drop UDP packets from source port 0
echo "Test Case #12: Drop UDP packets from source port 0" 2>&1 | tee -a $OUTPUT
echo "This SHOULD show packet loss" 2>&1 | tee -a $OUTPUT
hping3 -c 5 $EXTERNAL_ADDRESS -2 -s 0 -k -p 53 2>&1 | tee -a $OUTPUT
echo "" 2>&1 | tee -a $OUTPUT
echo "============================================================================================================================" 2>&1 | tee -a $OUTPUT
echo "" 2>&1 | tee -a $OUTPUT

#13: Drop UDP packets to destination port 0
echo "Test Case #13: Drop UDP packets to destination port 0" 2>&1 | tee -a $OUTPUT
echo "This SHOULD show packet loss" 2>&1 | tee -a $OUTPUT
hping3 -c 5 $EXTERNAL_ADDRESS -2 -p 0 2>&1 | tee -a $OUTPUT
echo "" 2>&1 | tee -a $OUTPUT
echo "============================================================================================================================" 2>&1 | tee -a $OUTPUT
echo "" 2>&1 | tee -a $OUTPUT

#14: Accept SSH
echo "Test Case #14: Accept SSH packet" 2>&1 | tee -a $OUTPUT
echo "This SHOULD NOT show packet loss" 2>&1 | tee -a $OUTPUT
hping3 -c 5 $EXTERNAL_ADDRESS -S -p 22 2>&1 | tee -a $OUTPUT
echo "" 2>&1 | tee -a $OUTPUT
echo "============================================================================================================================" 2>&1 | tee -a $OUTPUT
echo "" 2>&1 | tee -a $OUTPUT

#15: Accept http
echo "Test Case #15: Accept http packet" 2>&1 | tee -a $OUTPUT
echo "This SHOULD NOT show packet loss" 2>&1 | tee -a $OUTPUT
hping3 -c 5 $EXTERNAL_ADDRESS -S -p 80 2>&1 | tee -a $OUTPUT
echo "" 2>&1 | tee -a $OUTPUT
echo "============================================================================================================================" 2>&1 | tee -a $OUTPUT
echo "" 2>&1 | tee -a $OUTPUT

#16: Accept https
echo "Test Case #16: Accept https packet" 2>&1 | tee -a $OUTPUT
echo "This SHOULD NOT show packet loss" 2>&1 | tee -a $OUTPUT
hping3 -c 5 $EXTERNAL_ADDRESS -S -p 443 2>&1 | tee -a $OUTPUT
echo "" 2>&1 | tee -a $OUTPUT
echo "============================================================================================================================" 2>&1 | tee -a $OUTPUT
echo "" 2>&1 | tee -a $OUTPUT
