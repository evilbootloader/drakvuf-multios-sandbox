#!/bin/bash


ip link set xenbr1 up
/home/user/drakvuf-tools/network-setup.sh 2

##########################################
# START DRAKVUF / DIRWATCH               #
##########################################

dirwatch 1 \
    ubuntu_sandbox \
    /home/user/drakvuf-tools/ubuntu_sandbox.cfg \
    /root/linux.json \
    1415 \
    /malware_incoming \
    /malware_processing \
    /malware_finished \
    2 \
    /home/user/drakvuf-tools/clone-ubuntu.pl \
    /home/user/drakvuf-tools/preconfig-ubuntu.sh \
    /home/user/drakvuf-tools/drakvuf-ubuntu.sh \
    /home/user/drakvuf-tools/cleanup.sh \
    /home/user/drakvuf-tools/tcpdump.sh
