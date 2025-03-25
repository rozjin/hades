#!/bin/bash

device_file=$(losetup -f)
losetup $device_file build/persist.img
partprobe $device_file
mount "${device_file}p1" "/mnt/hades"