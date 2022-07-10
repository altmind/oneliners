#!/bin/bash
awk -v "ORS=" -e ' $1 ~ /(md5|sha)/ \
    {print "  " $5 " |"} $1 ~ /(des|aes)/ {b = b "  " $6 " |"} $1 ~ /(rsa|dsa)/ \
    {print b "  " $6 " | " $7 " | ";b=""}' bench-nomt.txt | sed -e 's/\.\(..\)k/\10/g' | sed -e "s/\ \+/ /g"