#!/bin/bash

TYPE=$1
NAME=$2
STATE=$3

case $STATE in
    # if it becomes the master
    "MASTER") python3 /path/to/garp-reply.py
              exit 0
              ;;
    # if it becomes the backup
    "BACKUP") exit 0
              ;;
    # if in fault
    "FAULT")  exit 0
              ;;
    # unknown state
    *)        echo "unknown state"
              exit 1
              ;;

esac
