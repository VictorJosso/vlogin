#!/bin/bash


onINT() {
echo "Killing command with PID $helperPID too"
kill "$helperPID"
exit
}

trap "onINT" SIGINT

python helper.py &
helperPID="$!"
gunicorn -b localhost:5005 -w 10 VloginApp:app
echo Done