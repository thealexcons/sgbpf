#!/bin/bash


get_cpu() {
    local idx=$1
    local cpu_count=$(($(getconf _NPROCESSORS_ONLN) - 1))
    local result=$((idx % cpu_count))
    echo "$result"
}

clean_up() {
    echo Killing all workers
    pkill -P $$
}

trap clean_up SIGHUP SIGINT SIGTERM

if [ $# -lt 1 ]; then
    echo "Error: Insufficient arguments provided."
    echo "Usage: ./run_workers.sh <first port> <num workers> <alive time>"
    exit 1
fi

startPort=$1
numWorkers=$2
aliveTime=$3

endPort=$((startPort + numWorkers))

filename="../workers.cfg"

command="echo \"Starting ${numWorkers}\" workers"

eval "> $filename"

for ((p=${startPort}; p<${endPort}; p++)); do
    # append the command to the main command string
    cpu_number=$(get_cpu $p)
    command="${command} & ./worker_vector $p $cpu_number"

    # write to file
    echo "127.0.0.1:$p" >> "$filename"
    if [[ $p -eq $((startPort + numServers - 1)) ]]
    then
        echo -n "" >> "$filename"
    fi
done

eval "${command} &"

sleep ${aliveTime}

clean_up
