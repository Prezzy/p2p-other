#!/usr/bin/bash


for i in {1..1}
do 
	taskset -c 0 python3 ver_pop_node.py &
	sleep 2
	taskset -c 2 python3 client_pop_node.py

	wait
	echo "done experiment $i"
done
