#!/bin/bash

export PROGRAM=./run-cryptoblogdev.sh
rerun () {
   kill -TERM `cat .gopid`
   sleep 1 
  go build && bash -c 'echo $$ > .gopid ; exec $PROGRAM ' &
} 


while true
do
    rerun
    inotifywait -e modify *go templates/*.template
done

