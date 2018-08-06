#!/bin/sh

rm -f $1

while read line
do
	echo $line
	echo $line >> $1
done

