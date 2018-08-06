#!/bin/sh

for file in ~/botnet/it_fulldump/*
do
	echo $file
	./botgraber $file 2>&-
done

