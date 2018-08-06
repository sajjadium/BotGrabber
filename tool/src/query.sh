#!/bin/sh

if [ $# -eq 0 ]
then
	echo "Error: Please give a query"
	exit 0
fi

echo "$1;" | sqlite3 /share/botnet/it_netflow.db | ../sqlite2nf

