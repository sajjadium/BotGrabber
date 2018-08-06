#!/bin/sh

sqlite3 $1 "select ip, max(score) from scores where score >= $2 group by ip order by ip"

