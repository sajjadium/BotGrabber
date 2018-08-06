#!/bin/sh

sqlite3 ../run-6/sbu_botgrabber.db "select c_id, src_ip, src_port, dst_ip, dst_port from clusters where tw_id = $2 and c_id in (select c_id from clusters where tw_id = $2 and src_ip = '$1') order by c_id, src_ip, src_port, dst_ip, dst_port"

