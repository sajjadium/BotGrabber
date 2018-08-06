#!/bin/sh

sqlite3 ../sbu_botgrabber.db "SELECT ip || ': (' || CAST(cor_tw_id AS TEXT) || ':' || CAST(cor_c_id AS TEXT) || ') -> (' || CAST(tw_id AS TEXT) || ':' || CAST(c_id AS TEXT) || ')' FROM correlations WHERE ip = '$1'"

