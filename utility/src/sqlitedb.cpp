#include "sqlitedb.h"
#include "common.h"

#include <cstring>
#include <cstdio>

#include <unistd.h>

namespace utility {
	int handleRow(void *rs, int argc, char *argv[], char *col_names[]) {
		DataRow *data_row = new DataRow();

		for (int i = 0; i < argc; i++) {
			char *col_name = strclone(col_names[i]);
			char *col_data = strclone(argv[i]);
			data_row->insert(DataRowPair(col_name, col_data));
		}

		((ResultSet *)rs)->push_back(data_row);

		return 0;
	}

	bool ColnameCompare::operator() (const char *cn1, const char *cn2) const {
		return (strcmp(cn1, cn2) < 0);
	}

	SqliteDB::SqliteDB(const char *db_filename) {
		this->db_filename = strclone(db_filename);

		this->db_conn = NULL;
	}

	SqliteDB::~SqliteDB() {
		delete[] this->db_filename;
		this->close();
	}

	bool SqliteDB::open() {
		if (sqlite3_open(this->db_filename, &this->db_conn) != SQLITE_OK) {
			fprintf(stderr, "SqliteDB Error: %s\n", sqlite3_errmsg(this->db_conn));
			return false;
		}

		return true;
	}

	void SqliteDB::close() {
		sqlite3_close(this->db_conn);
	}

	bool SqliteDB::executeUpdate(const char *cmd) {
		char *err_msg = NULL;

		while (true) {
			int ret = sqlite3_exec(this->db_conn, cmd, NULL, NULL, &err_msg);

			if (ret == SQLITE_OK)
				break;
			else {
//				fprintf(stderr, "SQL error: %s\n", err_msg);
				sqlite3_free(err_msg);
				return false;
			}
		}

		return true;
	}

	ResultSet *SqliteDB::executeSelect(const char *cmd) {
		char *err_msg = NULL;
		ResultSet *rs = new ResultSet();

		while (true) {
			int ret = sqlite3_exec(this->db_conn, cmd, handleRow, rs, &err_msg);

			if (ret == SQLITE_OK)
				break;
			else {
				this->freeResultSet(rs);
//				fprintf(stderr, "SQL error: %s\n", err_msg);
				sqlite3_free(err_msg);
				return NULL;
			}
		}

		return rs;
	}

	void SqliteDB::freeResultSet(ResultSet *rs) {
		for (int i = 0; i < rs->size(); i++) {
			DataRow *dr = rs->at(i);
			DataRow::iterator it = dr->begin();
			while (it != dr->end()) {
				const char *col_name = it->first;
				char *col_data = it->second;
				dr->erase(it++);
				delete[] col_name;
				delete[] col_data;
			}

			delete dr;
		}
		delete rs;
	}
}

