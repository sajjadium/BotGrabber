#ifndef UTILITY_SQLITEDB_H
#define UTILITY_SQLITEDB_H

#include <sqlite3.h>

#include <deque>
#include <map>

#include <cstring>

using namespace std;

namespace utility {
	class ColnameCompare {
		public:
			bool operator() (const char *, const char *) const;
	};

	typedef map<const char *, char *, ColnameCompare> DataRow;
	typedef pair<const char *, char *> DataRowPair;
	typedef deque<DataRow *> ResultSet;

	class SqliteDB {
		public:
			char *db_filename;
			sqlite3 *db_conn;

			SqliteDB(const char *);
			~SqliteDB();

			bool open();
			void close();
			bool executeUpdate(const char *);
			ResultSet *executeSelect(const char *);
			static void freeResultSet(ResultSet *);
	};
}

#endif

