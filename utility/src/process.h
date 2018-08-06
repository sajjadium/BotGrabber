#ifndef UTILITY_PROCESS_H
#define UTILITY_PROCESS_H

#include <vector>
#include <unistd.h>

#include <cstdio>

using namespace std;

namespace utility {
	class Process {
		public:
			pid_t id;

			char **args;

			bool is_input;
			bool is_output;
			bool is_error;

			int input_fd;
			int output_fd;
			int error_fd;

			FILE *input;
			FILE *output;
			FILE *error;

			Process(const char **, bool, bool, bool);
			~Process();

			bool start();

			vector<int> *getOpenFiles();

			void closeInput();
			void closeOutput();
			void closeError();

			void terminate();
	};
}

#endif

