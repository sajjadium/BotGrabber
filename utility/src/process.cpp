#include "process.h"
#include "common.h"

#include <sys/wait.h>
#include <stdlib.h>
#include <string.h>
#include <set>

using namespace std;

namespace utility {
	Process::Process(const char **args, bool is_input, bool is_output, bool is_error) {
		memset(this, 0, sizeof(Process));

		int len = 0;
		while (args[len] != NULL) len++;
		len++;

		this->args = new char*[len];
		for (int i = 0; i < len; i++)
			this->args[i] = strclone(args[i]);

		this->is_input = is_input;
		this->is_output = is_output;
		this->is_error = is_error;
	}

	bool Process::start() {
		int input_pipe_fds[2];
		int output_pipe_fds[2];
		int error_pipe_fds[2];

		if (is_input) pipe(input_pipe_fds);
		if (is_output) pipe(output_pipe_fds);
		if (is_error) pipe(error_pipe_fds);

		pid_t child_pid = fork();
		if (child_pid == -1) {
			fprintf(stderr, "Can not create process\n");

			return false;
		}

		if (child_pid == 0) {
			if (this->is_input) dup2(input_pipe_fds[0], STDIN_FILENO);
			if (this->is_output) dup2(output_pipe_fds[1], STDOUT_FILENO);
			if (this->is_error) dup2(error_pipe_fds[1], STDERR_FILENO);

			set<int> main_files;
			main_files.insert(STDIN_FILENO);
			main_files.insert(STDOUT_FILENO);
			main_files.insert(STDERR_FILENO);
			if (this->is_input) main_files.insert(input_pipe_fds[0]);
			if (this->is_output) main_files.insert(output_pipe_fds[1]);
			if (this->is_error) main_files.insert(error_pipe_fds[1]);

			vector<int> *open_files = getOpenFiles();
			for (int i = 0; i < open_files->size(); i++)
				if (main_files.count(open_files->at(i)) == 0)
					close(open_files->at(i));

			delete open_files;

			execvp(this->args[0], (char * const *)this->args);

			if (this->is_input) close(input_pipe_fds[0]);
			if (this->is_output) close(output_pipe_fds[1]);
			if (this->is_error) close(error_pipe_fds[1]);

			abort();
		} else {
			if (this->is_input) {
				close(input_pipe_fds[0]);
				this->input_fd = input_pipe_fds[1];
				this->input = fdopen(this->input_fd, "w");
			}

			if (this->is_output) {
				close(output_pipe_fds[1]);
				this->output_fd = output_pipe_fds[0];
				this->output = fdopen(this->output_fd, "r");
			}

			if (this->is_error) {
				close(error_pipe_fds[1]);
				this->error_fd = error_pipe_fds[0];
				this->error = fdopen(this->error_fd, "r");
			}

			this->id = child_pid;
		}

		return true;
	}

	Process::~Process() {
		int i = 0;
		while (this->args[i] != NULL) delete[] this->args[i];
		delete[] this->args;

		this->terminate();
	}

	vector<int> *Process::getOpenFiles() {
		char temp[50];
		int file_id;
		vector<int> *open_files = new vector<int>();

		sprintf(temp, "ls /proc/%d/fd", getpid());
		FILE *of = popen(temp, "r");
		while (fscanf(of, "%d", &file_id) == 1)
			open_files->push_back(file_id);

		pclose(of);

		return open_files;
	}

	void Process::closeInput() {
		if (this->input != NULL) {
			close(this->input_fd);
			this->input_fd = -1;
			fclose(this->input);
			this->input = NULL;
		}
	}

	void Process::closeOutput() {
		if (this->output != NULL) {
			close(this->output_fd);
			this->output_fd = -1;
			fclose(this->output);
			this->output = NULL;
		}
	}

	void Process::closeError() {
		if (this->error != NULL) {
			close(this->error_fd);
			this->error_fd = -1;
			fclose(this->error);
			this->error = NULL;
		}
	}

	void Process::terminate() {
		this->closeInput();
		this->closeOutput();
		this->closeError();
		waitpid(this->id, NULL, 0);
	}
}

