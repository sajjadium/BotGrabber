#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
	char data[200];

	while (fgets(data, sizeof(data), stdin) != NULL) {
		for (int i = 0; i < strlen(data); i++)
			if (data[i] == '|')
				data[i] = '\t';

		printf("%s", data);
	}

	return 0;
}

