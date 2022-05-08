#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>

/* You need to change this macro to your RUFS mount point*/
#define TESTDIR "/tmp/jay77/mountdir"

#define N_FILES 100
#define BLOCKSIZE 4096
#define FSPATHLEN 256
#define ITERS 16
#define ITERS_LARGE 2048
#define FILEPERM 0666
#define DIRPERM 0755

char buf[BLOCKSIZE];

int main(int argc, char **argv) {

	int i, fd = 0, ret = 0;
	struct stat st;

	/* TEST 1: file create test */
	if ((fd = creat(TESTDIR "/file", FILEPERM)) < 0) {
		perror("creat");
		printf("TEST 1: File create failure \n");
		exit(1);
	}
	printf("TEST 1: File create Success \n");


	/* TEST 2: file small write test */
	for (i = 0; i < ITERS; i++) {
		//memset with some random data
		memset(buf, 0x61 + i, BLOCKSIZE);

		if (write(fd, buf, BLOCKSIZE) != BLOCKSIZE) {
			printf("TEST 2: File write failure \n");
			exit(1);
		}
	}

	fstat(fd, &st);
	if (st.st_size != ITERS*BLOCKSIZE) {
		printf("TEST 2: File write failure \n");
		exit(1);
	}
	printf("TEST 2: File write Success \n");


	/* TEST 3: file close */
	if (close(fd) < 0) {
		printf("TEST 3: File close failure \n");
	}
	printf("TEST 3: File close Success \n");


	/* Open for reading */
	if ((fd = open(TESTDIR "/file", FILEPERM)) < 0) {
		perror("open");
		exit(1);
	}

	/* TEST 4: file small read test */
	for (i = 0; i < ITERS; i++) {
		//clear buffer
		memset(buf, 0, BLOCKSIZE);

		if (read(fd, buf, BLOCKSIZE) != BLOCKSIZE) {
			printf("TEST 4: File read failure \n");
			exit(1);
		}
		//printf("buf %s \n", buf);
	}

	if (pread(fd, buf, BLOCKSIZE, 2*BLOCKSIZE) != BLOCKSIZE) {
		perror("pread");
		printf("TEST 4: File read failure \n");
		exit(1);
	}

	printf("TEST 4: File read Success \n");
	close(fd);


	/* TEST 5: file remove test */
	if ((ret = unlink(TESTDIR "/file")) < 0) {
		perror("unlink");
		printf("TEST 5: File unlink failure \n");
		exit(1);
	}
	printf("TEST 5: File unlink success \n");


	/* TEST 6: directory create test */
	if ((ret = mkdir(TESTDIR "/files", DIRPERM)) < 0) {
		perror("mkdir");
		printf("TEST 6: failure. Check if dir %s already exists, and "
			"if it exists, manually remove and re-run \n", TESTDIR "/files");
		exit(1);
	}
	printf("TEST 6: Directory create success \n");


	/* TEST 7: directory remove test */
	if ((ret = rmdir(TESTDIR "/files")) < 0) {
		perror("mkdir");
		printf("TEST 7: Directory remove failure \n");
		exit(1);
	}

	if (opendir(TESTDIR "/files") != NULL) {
		perror("mkdir");
		printf("TEST 7: Directory remove failure \n");
		exit(1);
	}

	printf("TEST 7: Directory remove success \n");


	mkdir(TESTDIR "/files", DIRPERM);

	/* TEST 8: sub-directory create test */
	for (i = 0; i < N_FILES; ++i) {
		char subdir_path[FSPATHLEN];
		memset(subdir_path, 0, FSPATHLEN);

		sprintf(subdir_path, "%s%d", TESTDIR "/files/dir", i);
		if ((ret = mkdir(subdir_path, DIRPERM)) < 0) {
			perror("mkdir");
			printf("TEST 8: Sub-directory create failure \n");
			exit(1);
		}
	}

	for (i = 0; i < N_FILES; ++i) {
		DIR *dir;
		char subdir_path[FSPATHLEN];
		memset(subdir_path, 0, FSPATHLEN);

		sprintf(subdir_path, "%s%d", TESTDIR "/files/dir", i);
		if ((dir = opendir(subdir_path)) == NULL) {
			perror("opendir");
			printf("TEST 8: Sub-directory create failure \n");
			exit(1);
		}
	}
	printf("TEST 8: Sub-directory create success \n");


	/* TEST 9: Large file write-read test */
	if ((fd = creat(TESTDIR "/largefile", FILEPERM)) < 0) {
		perror("creat large file fail");
		exit(1);
	}

	/* Perform sequential writes */
	for (i = 0; i < ITERS_LARGE; i++) {
		//memset with some random data
		memset(buf, 0x61 + i % 26, BLOCKSIZE);

		if (write(fd, buf, BLOCKSIZE) != BLOCKSIZE) {
			printf("TEST 9: Large file write failure \n");
			exit(1);
		}
	}

	fstat(fd, &st);
	if (st.st_size != ITERS_LARGE*BLOCKSIZE) {
		printf("TEST 9: Large file write failure \n");
		exit(1);
	}
	printf("TEST 9: Large file write success \n");


	/* Close operation */
	if (close(fd) < 0) {
		perror("close largefile");
		exit(1);
	}

	/* Open for reading */
	if ((fd = open(TESTDIR "/largefile", FILEPERM)) < 0) {
		perror("open");
		exit(1);
	}


	/* TEST 10: Large file read test */
	if (pread(fd, buf, BLOCKSIZE, 1000*BLOCKSIZE) != BLOCKSIZE) {
		perror("pread");
		printf("TEST 10: Large file read failure \n");
		exit(1);
	}

	/* Verify file content */
	if (buf[0] != 0x61 + 1000 % 26) {
		perror("pread");
		printf("TEST 10: Large file read failure \n");
		exit(1);
	}

	printf("TEST 10: Large file read Success \n");
	close(fd);


	printf("Benchmark completed \n");
	return 0;
}
