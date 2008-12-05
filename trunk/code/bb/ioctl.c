#include <string.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/loop.h> /* ioctl_list */

int main(int argc, char *argv[])
{
	char *path, *path_target_a, *path_target_b;

	if (argc != 4) {
		fprintf(stderr, "usage: ioctl pathname\n");
	}

	path = argv[1];
	path_target_a = argv[2];
	path_target_b = argv[3];

	int fd = open(path, O_RDWR);
	int fd_target_a = open(path_target_a, O_RDONLY);
	int fd_target_b = open(path_target_b, O_RDONLY);

	printf("opened\n");

	if (fd < 0) {
		perror("Failed to open device");
		return 1;
	}

	if (fd_target_a < 0) {
		perror("Failed to open target a");
		return 1;
	}

	if (fd_target_b < 0) {
		perror("Failed to open target b");
		return 1;
	}

	int cmd = LOOP_SET_FD;

	if (ioctl(fd, cmd, fd_target_a)) {
		perror("ioctl");
		return 1;
	}

	if (ioctl(fd, cmd, fd_target_b)) {
		perror("ioctl");
		return 1;
	}

	printf("closed\n");

	if (close(fd) < 0) {
		perror("close");
		return 1;
	}

	return 0;
}
