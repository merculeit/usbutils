// SPDX-License-Identifier: GPL-2.0+
/*
 * Helpers for querying USB properties from sysfs
 */

#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

#if LINUX
#include <linux/limits.h>
#endif

#include <libusb.h>

#include "sysfs.h"

/*
 * The documentation of libusb_get_port_numbers() says "As per the USB 3.0
 * specs, the current maximum limit for the depth is 7."
 */
#define USB_MAX_DEPTH 7

#define SYSFS_DEV_ATTR_PATH "/sys/bus/usb/devices/%s/%s"

int get_sysfs_name(char *buf, size_t size, libusb_device *dev)
{
#if LINUX
	int len = 0;
	uint8_t bnum = libusb_get_bus_number(dev);
	uint8_t pnums[USB_MAX_DEPTH];
	int num_pnums;

	buf[0] = '\0';

	num_pnums = libusb_get_port_numbers(dev, pnums, sizeof(pnums));
	if (num_pnums == LIBUSB_ERROR_OVERFLOW) {
		return -1;
	} else if (num_pnums == 0) {
		/* Special-case root devices */
		return snprintf(buf, size, "usb%d", bnum);
	}

	len += snprintf(buf, size, "%d-", bnum);
	for (int i = 0; i < num_pnums; i++)
		len += snprintf(buf + len, size - len, i ? ".%d" : "%d", pnums[i]);

	return len;
#else
	return -1;
#endif
}

int read_sysfs_prop(char *buf, size_t size, char *sysfs_name, char *propname)
{
#if LINUX
	int n, fd;
	char path[PATH_MAX];

	buf[0] = '\0';
	snprintf(path, sizeof(path), SYSFS_DEV_ATTR_PATH, sysfs_name, propname);
	fd = open(path, O_RDONLY);

	if (fd == -1)
		return 0;

	n = read(fd, buf, size);

	if (n > 0)
		buf[n-1] = '\0';  // Turn newline into null terminator

	close(fd);
	return n;
#else
	return 0;
#endif
}
