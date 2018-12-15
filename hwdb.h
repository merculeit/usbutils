// SPDX-License-Identifier: GPL-2.0+

#ifndef _HWDB_H
#define _HWDB_H

#include <stdint.h>
#include <stddef.h>

typedef uint64_t hwdb_gid_t;
typedef uint32_t hwdb_key_t;

#define HWDB_GID_NOT_DEFINED									0xffffffffffffffffULL
#define HWDB_GID_VENDOR_DEVICE_AND_INTERFACE					0x0000000000000000ULL
#define HWDB_GID_KNOWN_DEVICE_CLASSES_SUBCLASSES_AND_PROTOCOLS	0x0000000000000043ULL
#define HWDB_GID_AUDIO_CLASS_TERMINAL_TYPES						0x0000000000005441ULL
#define HWDB_GID_HID_DESCRIPTOR_TYPES							0x0000000000444948ULL
#define HWDB_GID_HID_DESCRIPTOR_ITEM_TYPES						0x0000000000000052ULL
#define HWDB_GID_PHYSICAL_DESCRIPTOR_BIAS_TYPES					0x0000000053414942ULL
#define HWDB_GID_PHYSICAL_DESCRIPTOR_ITEM_TYPES					0x0000000000594850ULL
#define HWDB_GID_HID_USAGES										0x0000000000545548ULL
#define HWDB_GID_LANGUAGES										0x000000000000004cULL
#define HWDB_GID_VIDEO_CLASS_TERMINAL_TYPES						0x0000000000005456ULL

struct hwdb_entry {
	int depth;
	hwdb_gid_t gid;
	hwdb_key_t key;

	char *name;

	size_t num_subentries;
	struct hwdb_entry *subentries;
};

struct hwdb_group_key_map {
	hwdb_gid_t gid;
	hwdb_key_t key;
};

struct hwdb {
	size_t num_entries;
	struct hwdb_entry *entries;

	size_t num_groups;
	struct hwdb_group_key_map *group_key_maps;

	struct hwdb_entry root;
};

int hwdb_init(struct hwdb *hwdb, const char *usbids_path);
void hwdb_exit(struct hwdb *hwdb);
const struct hwdb_entry *hwdb_get_entry(
		const struct hwdb *hwdb, hwdb_gid_t gid, int depth, hwdb_key_t *keys);



static inline const char *hwdb_get_name(const struct hwdb_entry *entry)
{
	return entry == NULL ? NULL : entry->name;
}

#define HWDB_GET_NAME(HWDB, GID, KEYS) \
	hwdb_get_name(hwdb_get_entry(HWDB, GID, sizeof(KEYS)/sizeof(*(KEYS)), KEYS))

#endif /* _HWDB_H */
