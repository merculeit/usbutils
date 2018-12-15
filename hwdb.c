// SPDX-License-Identifier: GPL-2.0+

#include "hwdb.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>


#define MSG_EMERGE		0
#define MSG_ALERT		1
#define MSG_CRIT		2
#define MSG_ERR			3
#define MSG_WARNING		4
#define MSG_NOTICE		5
#define MSG_INFO		6
#define MSG_DEBUG		7
#define MSG_VERBOSE		8

#define MSG_LEVEL MSG_ERR

__attribute__((format(printf, 2, 3)))
static int msg(unsigned int level, const char *format, ...)
{
	if (level <= MSG_LEVEL) {
		const char *cats[] = {
			"emerge", "alert", "crit", "err", "warning", "notice", "info", "debug", "verbose"
		};
		fprintf(stderr, "%s: ", cats[level]);

		va_list ap;
		va_start(ap, format);
		int r = vfprintf(stderr, format, ap);
		va_end(ap);
		return r;
	} else {
		return 0;
	}
}

static int hwdb_entry_compare(const struct hwdb_entry *a, const struct hwdb_entry *b)
{
	if (a->key < b->key)
		return -1;
	else if (a->key > b->key)
		return 1;
	else
		return 0;
}

static int hwdb_group_key_map_compare(const struct hwdb_group_key_map *a, const struct hwdb_group_key_map *b)
{
	if (a->gid < b->gid)
		return -1;
	else if (a->gid > b->gid)
		return 1;
	else
		return 0;
}

typedef int (*_cmp_t)(const void *, const void *);
#define HWDB_ENTRY_COMPARATOR			((_cmp_t)&hwdb_entry_compare)
#define HWDB_GROUP_KEY_MAP_COMPARATOR	((_cmp_t)&hwdb_group_key_map_compare)

static void hwdb_entry_clean(struct hwdb_entry *entry)
{
	msg(MSG_DEBUG, "%s(%p)\n", __func__, entry);

	free(entry->name);
	entry->name = NULL;

	entry->num_subentries = 0;
	entry->subentries = NULL;
}

static int hwdb_usbids_read_next_entry(FILE *fp, struct hwdb_entry *entry)
{
	msg(MSG_DEBUG, "%s(%p, %p)\n", __func__, fp, entry);

	char buf[1024];

	int depth;
	hwdb_gid_t gid;
	hwdb_key_t key;

	char *name = NULL;

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		char *begin, *end, *endptr;

		char *ptr = buf;
		size_t len = strlen(ptr);

		// remove LF
		if (ptr[len-1] == '\n') {
			ptr[len-1] = '\0';
			--len;
		}
		msg(MSG_VERBOSE, "%s(): line = \"%s\"\n", __func__, buf);

		if (*ptr == '#' || *ptr == '\0') {
			msg(MSG_VERBOSE, "%s(): comment or blank\n", __func__);
			continue;
		}

		// count leading tabs and remove them
		depth = 0;
		while (ptr[depth] == '\t') ++depth;
		ptr += depth;

		// group or key
		begin = ptr;
		while (isalnum(*ptr) || isxdigit(*ptr)) ++ptr;
		end = ptr;

		if (*ptr != ' ') {
			msg(MSG_WARNING, "%s(): unexpected character\n", __func__);
			goto invalid;
		}
		++ptr;

		if (*ptr != ' ') {
			// group
			gid = 0;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
			memcpy(&gid, begin, end - begin);
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
			for (size_t i = 0; i < (end - begin); ++i)
				((uint8_t *)&gid)[sizeof(hwdb_gid_t) - i - 1] = begin[i];
#else
			#error
#endif

			begin = ptr;
			while (isxdigit(*ptr)) ++ptr;
			end = ptr;

			if (*ptr != ' ') {
				msg(MSG_WARNING, "%s(): unexpected character\n", __func__);
				goto invalid;
			}
			++ptr;
		} else {
			// no explicit group
			if (depth == 0)
				gid = HWDB_GID_VENDOR_DEVICE_AND_INTERFACE;
			else
				gid = HWDB_GID_NOT_DEFINED;
		}

		if (*ptr != ' ') {
			msg(MSG_WARNING, "%s(): unexpected character\n", __func__);
			goto invalid;
		}
		++ptr;

		// key
		char ch = *end;
		*end = '\0';
		errno = 0;
		key = strtoul(begin, &endptr, 16);
		if (errno != 0 || *endptr != '\0') {
			msg(MSG_WARNING, "%s(): unexpected character\n", __func__);
			goto invalid;
		}
		*end = ch;

		// name
		size_t name_len = strlen(ptr);
		if (name_len != 0) {
			name = calloc(name_len + 1, sizeof(char));
			if (name == NULL) {
				msg(MSG_ERR, "%s(): failed to allocate memory (%s)\n", __func__, strerror(errno));
				goto error;
			}

			strcpy(name, ptr);
		} else {
			name = NULL;
		}

		msg(MSG_VERBOSE, "%s(): depth=%d, gid=0x%016llx, key=0x%08x, name=%s\n", __func__, depth, gid, key, name);
		entry->depth = depth;
		entry->gid = gid;
		entry->key = key;
		entry->name = name;
		entry->num_subentries = 0;
		entry->subentries = NULL;

		return 0;
	}

	msg(MSG_DEBUG, "%s(): failed to read line (%s) eof=%d\n", __func__, strerror(errno), feof(fp));
	return feof(fp) ? 1 : -1;

invalid:
	errno = EILSEQ;
error:
	free(name);
	return -1;
}

static int hwdb_usbids_count_entries(
		FILE *fp, int *p_max_depth, size_t *p_num_groups, size_t *p_num_entries)
{
	int r;

	int max_depth;
	size_t num_groups;
	size_t num_entries;

	hwdb_gid_t gid;

	struct hwdb_entry tmp_entry;
	struct hwdb_entry *entry = NULL;

	// count entries and groups
	r = fseek(fp, 0, SEEK_SET);
	if (r == -1) {
		msg(MSG_ERR, "%s(): failed to seek file (%s)\n", __func__, strerror(errno));
		goto error;
	}

	max_depth = 0;
	num_groups = 0;
	num_entries = 0;
	while ((r = hwdb_usbids_read_next_entry(fp, &tmp_entry)) == 0) {
		entry = &tmp_entry;

		// calculate maximum depth
		if (entry->depth > max_depth)
			max_depth = entry->depth;

		// count number of groups
		if (num_entries == 0) {
			if (entry->depth != 0) {
				msg(MSG_WARNING, "%s(): depth of the first entry is not 0 (%d)\n", __func__, entry->depth);
				goto error;
			}
			++num_groups;
			gid = entry->gid;
		} else if (entry->depth == 0 && entry->gid != gid) {
			++num_groups;
			gid = entry->gid;
		}

		// count number of entries
		++num_entries;

		hwdb_entry_clean(entry);
		entry = NULL;
	}
	if (r == -1) {
		msg(MSG_ERR, "%s(): failed to read next entry (%s)\n", __func__, strerror(errno));
		goto error;
	}

	*p_max_depth = max_depth;
	*p_num_groups = num_groups;
	*p_num_entries = num_entries;

	return 0;

error:
	if (entry != NULL) {
		hwdb_entry_clean(entry);
		entry = NULL;
	}

	return -1;
}

static int hwdb_usbids_create_group_entries(
		FILE *fp, size_t num_groups, struct hwdb_group_key_map *group_key_maps, struct hwdb_entry *entries)
{
	int r;

	size_t offset;
	hwdb_gid_t gid;

	struct hwdb_entry tmp_entry;
	struct hwdb_entry *entry = NULL;

	r = fseek(fp, 0, SEEK_SET);
	if (r == -1) {
		msg(MSG_ERR, "%s(): failed to seek file (%s)\n", __func__, strerror(errno));
		goto error;
	}

	offset = 0;
	while ((r = hwdb_usbids_read_next_entry(fp, &tmp_entry)) == 0) {
		entry = &tmp_entry;

		if (offset == 0 || (entry->depth == 0 && entry->gid != gid)) {
			struct hwdb_entry group_entry;

			if (offset == num_groups) {
				msg(MSG_CRIT, "%s(): too many groups\n", __func__);
				goto error;
			}

			group_key_maps[offset].gid = entry->gid;
			group_key_maps[offset].key = offset;

			group_entry.depth = -1;
			group_entry.gid = entry->gid;
			group_entry.key = offset;
			group_entry.name = NULL;
			group_entry.num_subentries = 0;
			group_entry.subentries = NULL;

			entries[offset++] = group_entry;
			gid = entry->gid;
		}

		hwdb_entry_clean(entry);
		entry = NULL;
	}
	if (r == -1) {
		msg(MSG_ERR, "%s(): failed to read next entry (%s)\n", __func__, strerror(errno));
		goto error;
	}

	return 0;

error:
	if (entry != NULL) {
		hwdb_entry_clean(entry);
		entry = NULL;
	}

	return -1;
}

static int hwdb_usbids_read_and_link_entries(
		FILE *fp, int max_depth, size_t num_groups, size_t num_entries, struct hwdb_entry *entries)
{
	int r;

	struct hwdb_entry tmp_entry;
	struct hwdb_entry *entry = NULL;

	size_t offset = num_groups;
	struct hwdb_entry *parent = entries;
	hwdb_gid_t gid = entries[0].gid;

	for (int depth = 0; depth <= max_depth; ++depth) {
		r = fseek(fp, 0, SEEK_SET);
		if (r == -1) {
			msg(MSG_ERR, "%s(): failed to seek file (%s)\n", __func__, strerror(errno));
			goto error;
		}

		while ((r = hwdb_usbids_read_next_entry(fp, &tmp_entry)) == 0) {
			entry = &tmp_entry;

			// only entries that depth is 0 have group explicitly
			if (entry->depth > 0)
				entry->gid = gid;

			if (entry->depth == depth - 1 || tmp_entry.gid != gid) {
				++parent;
			}
			gid = entry->gid;

			if (entry->depth == depth) {
				if (offset == num_entries) {
					msg(MSG_CRIT, "%s(): too many entries\n", __func__);
					goto error;
				}

				if (parent->num_subentries == 0)
					parent->subentries = &entries[offset];
				++parent->num_subentries;
				entries[offset++] = *entry;

				entry = NULL; // moved
			}

			if (entry != NULL) {
				hwdb_entry_clean(entry);
				entry = NULL;
			}
		}
		if (r == -1) {
			msg(MSG_ERR, "%s(): failed to read next entry (%s)\n", __func__, strerror(errno));
			goto error;
		}
	}

	return 0;

error:
	if (entry != NULL) {
		hwdb_entry_clean(entry);
		entry = NULL;
	}

	for (size_t i = 0; i < num_groups; ++i) {
		entries[i].num_subentries = 0;
		entries[i].subentries = NULL;
	}

	for (size_t i = num_groups; i < offset; ++i) {
		hwdb_entry_clean(&entries[i]);
	}

	return -1;
}

static int hwdb_usbids_read_file(FILE *fp, struct hwdb *hwdb)
{
	msg(MSG_DEBUG, "%s(%p, %p)\n", __func__, fp, hwdb);

	int r;

	int max_depth;
	size_t num_groups;
	size_t num_entries;

	struct hwdb_entry *entries = NULL;
	struct hwdb_group_key_map *group_key_maps = NULL;

	// count entries and groups, then allocate memory
	r = hwdb_usbids_count_entries(fp, &max_depth, &num_groups, &num_entries);
	if (r == -1) {
		msg(MSG_WARNING, "%s(): failed to count number of entries (%s)\n", __func__, strerror(errno));
		goto error;
	}

	msg(MSG_INFO, "%s(): max depth = %d\n", __func__, max_depth);
	msg(MSG_INFO, "%s(): # of entries = %zu\n", __func__, num_entries);
	msg(MSG_INFO, "%s(): # of groups = %zu\n", __func__, num_groups);

	if (num_entries == 0 || num_groups == 0) {
		msg(MSG_WARNING, "%s(): no valid entry\n", __func__);
		goto error;
	}

	num_entries += num_groups;
	entries = calloc(num_entries, sizeof(struct hwdb_entry));
	if (entries == NULL) {
		msg(MSG_ERR, "%s(): failed to allocate memory (%s)\n", __func__, strerror(errno));
		goto error;
	}

	group_key_maps = calloc(num_groups, sizeof(struct hwdb_group_key_map));
	if (group_key_maps == NULL) {
		msg(MSG_ERR, "%s(): failed to allocate memory (%s)\n", __func__, strerror(errno));
		goto error;
	}

	// prepare group entries
	r = hwdb_usbids_create_group_entries(fp, num_groups, group_key_maps, entries);
	if (r == -1) {
		msg(MSG_ERR, "%s(): failed to create group entries (%s)\n", __func__, strerror(errno));
		goto error;
	}

	// read entries into memory and link each with its children
	r = hwdb_usbids_read_and_link_entries(fp, max_depth, num_groups, num_entries, entries);
	if (r == -1) {
		msg(MSG_ERR, "%s(): failed to read and link entries (%s)\n", __func__, strerror(errno));
		goto error;
	}

	// sort by key
	qsort(hwdb->entries, hwdb->num_entries, sizeof(struct hwdb_entry), HWDB_ENTRY_COMPARATOR);

	hwdb->num_entries = num_entries;
	hwdb->entries = entries;

	hwdb->num_groups = num_groups;
	hwdb->group_key_maps = group_key_maps;

	// create root entry
	hwdb->root.depth = -2;
	hwdb->root.gid = HWDB_GID_NOT_DEFINED;
	hwdb->root.key = 0;
	hwdb->root.name = NULL;
	hwdb->root.num_subentries = num_groups;
	hwdb->root.subentries = entries;

	return 0;

error:
	free(entries);
	entries = NULL;

	free(group_key_maps);
	group_key_maps = NULL;

	return -1;
}

int hwdb_init(struct hwdb *hwdb, const char *usbids_path)
{
	msg(MSG_DEBUG, "%s(%p, %s)\n", __func__, hwdb, usbids_path);

	if (hwdb == NULL) {
		msg(MSG_ERR, "%s(): invalid parameter\n", __func__);
		errno = EINVAL;
		return -1;
	}

	hwdb->num_entries = 0;
	hwdb->entries = NULL;

	hwdb->num_groups = 0;
	hwdb->group_key_maps = NULL;

	hwdb->root.name = NULL;
	hwdb->root.num_subentries = 0;
	hwdb->root.subentries = NULL;

	if (usbids_path == NULL) {
		msg(MSG_WARNING, "%s(): invalid parameter\n", __func__);
		errno = EINVAL;
		return -1;
	}

	FILE *fp = fopen(usbids_path, "r");
	if (fp == NULL) {
		msg(MSG_ERR, "%s(): failed to open file (%s)\n", __func__, strerror(errno));
		return -1;
	}

	int r = hwdb_usbids_read_file(fp, hwdb);

	fclose(fp);
	return r;
}

void hwdb_exit(struct hwdb *hwdb)
{
	msg(MSG_DEBUG, "%s(%p)\n", __func__, hwdb);

	if (hwdb == NULL) {
		msg(MSG_ERR, "%s(): invalid parameter\n", __func__);
		errno = EINVAL;
		return;
	}

	hwdb_entry_clean(&hwdb->root);

	for (size_t i = 0; i < hwdb->num_entries; ++i)
		hwdb_entry_clean(&hwdb->entries[i]);

	hwdb->num_entries = 0;
	free(hwdb->entries);
	hwdb->entries = NULL;

	hwdb->num_groups = 0;
	free(hwdb->group_key_maps);
	hwdb->group_key_maps = NULL;
}

static hwdb_key_t hwdb_get_group_key(const struct hwdb *hwdb, hwdb_gid_t gid)
{
	msg(MSG_DEBUG, "%s(%p, 0x%016llx)\n", __func__, hwdb, gid);

	struct hwdb_group_key_map key_map;
	key_map.gid = gid;

	const struct hwdb_group_key_map *map = bsearch(
			&key_map, hwdb->group_key_maps,
			hwdb->num_groups, sizeof(struct hwdb_group_key_map),
			HWDB_GROUP_KEY_MAP_COMPARATOR);
	if (map != NULL)
		return map->key;

	msg(MSG_INFO, "%s(): no entry\n", __func__);
	errno = ENOENT;
	return hwdb->root.num_subentries;
}

static const struct hwdb_entry *hwdb_entry_get_subentry(
		const struct hwdb_entry *entry, hwdb_key_t key)
{
	msg(MSG_DEBUG, "%s(%p, 0x%08x)\n", __func__, entry, key);

	struct hwdb_entry key_entry;
	key_entry.key = key;

	const struct hwdb_entry *subentry = (const struct hwdb_entry *)bsearch(
			&key_entry, entry->subentries,
			entry->num_subentries, sizeof(struct hwdb_entry),
			HWDB_ENTRY_COMPARATOR);
	if (subentry != NULL)
		return subentry;

	msg(MSG_INFO, "%s(): no entry\n", __func__);
	errno = ENOENT;
	return NULL;
}

static const struct hwdb_entry *hwdb_entry_get_subentry_recursively(
		const struct hwdb_entry *entry, int depth, hwdb_key_t *keys)
{
	msg(MSG_DEBUG, "%s(%p, %d, %p)\n", __func__, entry, depth, keys);

	for (int d = 0; d < depth; ++d) {
		entry = hwdb_entry_get_subentry(entry, keys[d]);
		if (entry == NULL)
			return NULL;
	}
	return entry;
}

const struct hwdb_entry *hwdb_get_entry(
		const struct hwdb *hwdb, hwdb_gid_t gid, int depth, hwdb_key_t *keys)
{
	msg(MSG_DEBUG, "%s(%p, 0x%016llx, %d, %p)\n", __func__, hwdb, gid, depth, keys);

	if (hwdb == NULL || depth < 0 || keys == NULL) {
		msg(MSG_ERR, "%s(): invalid parameter\n", __func__);
		errno = EINVAL;
		return NULL;
	}

	hwdb_key_t gkey = hwdb_get_group_key(hwdb, gid);
	if (gkey >= hwdb->num_groups) {
		msg(MSG_INFO, "%s(): no entry\n", __func__);
		errno = ENOENT;
		return NULL;
	}

	return hwdb_entry_get_subentry_recursively(&hwdb->root.subentries[gkey], depth, keys);
}

