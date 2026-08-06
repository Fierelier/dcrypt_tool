#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <termios.h>
#include <sys/stat.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <libgen.h>
#include "xts.h"
#include "crc32.h"
#include "sha512_pkcs5_2_small.h"

#define HEADER_SIZE 2048
#define SALT_SIZE   64
#define DISKKEY_SIZE 256
#define SIGN 0x50524344u
#define VF_TMP_MODE     0x01
#define VF_REENCRYPT    0x02
#define VF_STORAGE_FILE 0x04
#define VF_NO_REDIR     0x08

static int g_verbose = 0;
#define VLOG(...) do { if (g_verbose) printf(__VA_ARGS__); } while (0)

#define CF_AES 0
#define CF_TWOFISH 1
#define CF_SERPENT 2
#define CF_AES_TWOFISH 3
#define CF_TWOFISH_SERPENT 4
#define CF_SERPENT_AES 5
#define CF_AES_TWOFISH_SERPENT 6
#define CF_CIPHERS_NUM 7

typedef struct {
	int count;
	const cipher_ops *layers[3];
	const char *names[3];
} cascade_t;

static const cascade_t CASCADES[CF_CIPHERS_NUM] = {
	{ 1, { &CIPHER_AES }, { "aes" } },
	{ 1, { &CIPHER_TWOFISH }, { "twofish" } },
	{ 1, { &CIPHER_SERPENT }, { "serpent" } },
	{ 2, { &CIPHER_TWOFISH, &CIPHER_AES }, { "twofish", "aes" } },
	{ 2, { &CIPHER_SERPENT, &CIPHER_TWOFISH }, { "serpent", "twofish" } },
	{ 2, { &CIPHER_AES, &CIPHER_SERPENT }, { "aes", "serpent" } },
	{ 3, { &CIPHER_SERPENT, &CIPHER_TWOFISH, &CIPHER_AES }, { "serpent", "twofish", "aes" } },
};

static const char *ALGO_NAME(int alg)
{
	static const char *names[CF_CIPHERS_NUM] = {
		"aes", "twofish", "serpent", "aes-twofish",
		"twofish-serpent", "serpent-aes", "aes-twofish-serpent"
	};
	if (alg >= 0 && alg < CF_CIPHERS_NUM) return names[alg];
	return "unknown";
}

static void cascade_decrypt(int alg, const unsigned char *key192,
	const unsigned char *data, size_t len, uint64_t sector, unsigned char *out)
{
	const cascade_t *casc = &CASCADES[alg];
	unsigned char *buf_a = malloc(len);
	unsigned char *buf_b = malloc(len);
	unsigned char *cur, *next, *tmp;
	int i, li;

	memcpy(buf_a, data, len);
	cur = buf_a;
	next = buf_b;

	for (i = casc->count - 1; i >= 0; i--) {
		li = i;
		const unsigned char *crypt_key = key192 + li * 64;
		const unsigned char *tweak_key = key192 + li * 64 + 32;
		xts_pass(casc->layers[li], crypt_key, tweak_key, cur, len, sector, 1, next);
		tmp = cur; cur = next; next = tmp;
	}
	memcpy(out, cur, len);
	free(buf_a);
	free(buf_b);
}

static void pbkdf2_password(const char *password, const unsigned char *salt,
	unsigned char *dk, unsigned long dklen)
{
	size_t plen = strlen(password);
	unsigned char *pwd16 = malloc(plen * 2);
	size_t i;

	/* UTF-16LE of the (assumed ASCII/Latin1) password, matching dc_pass wchar_t layout */
	for (i = 0; i < plen; i++) {
		pwd16[i * 2] = (unsigned char)password[i];
		pwd16[i * 2 + 1] = 0;
	}
	sha512_pkcs5_2(1000, pwd16, (uint32_t)(plen * 2), salt, SALT_SIZE, dk, dklen);
	free(pwd16);
}

static int try_unlock(const unsigned char *raw, const char *password, unsigned char *dec_out)
{
	unsigned char dk[DISKKEY_SIZE];
	unsigned char dec[HEADER_SIZE];
	int alg;

	pbkdf2_password(password, raw, dk, DISKKEY_SIZE);

	for (alg = 0; alg < CF_CIPHERS_NUM; alg++) {
		uint32_t sign, hdr_crc, crc_calc;
		cascade_decrypt(alg, dk, raw, HEADER_SIZE, 0, dec);
		memcpy(&sign, dec + SALT_SIZE, 4);
		memcpy(&hdr_crc, dec + SALT_SIZE + 4, 4);
		if (sign != SIGN) continue;
		crc_calc = crc32_calc(dec + SALT_SIZE + 8, HEADER_SIZE - SALT_SIZE - 8);
		if (crc_calc == hdr_crc) {
			memcpy(dec_out, dec, HEADER_SIZE);
			return alg;
		}
	}
	return -1;
}

typedef struct {
	uint16_t version;
	uint32_t flags;
	uint32_t disk_id;
	int32_t alg_1;
	unsigned char key_1[DISKKEY_SIZE];
	int32_t alg_2;
	unsigned char key_2[DISKKEY_SIZE];
	uint64_t stor_off;
	uint64_t tmp_size;
} header_info_t;

static void parse_header(const unsigned char *dec, header_info_t *info)
{
	size_t base = SALT_SIZE;
	size_t off;

	memcpy(&info->version, dec + base + 8, 2);
	memcpy(&info->flags, dec + base + 10, 4);
	memcpy(&info->disk_id, dec + base + 14, 4);

	off = base + 18;
	memcpy(&info->alg_1, dec + off, 4);
	memcpy(info->key_1, dec + off + 4, DISKKEY_SIZE);

	off = off + 4 + DISKKEY_SIZE;
	memcpy(&info->alg_2, dec + off, 4);
	memcpy(info->key_2, dec + off + 4, DISKKEY_SIZE);

	off = off + 4 + DISKKEY_SIZE;
	memcpy(&info->stor_off, dec + off, 8);

	off = off + 8 + 8;
	memcpy(&info->tmp_size, dec + off, 8);
}

static void resolve_disk(const char *device, char *disk_out, size_t disk_out_sz, long *byte_offset)
{
	char resolved[4096], sys_path[4200], start_path[4200], link_path[4200];
	char *base;
	FILE *f;

	if (realpath(device, resolved) == NULL) {
		strncpy(resolved, device, sizeof(resolved) - 1);
		resolved[sizeof(resolved) - 1] = 0;
	}
	base = basename(resolved);
	snprintf(sys_path, sizeof(sys_path), "/sys/class/block/%s/partition", base);

	f = fopen(sys_path, "r");
	if (f == NULL) {
		strncpy(disk_out, device, disk_out_sz - 1);
		disk_out[disk_out_sz - 1] = 0;
		*byte_offset = 0;
		return;
	}
	fclose(f);

	snprintf(start_path, sizeof(start_path), "/sys/class/block/%s/start", base);
	f = fopen(start_path, "r");
	if (f != NULL) {
		long start = 0;
		if (fscanf(f, "%ld", &start) != 1) start = 0;
		fclose(f);
		*byte_offset = start * 512;
	} else {
		*byte_offset = 0;
	}

	snprintf(link_path, sizeof(link_path), "/sys/class/block/%s", base);
	{
		char parent_resolved[4096];
		if (realpath(link_path, parent_resolved) != NULL) {
			char *dirn = dirname(parent_resolved);
			char *pbase = basename(dirn);
			snprintf(disk_out, disk_out_sz, "/dev/%s", pbase);
		} else {
			strncpy(disk_out, device, disk_out_sz - 1);
			disk_out[disk_out_sz - 1] = 0;
		}
	}
}

static int read_header(const char *device, unsigned char *buf)
{
	char disk[4096];
	long byte_offset = 0;
	FILE *f;
	size_t n;

	resolve_disk(device, disk, sizeof(disk), &byte_offset);
	f = fopen(disk, "rb");
	if (f == NULL) {
		perror("fopen");
		return -1;
	}
	if (fseek(f, byte_offset, SEEK_SET) != 0) {
		perror("fseek");
		fclose(f);
		return -1;
	}
	n = fread(buf, 1, HEADER_SIZE, f);
	fclose(f);
	if (n != HEADER_SIZE) {
		fprintf(stderr, "short read on header\n");
		return -1;
	}
	return 0;
}

static void read_password(char *buf, size_t bufsz)
{
	const char *env = getenv("DC_PASSWORD");
	struct termios oldt, newt;

	if (env != NULL) {
		strncpy(buf, env, bufsz - 1);
		buf[bufsz - 1] = 0;
		return;
	}

	printf("password: ");
	fflush(stdout);

	if (tcgetattr(STDIN_FILENO, &oldt) == 0) {
		newt = oldt;
		newt.c_lflag &= ~ECHO;
		tcsetattr(STDIN_FILENO, TCSANOW, &newt);
	}

	if (fgets(buf, (int)bufsz, stdin) == NULL) {
		buf[0] = 0;
	} else {
		size_t len = strlen(buf);
		if (len > 0 && buf[len - 1] == '\n') buf[len - 1] = 0;
	}

	tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
	printf("\n");
}

static void bytes_to_hex(const unsigned char *data, size_t len, char *out)
{
	static const char hexd[] = "0123456789abcdef";
	size_t i;
	for (i = 0; i < len; i++) {
		out[i * 2] = hexd[data[i] >> 4];
		out[i * 2 + 1] = hexd[data[i] & 0xf];
	}
	out[len * 2] = 0;
}

static int get_device_size(const char *path, uint64_t *size_out)
{
	int fd = open(path, O_RDONLY);
	uint64_t sz;
	off_t end;

	if (fd < 0) {
		perror("open");
		return -1;
	}
	if (ioctl(fd, BLKGETSIZE64, &sz) == 0) {
		*size_out = sz;
		close(fd);
		return 0;
	}
	end = lseek(fd, 0, SEEK_END);
	close(fd);
	if (end < 0) {
		perror("lseek");
		return -1;
	}
	*size_out = (uint64_t)end;
	return 0;
}

static void hex_dump_line(const unsigned char *data, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++) {
		printf("%02x ", data[i]);
	}
	printf(" |");
	for (i = 0; i < len; i++) {
		printf("%c", (data[i] >= 32 && data[i] < 127) ? data[i] : '.');
	}
	printf("|\n");
}

/* Decrypt a single 512-byte sector directly (no cryptsetup needed) and check
   whether it looks like a plausible filesystem boot sector, for diagnostics. */
static void probe_boot_sector(const char *device, const unsigned char *data_key,
	long sector_offset)
{
	FILE *f;
	unsigned char ct[512], pt[512];
	int looks_ntfs, looks_fat, has_bootsig;

	f = fopen(device, "rb");
	if (f == NULL) {
		perror("fopen (probe)");
		return;
	}
	if (fseeko(f, (off_t)sector_offset * 512, SEEK_SET) != 0) {
		perror("fseeko (probe)");
		fclose(f);
		return;
	}
	if (fread(ct, 1, 512, f) != 512) {
		fprintf(stderr, "probe: short read\n");
		fclose(f);
		return;
	}
	fclose(f);

	xts_pass(&CIPHER_AES, data_key, data_key + 32, ct, 512, (uint64_t)sector_offset, 1, pt);

	has_bootsig = (pt[510] == 0x55 && pt[511] == 0xaa);
	looks_ntfs = (memcmp(pt + 3, "NTFS    ", 8) == 0);
	looks_fat = (memcmp(pt + 54, "FAT", 3) == 0) || (memcmp(pt + 82, "FAT32   ", 8) == 0);

	printf("probe: decrypted sector %ld, first 16 bytes:\n  ", sector_offset);
	hex_dump_line(pt, 16);
	printf("probe: boot signature 55AA present: %s\n", has_bootsig ? "yes" : "no");
	printf("probe: looks like NTFS: %s, looks like FAT: %s\n",
		looks_ntfs ? "yes" : "no", looks_fat ? "yes" : "no");
	if (!has_bootsig) {
		printf("probe: WARNING - no valid boot signature, offset/key is likely wrong\n");
	}
}

static void do_close(const char *mapper_name)
{
	char cmd[512];

	snprintf(cmd, sizeof(cmd), "dmsetup remove %s", mapper_name);
	printf("running: %s\n", cmd);
	if (system(cmd) != 0) {
		fprintf(stderr, "dmsetup remove failed (mapping may not exist)\n");
	}
}

static int run_dmsetup_create(const char *mapper_name, const char *table)
{
	char cmd[512];
	FILE *p;
	int rc;

	snprintf(cmd, sizeof(cmd), "dmsetup create %s", mapper_name);
	printf("running: %s\n", cmd);
	VLOG("with table:\n%s\n", table);
	p = popen(cmd, "w");
	if (p == NULL) {
		perror("popen");
		return -1;
	}
	fputs(table, p);
	rc = pclose(p);
	return rc == 0 ? 0 : -1;
}

static void reconstruct_and_mount(const char *device, const unsigned char *data_key,
	long reloc_off_sectors, int head_len_sectors, uint64_t dsk_size, const char *mapper_name)
{
	long head_len_bytes = (long)head_len_sectors * 512;
	long main_len_sectors;
	char hexkey[129];
	char table[2048];

	if ((long)dsk_size < 2 * head_len_bytes) {
		fprintf(stderr, "partition too small for expected layout\n");
		return;
	}
	main_len_sectors = (long)((dsk_size - 2ULL * (uint64_t)head_len_bytes) / 512);

	if (g_verbose) {
		printf("probing relocated segment (should contain the filesystem's boot sector):\n");
		probe_boot_sector(device, data_key, reloc_off_sectors);
	}

	bytes_to_hex(data_key, 64, hexkey);

	/* dm-crypt table format: <start> <count> crypt <cipher> <key> <iv_offset> <device> <device_offset>
	   device_offset is the physical sector to read from. iv_offset is +1 relative to that:
	   DiskCryptor's own tweak generator pre-increments the sector index before using it
	   (confirmed in its xts_fast.c: "idx.v64[0]++;" before the tweak encrypt call), whereas
	   the Linux kernel's plain64 IV generator uses the raw iv_sector with no adjustment
	   (crypt_iv_plain64_gen: "*(__le64 *)iv = cpu_to_le64(dmreq->iv_sector);"). Setting
	   iv_offset = device_offset + 1 makes the two conventions match. */
	snprintf(table, sizeof(table),
		"0 %ld crypt aes-xts-plain64 %s %ld %s %ld\n"
		"%ld %ld crypt aes-xts-plain64 %s %ld %s %ld",
		(long)head_len_sectors, hexkey, reloc_off_sectors + 1, device, reloc_off_sectors,
		(long)head_len_sectors, main_len_sectors, hexkey, (long)head_len_sectors + 1, device,
		(long)head_len_sectors);

	if (run_dmsetup_create(mapper_name, table) == 0) {
		printf("mapped to /dev/mapper/%s\n", mapper_name);
		VLOG("verify: first bytes of the mapping should look like a filesystem "
			"(e.g. NTFS boot sector), check with e.g. 'xxd /dev/mapper/%s | head'\n",
			mapper_name);
	} else {
		fprintf(stderr, "dmsetup create failed\n");
	}
}

static void do_mount(const char *device, const header_info_t *info,
	const char *mapper_name, int offset_sectors)
{
	int alg = info->alg_1;
	const cascade_t *casc;

	VLOG("data cipher: %s\n", ALGO_NAME(alg));

	if (alg != CF_AES) {
		int i;
		casc = &CASCADES[alg];
		printf("non-AES/cascade volume: mount not automated, use dmsetup manually with:\n");
		for (i = 0; i < casc->count; i++) {
			char ck[65], tk[65];
			bytes_to_hex(info->key_1 + i * 64, 32, ck);
			bytes_to_hex(info->key_1 + i * 64 + 32, 32, tk);
			printf("  layer %d (%s): crypt=%s tweak=%s\n", i, casc->names[i], ck, tk);
		}
		return;
	}

	if (info->flags & VF_NO_REDIR) {
		/* no relocation area: data starts directly at head_len, offset given by caller */
		uint64_t dsk_size;
		long len_sectors;
		char hexkey[129];
		char table[512];

		if (get_device_size(device, &dsk_size) != 0) {
			fprintf(stderr, "could not determine partition size\n");
			return;
		}
		len_sectors = (long)(dsk_size / 512) - offset_sectors;
		bytes_to_hex(info->key_1, 64, hexkey);
		snprintf(table, sizeof(table), "0 %ld crypt aes-xts-plain64 %s %d %s %d",
			len_sectors, hexkey, offset_sectors + 1, device, offset_sectors);
		if (run_dmsetup_create(mapper_name, table) == 0) {
			printf("mapped to /dev/mapper/%s\n", mapper_name);
		} else {
			fprintf(stderr, "dmsetup create failed\n");
		}
		return;
	}

	if (info->flags & VF_STORAGE_FILE) {
		long reloc_off_sectors;
		uint64_t dsk_size;

		if (info->stor_off == 0) {
			fprintf(stderr, "storage-file redirection offset is 0 (unexpected); aborting\n");
			return;
		}
		if (get_device_size(device, &dsk_size) != 0) {
			fprintf(stderr, "could not determine partition size\n");
			return;
		}
		reloc_off_sectors = (long)(info->stor_off / 512);
		VLOG("volume uses a storage-file redirection area at byte offset %llu"
			" (experimental: verify reconstructed output looks correct)\n",
			(unsigned long long)info->stor_off);
		reconstruct_and_mount(device, info->key_1, reloc_off_sectors, offset_sectors,
			dsk_size, mapper_name);
		return;
	}

	/* normal case: first head_len bytes of the filesystem are relocated to the
	   end of the partition to make room for the header. */
	{
		uint64_t dsk_size;
		long reloc_off_sectors;

		if (get_device_size(device, &dsk_size) != 0) {
			fprintf(stderr, "could not determine partition size\n");
			return;
		}
		reloc_off_sectors = (long)((dsk_size - (uint64_t)(offset_sectors * 512)) / 512);
		VLOG("volume uses relocation (boot sector stored at end of partition);"
			" reconstructing logical order\n");
		reconstruct_and_mount(device, info->key_1, reloc_off_sectors, offset_sectors,
			dsk_size, mapper_name);
	}
}

int main(int argc, char **argv)
{
	const char *device = NULL;
	const char *mapper_name = NULL;
	int offset_sectors = 4;
	char password[256];
	unsigned char raw[HEADER_SIZE];
	unsigned char dec[HEADER_SIZE];
	header_info_t info;
	int alg, i;
	int npositional = 0;

	signal(SIGPIPE, SIG_IGN);

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-v") == 0) {
			g_verbose = 1;
		}
	}

	if (argc >= 2 && strcmp(argv[1], "--close") == 0) {
		const char *name = NULL;
		for (i = 2; i < argc; i++) {
			if (strcmp(argv[i], "-v") != 0) {
				name = argv[i];
				break;
			}
		}
		if (name == NULL) {
			fprintf(stderr, "usage: %s --close <name>\n", argv[0]);
			return 1;
		}
		do_close(name);
		return 0;
	}

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--offset-sectors") == 0 && i + 1 < argc) {
			offset_sectors = atoi(argv[++i]);
		} else if (strcmp(argv[i], "-v") == 0) {
			g_verbose = 1;
		} else if (npositional == 0) {
			device = argv[i];
			npositional++;
		} else if (npositional == 1) {
			mapper_name = argv[i];
			npositional++;
		}
	}

	if (device == NULL || mapper_name == NULL) {
		fprintf(stderr, "usage: %s <device> <name> [--offset-sectors N] [-v]\n"
			"       %s --close <name>\n", argv[0], argv[0]);
		return 1;
	}

	read_password(password, sizeof(password));

	if (read_header(device, raw) != 0) {
		return 1;
	}

	alg = try_unlock(raw, password, dec);
	if (alg < 0) {
		fprintf(stderr, "could not unlock header: wrong password or unrecognized header\n");
		return 1;
	}

	printf("header unlocked, header cipher: %s\n", ALGO_NAME(alg));
	parse_header(dec, &info);
	VLOG("version=%u alg_1=%s alg_2=%s\n", info.version,
		ALGO_NAME(info.alg_1), info.alg_2 == -1 ? "none" : ALGO_NAME(info.alg_2));
	VLOG("flags=0x%02x [%s%s%s%s]\n", info.flags,
		(info.flags & VF_TMP_MODE) ? "TMP_MODE " : "",
		(info.flags & VF_REENCRYPT) ? "REENCRYPT " : "",
		(info.flags & VF_STORAGE_FILE) ? "STORAGE_FILE " : "",
		(info.flags & VF_NO_REDIR) ? "NO_REDIR " : "");
	VLOG("stor_off=%llu tmp_size=%llu\n",
		(unsigned long long)info.stor_off, (unsigned long long)info.tmp_size);

	do_mount(device, &info, mapper_name, offset_sectors);

	return 0;
}
