/*
 * SPDX-License-Identifier:	GPL-2.0+
 */

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "aml_chksum.h"
#include "sha256.h"

static void printf_sha256_sum(const char *format, const uint8_t *sum)
{
	int index = 0;
	char str[SHA256_SUM_LEN * 2 + 1];

	str[0] = '\0';
	for (index = 0; index < SHA256_SUM_LEN; ++index) {
		sprintf(str, "%s%02x", str, sum[index]);
	}
	printf(format, str);
}

int main(int argc, char **argv)
{
	// aml_chksum takes one argument with the path to a u-boot.bin
	if (argc < 2) {
		printf("ERROR: Missing filename.\n");
		return EINVAL;
	}
	char *filename = argv[1];

	FILE *fp = fopen(filename, "r+b");
	if (fp == NULL) {
		printf("Error: Cannot open file \"%s\": %s\n", filename, strerror(errno));
		return errno;
	}

	// read header data from 0
	uint8_t *header_buffer = calloc(AML_HEADER_READ_SIZE, sizeof(uint8_t));
	if (fseek(fp, 0, SEEK_SET) != 0) {
		printf("ERROR: Cannot seek to header: %s\n", strerror(errno));
		return errno;
	}
	int read_header_size = fread(header_buffer, sizeof(uint8_t), AML_HEADER_READ_SIZE, fp);
	if (read_header_size != AML_HEADER_READ_SIZE) {
		printf("ERROR: Cannot read header: %s\n", strerror(errno));
		return errno;
	}

	// basic header check
	st_aml_block_header *header = (st_aml_block_header *)(header_buffer + AML_HEADER_OFFSET);
	if (header->dwMagic != AML_BLK_ID ||
		header->byVerMajor != AML_BLK_VER_MJR ||
		header->byVerMinor != AML_BLK_VER_MIN ||
		header->bySizeHdr != AML_HEADER_SIZE ||
		header->nSigType != 0 ||
		header->nPUKType != 0) {
		printf("ERROR: Bad header.\n");
		return EINVAL;
	}

	// sha256 sum is the 32b following the header
	uint8_t *origSum = (header_buffer + AML_HEADER_OFFSET + AML_HEADER_SIZE);

	printf("nTotalSize=%u\n", header->nTotalSize);
	printf("nCHKStart=%u\n", header->nCHKStart);
	printf("nCHKSize=%u\n", header->nCHKSize);
	printf("nDataOffset=%u\n", header->nDataOffset);
	printf("nDataLen=%u\n", header->nDataLen);
	printf_sha256_sum("origSum=%s\n", origSum);

	// initialize sha context
	uint8_t genSum[SHA256_SUM_LEN];
    sha256_context ctx;
	sha256_starts(&ctx);

	// start with header
	sha256_update(&ctx, (uint8_t *)header, AML_HEADER_SIZE);

	// read raw data starting from header position + chk start
	uint8_t *data_buffer = calloc(header->nCHKSize, sizeof(uint8_t));
	if (fseek(fp, AML_HEADER_OFFSET + header->nCHKStart, SEEK_SET) != 0) {
		printf("ERROR: Cannot seek to data: %s\n", strerror(errno));
		return errno;
	}
	int read_data_size = fread(data_buffer, sizeof(uint8_t), header->nCHKSize, fp);
	if (read_data_size != header->nCHKSize) {
		printf("ERROR: Cannot read data: %s\n", strerror(errno));
		return errno;
	}

	// append raw data and finish
	sha256_update(&ctx, data_buffer, header->nCHKSize);
	sha256_finish(&ctx, genSum);
	printf_sha256_sum("genSum=%s\n", genSum);

	// clone header
	uint8_t *sd_header_buffer = calloc(AML_HEADER_READ_SIZE, sizeof(uint8_t));
	memcpy(sd_header_buffer, header_buffer, AML_HEADER_READ_SIZE);
	st_aml_block_header *sd_header = (st_aml_block_header *)(sd_header_buffer + AML_HEADER_OFFSET);
	uint8_t *sdSum = (sd_header_buffer + AML_HEADER_OFFSET + AML_HEADER_SIZE);

	// update sd header
	sd_header->nTotalSize -= AML_SD_OFFSET;
	sd_header->nDataLen -= AML_SD_OFFSET;
	sd_header->nCHKStart = AML_HEADER_SIZE + AML_CHKSUM_SIZE; // start after checksum
	sd_header->nCHKSize = sd_header->nTotalSize - sd_header->nCHKStart; // must be less then total size, bl1 only reads ~48kb to memory
	printf("nTotalSize=%u\n", sd_header->nTotalSize);
	printf("nCHKStart=%u\n", sd_header->nCHKStart);
	printf("nCHKSize=%u\n", sd_header->nCHKSize);
	printf("nDataOffset=%u\n", sd_header->nDataOffset);
	printf("nDataLen=%u\n", sd_header->nDataLen);

	// read raw data starting from sd header position + chk start
	free(data_buffer);
	data_buffer = calloc(sd_header->nCHKSize, sizeof(uint8_t));
	if (fseek(fp, AML_SD_OFFSET + AML_HEADER_OFFSET + sd_header->nCHKStart, SEEK_SET) != 0) {
		printf("ERROR: Cannot seek to data: %s\n", strerror(errno));
		return errno;
	}
	read_data_size = fread(data_buffer, sizeof(uint8_t), sd_header->nCHKSize, fp);
	if (read_data_size != sd_header->nCHKSize) {
		printf("ERROR: Cannot read data: %s\n", strerror(errno));
		return errno;
	}

	// calculate checksum for sd header
	sha256_starts(&ctx);
	sha256_update(&ctx, (uint8_t *)sd_header, AML_HEADER_SIZE);
	sha256_update(&ctx, data_buffer, sd_header->nCHKSize);
	sha256_finish(&ctx, sdSum);
	printf_sha256_sum("sdSum=%s\n", sdSum);

	// write sd header to 512
	if (fseek(fp, AML_SD_OFFSET, SEEK_SET) != 0) {
		printf("ERROR: Cannot seek to sd header: %s\n", strerror(errno));
		return errno;
	}
	int write_size = fwrite(sd_header_buffer, sizeof(uint8_t), AML_HEADER_READ_SIZE, fp);
	if (write_size != AML_HEADER_READ_SIZE) {
		printf("ERROR: Cannot write sd header: %s\n", strerror(errno));
		return errno;
	}
	fflush(fp);

	// new header
	header->nCHKStart = AML_SD_OFFSET - AML_HEADER_OFFSET; // must be 496+ for MBR support
	header->nCHKSize = header->nTotalSize - header->nCHKStart; // must be less then total size, bl1 only reads ~48kb to memory
	header->nDataOffset = 1024 - 16; // point to code that copies bl2 from 4608 to 4096
	header->nDataLen = header->nTotalSize - header->nDataOffset;
	printf("nCHKStart=%u\n", header->nCHKStart);
	printf("nCHKSize=%u\n", header->nCHKSize);
	printf("nDataOffset=%u\n", header->nDataOffset);
	printf("nDataLen=%u\n", header->nDataLen);

	// read raw data starting from new header position + chk start
	free(data_buffer);
	data_buffer = calloc(header->nCHKSize, sizeof(uint8_t));
	if (fseek(fp, AML_HEADER_OFFSET + header->nCHKStart, SEEK_SET) != 0) {
		printf("ERROR: Cannot seek to data: %s\n", strerror(errno));
		return errno;
	}
	read_data_size = fread(data_buffer, sizeof(uint8_t), header->nCHKSize, fp);
	if (read_data_size != header->nCHKSize) {
		printf("ERROR: Cannot read data: %s\n", strerror(errno));
		return errno;
	}

	// calculate checksum for new header
	sha256_starts(&ctx);
	sha256_update(&ctx, (uint8_t *)header, AML_HEADER_SIZE);
	sha256_update(&ctx, data_buffer, header->nCHKSize);
	sha256_finish(&ctx, origSum);
	printf_sha256_sum("newSum=%s\n", origSum);

	// write new header to 0
	if (fseek(fp, 0, SEEK_SET) != 0) {
		printf("ERROR: Cannot seek to header: %s\n", strerror(errno));
		return errno;
	}
	write_size = fwrite(header_buffer, sizeof(uint8_t), AML_HEADER_READ_SIZE, fp);
	if (write_size != AML_HEADER_READ_SIZE) {
		printf("ERROR: Cannot write header: %s\n", strerror(errno));
		return errno;
	}
	fflush(fp);

	fclose(fp);
	free(data_buffer);
	free(header_buffer);
	free(sd_header_buffer);
	return 0;
}

