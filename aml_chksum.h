#ifndef _AML_CHKSUM_H
#define _AML_CHKSUM_H

#define AML_SD_OFFSET (512)
#define AML_HEADER_OFFSET (16)
#define AML_HEADER_SIZE (64)
#define AML_CHKSUM_SIZE (32)
#define AML_HEADER_READ_SIZE (AML_HEADER_OFFSET + AML_HEADER_SIZE + AML_CHKSUM_SIZE)

// Below defines and struct is copied from arch/arm/cpu/armv8/common/firmware/plat/gxb/crypto/secureboot.c
// before bl2 code was removed in "ae6230b5aff5d02f03198d4f6a22e32ae2502447: Remove bl2 code"

#define AML_BLK_ID       (0x4C4D4140)
#define AML_BLK_VER_MJR  (1)
#define AML_BLK_VER_MIN  (0)

typedef struct __st_aml_block_header{
	//16
	unsigned int   dwMagic;       //"@AML"
	unsigned int   nTotalSize;    //total size: sizeof(hdr)+
	                              //  nSigLen + nDataLen
	unsigned char  bySizeHdr;     //sizeof(st_aml_block)
	unsigned char  byRootKeyIndex;//root key index; only romcode
	                              //  will use it, others just skip
	unsigned char  byVerMajor;    //major version
	unsigned char  byVerMinor;    //minor version

	unsigned char  szPadding1[4]; //padding???

	//16+16
	unsigned int   nSigType;      //e_aml_sig_type : AML_SIG_TYPE_NONE...
	unsigned int   nSigOffset;	  //sig data offset, include header
	unsigned int   nSigLen;       //sig data length
	//unsigned char  szPadding2[4]; //padding???
	unsigned int   nCHKStart;     //begin to be protected with SHA2

	//32+16
	unsigned int   nPUKType;     //e_aml_data_type : AML_DATA_TYPE_PROGRAM
	unsigned int   nPUKOffset;   //raw data offset, include header
	unsigned int   nPUKDataLen;	 //raw data length
	//unsigned char  szPadding4[4]; //padding???
	unsigned int   nCHKSize;     //size to be protected with SHA2

	//48+16
	unsigned int   nDataType;     //e_aml_data_type : AML_DATA_TYPE_PROGRAM
	unsigned int   nDataOffset;   //raw data offset, include header
	unsigned int   nDataLen;	  //raw data length
	unsigned char  szPadding3[4]; //padding???

	//64
} st_aml_block_header;

#endif /* _AML_CHKSUM_H */
