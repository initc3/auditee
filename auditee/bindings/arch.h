/*
 * Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


//#include "inst.h"
//#include "se_types.h"
//#include "sgx_attributes.h"
//#include "sgx_key.h"
//#include "sgx_report.h"
//#include "sgx_tcrypto.h"

/*
 *  This file is to define Enclave's Report
*/
#define SGX_HASH_SIZE        32              /* SHA256 */

#define SGX_REPORT_DATA_SIZE    64

#define SGX_ISVEXT_PROD_ID_SIZE 16
#define SGX_ISV_FAMILY_ID_SIZE  16

typedef struct _sgx_measurement_t
{
    uint8_t                 m[SGX_HASH_SIZE];
} sgx_measurement_t;

typedef uint16_t            sgx_prod_id_t;

typedef uint8_t sgx_isvext_prod_id_t[SGX_ISVEXT_PROD_ID_SIZE];
typedef uint8_t sgx_isvfamily_id_t[SGX_ISV_FAMILY_ID_SIZE];


/****************************************************************************
* Definitions for enclave signature
****************************************************************************/
typedef struct _attributes_t
{
    uint64_t      flags;
    uint64_t      xfrm;
} sgx_attributes_t;

/* define MISCSELECT - all bits are currently reserved */
typedef uint32_t    sgx_misc_select_t;
//
//typedef struct _sgx_misc_attribute_t {
//    sgx_attributes_t    secs_attr;
//    sgx_misc_select_t   misc_select;
//} sgx_misc_attribute_t;



#define SE_KEY_SIZE         384         /* in bytes */
#define SE_EXPONENT_SIZE    4           /* RSA public key exponent size in bytes */


typedef struct _css_header_t {        /* 128 bytes */
    uint8_t  header[12];                /* (0) must be (06000000E100000000000100H) */
    uint32_t type;                      /* (12) bit 31: 0 = prod, 1 = debug; Bit 30-0: Must be zero */
    uint32_t module_vendor;             /* (16) Intel=0x8086, ISV=0x0000 */
    uint32_t date;                      /* (20) build date as yyyymmdd */
    uint8_t  header2[16];               /* (24) must be (01010000600000006000000001000000H) */
    uint32_t hw_version;                /* (40) For Launch Enclaves: HWVERSION != 0. Others, HWVERSION = 0 */
    uint8_t  reserved[84];              /* (44) Must be 0 */
} css_header_t;
//se_static_assert(sizeof(css_header_t) == 128);

typedef struct _css_key_t {           /* 772 bytes */
    uint8_t modulus[SE_KEY_SIZE];       /* (128) Module Public Key (keylength=3072 bits) */
    uint8_t exponent[SE_EXPONENT_SIZE]; /* (512) RSA Exponent = 3 */
    uint8_t signature[SE_KEY_SIZE];     /* (516) Signature over Header and Body */
} css_key_t;
//se_static_assert(sizeof(css_key_t) == 772);

typedef struct _css_body_t {             /* 128 bytes */
    sgx_misc_select_t    misc_select;    /* (900) The MISCSELECT that must be set */
    sgx_misc_select_t    misc_mask;      /* (904) Mask of MISCSELECT to enforce */
    uint8_t              reserved[4];    /* (908) Reserved. Must be 0. */
    sgx_isvfamily_id_t   isv_family_id;  /* (912) ISV assigned Family ID */
    sgx_attributes_t     attributes;     /* (928) Enclave Attributes that must be set */
    sgx_attributes_t     attribute_mask; /* (944) Mask of Attributes to Enforce */
    sgx_measurement_t    enclave_hash;   /* (960) MRENCLAVE - (32 bytes) */
    uint8_t              reserved2[16];  /* (992) Must be 0 */
    sgx_isvext_prod_id_t isvext_prod_id; /* (1008) ISV assigned Extended Product ID */
    uint16_t             isv_prod_id;    /* (1024) ISV assigned Product ID */
    uint16_t             isv_svn;        /* (1026) ISV assigned SVN */
} css_body_t;
//se_static_assert(sizeof(css_body_t) == 128);

typedef struct _css_buffer_t {         /* 780 bytes */
    uint8_t  reserved[12];              /* (1028) Must be 0 */
    uint8_t  q1[SE_KEY_SIZE];           /* (1040) Q1 value for RSA Signature Verification */
    uint8_t  q2[SE_KEY_SIZE];           /* (1424) Q2 value for RSA Signature Verification */
} css_buffer_t;
//se_static_assert(sizeof(css_buffer_t) == 780);

typedef struct _enclave_css_t {        /* 1808 bytes */
    css_header_t    header;             /* (0) */
    css_key_t       key;                /* (128) */
    css_body_t      body;               /* (900) */
    css_buffer_t    buffer;             /* (1028) */
} enclave_css_t;

//se_static_assert(sizeof(enclave_css_t) == 1808);
