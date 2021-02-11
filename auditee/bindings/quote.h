#define SGX_CPUSVN_SIZE 16
#define SGX_CONFIGID_SIZE 64
#define SGX_REPORT_BODY_RESERVED1_BYTES 12
#define SGX_REPORT_BODY_RESERVED2_BYTES 32
#define SGX_REPORT_BODY_RESERVED3_BYTES 32
#define SGX_REPORT_BODY_RESERVED4_BYTES 42
#define SGX_ISVEXT_PROD_ID_SIZE 16
#define SGX_ISV_FAMILY_ID_SIZE 16
#define SGX_HASH_SIZE 32
#define SGX_REPORT_DATA_SIZE 64

typedef uint8_t sgx_key_128bit_t[16];
typedef uint16_t sgx_config_svn_t;
typedef uint8_t sgx_config_id_t[SGX_CONFIGID_SIZE];
typedef uint32_t sgx_misc_select_t;
typedef uint8_t sgx_epid_group_id_t[4];
typedef uint16_t sgx_isv_svn_t;
typedef uint8_t sgx_isvext_prod_id_t[SGX_ISVEXT_PROD_ID_SIZE];
typedef uint8_t sgx_isvfamily_id_t[SGX_ISV_FAMILY_ID_SIZE];
typedef uint16_t sgx_prod_id_t;

typedef struct _sgx_cpu_svn_t
{
    uint8_t                        svn[SGX_CPUSVN_SIZE];
} sgx_cpu_svn_t;

typedef struct _basename_t
{
    uint8_t             name[32];
} sgx_basename_t;

typedef struct _attributes_t
{
    uint64_t      flags;
    uint64_t      xfrm;
} sgx_attributes_t;

typedef struct _sgx_measurement_t
{
    uint8_t                 m[SGX_HASH_SIZE];
} sgx_measurement_t;

typedef struct _sgx_report_data_t
{
    uint8_t                 d[SGX_REPORT_DATA_SIZE];
} sgx_report_data_t;

typedef struct _report_body_t
{
    sgx_cpu_svn_t           cpu_svn;        /* (  0) Security Version of the CPU */
    sgx_misc_select_t       misc_select;    /* ( 16) Which fields defined in SSA.MISC */
    uint8_t                 reserved1[SGX_REPORT_BODY_RESERVED1_BYTES];  /* ( 20) */
    sgx_isvext_prod_id_t    isv_ext_prod_id;/* ( 32) ISV assigned Extended Product ID */
    sgx_attributes_t        attributes;     /* ( 48) Any special Capabilities the Enclave possess */
    sgx_measurement_t       mr_enclave;     /* ( 64) The value of the enclave's ENCLAVE measurement */
    uint8_t                 reserved2[SGX_REPORT_BODY_RESERVED2_BYTES];  /* ( 96) */
    sgx_measurement_t       mr_signer;      /* (128) The value of the enclave's SIGNER measurement */
    uint8_t                 reserved3[SGX_REPORT_BODY_RESERVED3_BYTES];  /* (160) */
    sgx_config_id_t         config_id;      /* (192) CONFIGID */
    sgx_prod_id_t           isv_prod_id;    /* (256) Product ID of the Enclave */
    sgx_isv_svn_t           isv_svn;        /* (258) Security Version of the Enclave */
    sgx_config_svn_t        config_svn;     /* (260) CONFIGSVN */
    uint8_t                 reserved4[SGX_REPORT_BODY_RESERVED4_BYTES];  /* (262) */
    sgx_isvfamily_id_t      isv_family_id;  /* (304) ISV assigned Family ID */
    sgx_report_data_t       report_data;    /* (320) Data provided by the user */
} sgx_report_body_t;

typedef struct _quote_t
{
    uint16_t            version;        /* 0   */
    uint16_t            sign_type;      /* 2   */
    sgx_epid_group_id_t epid_group_id;  /* 4   */
    sgx_isv_svn_t       qe_svn;         /* 8   */
    sgx_isv_svn_t       pce_svn;        /* 10  */
    uint32_t            xeid;           /* 12  */
    sgx_basename_t      basename;       /* 16  */
    sgx_report_body_t   report_body;    /* 48  */
    uint32_t            signature_len;  /* 432 */
    uint8_t             signature[];    /* 436 */
} sgx_quote_t;
