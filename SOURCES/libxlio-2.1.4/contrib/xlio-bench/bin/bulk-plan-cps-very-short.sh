BULK_CLIENT_MHOST="vma-nolo05 r-aa-fatty01"
BULK_SERVER_MHOST=vma-nolo06
BULK_SERVER_DHOST=163.2.0.6

BULK_TYPE="cps"
BULK_PROTOS="https"
BULK_THREADS="32"
BULK_PAYLOADS="0B"
BULK_CONNECTIONS="2400"
BULK_STEP_DURATION="15"
BULK_TLS_MODE="sw"

# BULK_ENV_LIST as multiline string
read -r -d '' BULK_ENV_LIST << 'EOF' || true
# mode  proto   payload threads connections host         env
*       *       *       *       *           vma-nolo05   default-x86
*       *       *       *       *           vma-nolo06   default-x86
*       *       *       *       *           r-aa-fatty01 default-x86
EOF
