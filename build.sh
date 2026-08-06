#!/bin/sh
set -e

CC=${CC:-cc}
CFLAGS=${CFLAGS:-"-O2 -Wall"}
LDFLAGS=${LDFLAGS:-""}

SRC_DIR="src"
OUT="dcrypt_tool"

SOURCES="$SRC_DIR/main.c $SRC_DIR/xts.c $SRC_DIR/crc32.c $SRC_DIR/aes_small.c $SRC_DIR/twofish_small.c $SRC_DIR/serpent_small.c $SRC_DIR/sha512_small.c $SRC_DIR/sha512_pkcs5_2_small.c"

$CC $CFLAGS -I"$SRC_DIR" $SOURCES -o "$OUT" $LDFLAGS

echo "built ./$OUT"
