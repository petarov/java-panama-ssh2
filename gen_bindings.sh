#!/bin/sh

if [ -z $JAVA_HOME ]; then
  echo JAVA_HOME is not set!
  exit 1
fi
if [ ! -f $JAVA_HOME/bin/jextract ]; then
  echo JAVA_HOME does not point to a OpenJDK 13 build!
  exit 1
fi

OUT_NAME=ssh2

echo generating ...

$JAVA_HOME/bin/jextract \
  -L /usr/local/lib -I /usr/local/include \
  -lssh2 \
  -t $OUT_NAME --record-library-path /usr/local/include/libssh2.h \
  -o lib/$OUT_NAME.jar --log INFO

echo done.
