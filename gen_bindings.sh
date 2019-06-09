#!/bin/sh

if [ -z $JAVA_HOME ]; then
  echo JAVA_HOME is not set!
  exit 1
fi
if [ ! -f $JAVA_HOME/bin/jextract ]; then
  echo JAVA_HOME does not point to a OpenJDK 13 build!
  exit 1
fi

if [[ $OSTYPE =~ "darwin" ]]; then
  LIB_PATH=/usr/local/lib
  INC_PATH=/usr/local/include
elif [[ $OSTYPE =~ "linux" ]]; then
  LIB_PATH=/usr/lib64
  INC_PATH=/usr/include
else
  echo Unsupported os type - $OS_TYPE
  exit 1
fi

OUT_NAME=ssh2

echo generating ...

$JAVA_HOME/bin/jextract \
  -L $LIB_PATH -I $INC_PATH \
  -lssh2 \
  -t $OUT_NAME --record-library-path $INC_PATH/libssh2.h \
  -o lib/$OUT_NAME.jar --log INFO

echo done.

