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
elif [[ $OSTYPE =~ "linux" ]]; then
  LIB_PATH=/usr/lib64
else
  echo Unsupported os type - $OS_TYPE
  exit 1
fi

$JAVA_HOME/bin/javac -cp lib/ssh2.jar src/main/java/Main.java
$JAVA_HOME/bin/java -Djava.library.path=$LIB_PATH -cp lib/ssh2.jar:./src/main/java/ Main $@