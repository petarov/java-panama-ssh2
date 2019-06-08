#!/bin/sh

if [ -z $JAVA_HOME ]; then
  echo JAVA_HOME is not set!
  exit 1
fi
if [ ! -f $JAVA_HOME/bin/jextract ]; then
  echo JAVA_HOME does not point to a OpenJDK 13 build!
  exit 1
fi

$JAVA_HOME/bin/javac -cp lib/ssh2.jar src/main/java/Main.java 
$JAVA_HOME/bin/java -Djava.library.path=/usr/local/lib -cp lib/ssh2.jar:./src/main/java/ Main $@
