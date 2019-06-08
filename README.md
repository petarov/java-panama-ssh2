java-panama-ssh2
===================

A simple demo SSH2 client using the native [libssh2](https://www.libssh2.org) library and JDK 13 [Project Panama.
 ](https://openjdk.java.net/projects/panama/)
 
NOTE: This is an experimental project. Stability is not guaranteed.

## Requirements

Make sure `libssh2` is installed. 

    brew install libssh2

Get the latest Panama [JDK build](http://jdk.java.net/panama/). 
 
Configure the `JAVA_HOME` var to point to the downloaded JDK in your console.
 
To generate Java interfaces from the native headers run:
    
    ./gen_bindings.sh

## Run
    
To compile the code and run use:

    ./run.sh [-p|-k] hostname port username
    
  * `-p` uses a password login
  * `-k` uses a public key login
  
## Licnese

MIT