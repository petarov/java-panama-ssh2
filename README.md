java-panama-ssh2
===================

A simple Java SSH2 client using the native [libssh2](https://www.libssh2.org) library and JDK 13 [Project Panama.
 ](https://openjdk.java.net/projects/panama/)
 
NOTE: This is an experimental project. Stability is not guaranteed.

## Requirements

Install `libssh2`. 

    brew install libssh2

Get the latest Panama [JDK build](http://jdk.java.net/panama/). 
 
Open a console shell and configure the `JAVA_HOME` var to point to JDK 13.
 
Generate the required Java interfaces from the native libssh2 headers:
    
    ./gen_bindings.sh

## Run
    
To compile and run use:

    ./run.sh [-p|-k] hostname port username [path to ssh keys]
    
  * `-p` uses a password login. You'll be prompted to enter your password.
  * `-k` uses a public key login. You'll need to specify the path to your keys, e.g., `~/.ssh`.
  
## Licnese

MIT