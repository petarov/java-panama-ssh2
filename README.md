java-panama-ssh2
===================

A simple Java SSH2 client using the native [libssh2](https://www.libssh2.org) library and JDK 13 [Project Panama.
 ](https://openjdk.java.net/projects/panama/)
 
NOTE: This is an experimental project. Stability is not guaranteed.

## Install

The client has been tested on macOS and Linux. It should also be possible to run it on Windows, however, no work has been done in that direction. PRs are welcome!

Install `libssh2`. 

  * macOS - `brew install libssh2`
  * CentOS - `yum install libssh2.x86_64 libssh2-devel.x86_64`

Get the latest Panama [JDK build](http://jdk.java.net/panama/). 
 
Open a console shell and configure the `JAVA_HOME` var to point to JDK 13.
 
Generate the required Java interfaces from the native libssh2 headers:
    
    ./gen_bindings.sh

## Run
    
To compile and run use:

    ./run.sh [-p|-k] hostname port username [path to ssh keys]
    
  * `-p` uses a password login. You'll be prompted to enter your password.
  * `-k` uses a public key login. You'll need to specify the path to your keys, e.g., `~/.ssh`.
  
## License

MIT