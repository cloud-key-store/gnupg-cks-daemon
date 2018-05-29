Cloud Key Store - secure storage for private credentials
========================================================

Introduction
------------

Cloud Key Store (CKS) is a tool to protect private cryptographic keys in the cloud.
It performs cryptographic operations using the keys based on user requests.
The user authentication is password based.
An example usage is to store GnuPG private keys.
This repository contains an example of a GnuPG smart card that can substitute
the original daemon in order for GnuPG to utilize the CKS to store the keys.

Building instructions
---------------------

### Prerequisites

- Install build-utils and autotools:
  * Run autoreconf that will generate configure script
  * Run ./configure
  * Install missing dependencies as reported by the configure script

### Building the daemon

  * Run `make`. This will produce `./src/gnupg-cks-scd`.

Executing
---------

Pass the path to the executable to the agent as a parameter to `--scdaemon-program` option.
Have the CKS running at default `localhost:7000`.
Now the cards operations will be redirected to the CKS server.
