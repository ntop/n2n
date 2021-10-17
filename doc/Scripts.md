# Scripts

There are a number of useful scripts included with the distribution.
Some of these scripts are only useful during build and development, but
other scripts are intended for end users to be able to use.  These scripts
may be installed with n2n as part of your operating system package.

Short descriptions of these scripts are below.

## `scripts/hack_fakeautoconf`

This shell script is used during development to help build on Windows
systems.  An example of how to use it is shown in
the [Duilding document](Building.md)

## `tools/test_harness`

This shell script is used to run automated tests during development.

## `scripts/n2nctl`

This python script provides an easy command line interface to the running
edge.  It uses UDP communications to talk to the Management API.

Example:
- `scripts/n2nctl --help`
- `scripts/n2nctl help`

## `scripts/n2nhttpd`

This python script is a simple http gateway to the running edge.  It provides
a proxy for REST-like HTTP requests to talk to the Management API.

By default it runs on port 8080.

It also provides a simple HTML page showing some information, which when
run with default settings can be seen at http://localhost:8080/

Example:
- `scripts/n2nhttpd --help`
- `scripts/n2nhttpd 8087`
