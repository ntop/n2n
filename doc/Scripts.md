# Scripts

There are a number of useful scripts included with the distribution.
Some of these scripts are only useful during build and development, but
other scripts are intended for end users to be able to use.  These scripts
may be installed with n2n as part of your operating system package.

All scripts can be found in the `scripts` directory.

Short descriptions of these scripts are below.

## End user scripts

### `n2n-ctl`

This python script provides an easy command line interface to the running
n2n processes.  It uses UDP communications to talk to the Management API.
By specifying the right UDP port, it can talk to both the edge and the
supernode daemons.

Example:
- `scripts/n2n-ctl --help`
- `scripts/n2n-ctl help`

### `n2n-httpd`

This python script is a simple http gateway to the running edge.  It provides
a proxy for REST-like HTTP requests to talk to the Management API.

By default it runs on port 8080.

It also provides a simple HTML page showing some edge information, which when
run with default settings can be seen at http://localhost:8080/ (Also
a http://localhost:8080/supernode.html page for the supernode)

Example:
- `scripts/n2n-httpd --help`
- `scripts/n2n-httpd 8087`

## Build and Development scripts

### `hack_fakeautoconf.sh`

This shell script is used during development to help build on Windows
systems.  An example of how to use it is shown in
the [Building document](Building.md)

### `indent.sh`

This shell script is a wrapper for the `uncrustify` C code style checker
which checks or applies a set of rules to the code.  It is used during
the automated lint checks.

### `n2n-gateway.sh`

A sample script to route all the host traffic towards a remote gateway,
which is reachable via the n2n virtual interface.

### `version.sh`

This script is used to determine the current version number during the
build process.

It looks at both the VERSION file and the GIT tags and outputs the
version number to use.

## Monitoring and statistics

### `munin/n2n_`

This is a simple monitoring script that can be used with the munin-node
system to monitor the n2n daemons.

This is a fully autoconfigurable wildcard munin plugin, but to get a quick
sample:

get a list of suggested plugin names:
```
munin/n2n_ suggest
```

Enable some of those names:

```
ln -s /usr/share/munin/plugins/n2n_ /etc/munin/plugins/n2n_supernode_pkts
ln -s /usr/share/munin/plugins/n2n_ /etc/munin/plugins/n2n_supernode_counts
```

Manually test fetching and config:

```
/etc/munin/plugins/n2n_supernode_pkts
/etc/munin/plugins/n2n_supernode_pkts config
```

## Testing scripts

### `test_harness.sh`

This shell script is used to run automated tests during development.  It is
run with a testlist filename - pointing at a file containing the list of
tests to run.

Each test needs a file containing the expected output `${TESTNAME}.expected`
which is expected to exist in the same directory as the testlist (this dir is
referred to as `${listdir}` below).

Each test is a program, searched for in several locations, including the
`${listdir}/../scripts` dir.

Each test is run with its output being sent to `*.out` files in the `listdir`
and compared with the expected output.

### `scripts/test_integration_supernode.sh`

This starts a supernode and runs an integration test on the Json API using
the `n2n-ctl` command.
