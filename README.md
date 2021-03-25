# moep80211ncm (network coding module)

[![Build & Test](https://github.com/Supereg/moep80211ncm-unidirectional-communication/actions/workflows/ncm.yml/badge.svg)](https://github.com/Supereg/moep80211ncm-unidirectional-communication/actions/workflows/ncm.yml)
[![Coverage Status](https://coveralls.io/repos/github/Supereg/moep80211ncm-unidirectional-communication/badge.svg?branch=master&t=dQb2mQ)](https://coveralls.io/github/Supereg/moep80211ncm-unidirectional-communication?branch=master)

The ncm daemon creates a coded mesh network - at least, it will do so in the
future.

## Project

Objective of the project was to replace the bidirectional session management
with a unidirectional session management. See [project_proposal](./project_proposal).

The project contains a full [CI setup](./.github/workflows/ncm.yml)
using GitHub Actions doing 
unit testing, code coverage reporting and memchecking using valgrind.
See [Running session unit tests](#running-session-unit-tests) on how to manually 
run unit tests and collect code coverage.

## Dependencies

The ncm depends on the libmoep injection library. If not done so far, install
libmoep:

	git clone moep@git.net.in.tum.de:moep/libmoep
	cd libmoep
	autoreconf -fi
	./configure
	make
	make install
	ldconfig

See the libmoep README for further instructions.

This project uses the `libcheck` framework for unit testing.
Refer to [Running session unit tests](#running-session-unit-tests)
for install instructions.

If you cloned this repository without --recursive, you have to checkout the
submodule libmoepgf:

	git submodule init
	git submodule update


## Installation

To compile and run the moep80211ncm type

	autoreconf -fi
	./configure
	make
	./ncm --help

The script deploy.sh aids in deploying the source to a temporary build
directory on a set of nodes via PSSH (or SSH) and compiling the sources.

## Running session unit tests

The unit tests for the session management rely on the [libcheck](https://libcheck.github.io/check/)
framework.
Refer to the [install instructions](https://libcheck.github.io/check/web/install.html) on how to install `libcheck`.
Steps for debian based systems are highlighted below:

```shell
apt install check
```

If you additionally want to capture code coverage you have to install the `lcov` dependency:

```shell
apt install lcov
```

**Running unit tests without code coverage reporting:**

```shell
autoreconf -fi
./configure
make
cd tests/ # see note below
make check
```

`libmoepgf` includes some long running benchmark tests which would be executed as well if running `make check`
in the root directory. To only run session tests you can switch to the `./tests` directory before calling `make check`.

`make check` builds **and** runs the test suite.
If the unit tests fails, log output will be place in `./tests/test-suite.log`.
Additionally, you may also call `./tests/check_session` manually to view full testing log output.

**Running unit tests with code coverage reporting:**

_Note: Unit tests with code coverage reporting run without any compiler optimizations._

```shell
autoreconf -fi
./configure --enable-code-coverage
make
cd tests/
make check
cd ..
make code-coverage-capture
```

`make code-coverage-capture` uses `lcov` to collect code coverage in a processable format.
The lcov file, which can be feed into other coverage displaying systems, is placed under `./ncm-coverage.info`.
Otherwise you may want to open `./ncm-coverage/index.html` to get a human readable visualization
of the collected code coverage.

