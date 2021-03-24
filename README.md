# moep80211ncm (network coding module)

[![Build & Test](https://github.com/Supereg/moep80211ncm-unidirectional-communication/actions/workflows/ncm.yml/badge.svg)](https://github.com/Supereg/moep80211ncm-unidirectional-communication/actions/workflows/ncm.yml)
[![Coverage Status](https://coveralls.io/repos/github/Supereg/moep80211ncm-unidirectional-communication/badge.svg?branch=master&t=dQb2mQ)](https://coveralls.io/github/Supereg/moep80211ncm-unidirectional-communication?branch=master)

The ncm daemon creates a coded mesh network - at least, it will do so in the
future.

## Project Notes




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

