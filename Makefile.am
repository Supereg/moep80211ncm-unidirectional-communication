
SUBDIRS = libmoepgf libmoeprlnc libjsm . src tests

@CODE_COVERAGE_RULES@

# defaults to $(PACKAGE_NAME)-$(PACKAGE_VERSION)-coverage[.info]
# which is a bit ugly, since we need the file name in CI steps
# thus including the package version isn't ideal
CODE_COVERAGE_OUTPUT_FILE = ncm-coverage.info
CODE_COVERAGE_OUTPUT_DIRECTORY = ncm-coverage

CODE_COVERAGE_IGNORE_PATTERN  = "/usr/include/*"
# When running ./configure in a separate build directory (e.g mkdir build && cd build && ../configure)
# $(abs_top_srcdir) isn't actually a absolute path (equals to something like "ROOT_DIR/build/..").
# The problem lcov can't resolve such relative paths in the --remove arg,
# thus we have to work with just excluding any /tests directory, which is probably fine
CODE_COVERAGE_IGNORE_PATTERN += "**/tests/*"
CODE_COVERAGE_IGNORE_PATTERN += "**/libmoepcommon/include/*"
