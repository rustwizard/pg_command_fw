PG_CONFIG    ?= pg_config

PG_VER       := $(shell $(PG_CONFIG) --version | grep -oE '[0-9]+' | head -1)
PG_PKGLIBDIR := $(shell $(PG_CONFIG) --pkglibdir)
PG_SHAREDIR  := $(shell $(PG_CONFIG) --sharedir)
PG_BINDIR    := $(shell $(PG_CONFIG) --bindir)

EXTENSION    = pg_command_fw
VERSION      := $(shell grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
PACKAGE_DIR  = target/release/$(EXTENSION)-pg$(PG_VER)

# .so on Linux, .dylib on macOS
UNAME_S      := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    LIB_EXT = dylib
else
    LIB_EXT = so
endif

PGXN_ZIP     = $(EXTENSION)-$(VERSION).zip

.PHONY: all package install clean pgxn-zip

all: package

package:
	cargo pgrx package --pg-config $(PG_CONFIG)

install: package
	install -m 755 \
		"$(PACKAGE_DIR)$(PG_PKGLIBDIR)/$(EXTENSION).$(LIB_EXT)" \
		"$(PG_PKGLIBDIR)/"
	install -m 644 \
		"$(PACKAGE_DIR)$(PG_SHAREDIR)/extension/$(EXTENSION).control" \
		"$(PG_SHAREDIR)/extension/"
	install -m 644 \
		"$(PACKAGE_DIR)$(PG_SHAREDIR)/extension/$(EXTENSION)"--*.sql \
		"$(PG_SHAREDIR)/extension/"

pgxn-zip:
	git archive --format=zip --prefix=$(EXTENSION)-$(VERSION)/ HEAD \
		-o $(PGXN_ZIP)
	@echo "Created $(PGXN_ZIP)"

clean:
	cargo clean
