TESTBASE=/Regression/bz1972820-use_pty-with-SELinux-ROLE
export TEST=$(TESTBASE)$(if $(RELEASE),,/$(USER))
export TESTVERSION=$(shell echo -n `date +%Y%m%d%H%M%S`; \
        [ -n "`git status --porcelain --untracked-files=no`" ] && \
	    echo .`git rev-parse --short HEAD`)


define TESTMETA
Name:            $(TEST)
TestVersion:     $(TESTVERSION)
Path:            $(TESTBASE)
Priority:        Normal
License:         GPLv2+
Confidential:    no
Destructive:     no
RhtsRequires:    library(sudo/common)
Requires:        sudo
Requires:        expect
endef
export TESTMETA

FILES=$(METADATA) runtest.sh Makefile

run: $(FILES) build
	./runtest.sh

build:
	chmod a+x runtest.sh

include /usr/share/rhts/lib/rhts-make.include

$(METADATA): Makefile
	@echo "$$TESTMETA" > $@
	rhts-lint $@