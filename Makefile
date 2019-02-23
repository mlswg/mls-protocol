LIBDIR := lib
include $(LIBDIR)/main.mk

$(LIBDIR)/main.mk:
ifneq (,$(shell git submodule status $(LIBDIR) 2>/dev/null))
	git submodule sync
	git submodule update $(CLONE_ARGS) --init
else
	git clone -q --depth 10 $(CLONE_ARGS) \
	    -b master https://github.com/martinthomson/i-d-template $(LIBDIR)
endif

cleanup-netlify-cache:
	rm -rf ~/.bundle

fix-insecure-links:
	sed -i'.bak' -e 's/http:/https:/g' draft-ietf-mls-protocol.html
