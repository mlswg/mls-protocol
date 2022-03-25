LIBDIR := lib
include $(LIBDIR)/main.mk

$(LIBDIR)/main.mk:
ifneq (,$(shell grep "path *= *$(LIBDIR)" .gitmodules 2>/dev/null))
	git submodule sync
	git submodule update $(CLONE_ARGS) --init
else
	git clone -q --depth 10 $(CLONE_ARGS) \
	    -b main https://github.com/martinthomson/i-d-template $(LIBDIR)
endif

fix-insecure-links:
	sed -i'.bak' -e 's/http:/https:/g' draft-ietf-mls-protocol.html

extract-tls:
	cat draft-ietf-mls-protocol.md | python3 extract-tls.py > draft-ietf-mls-protocol.tls

#extract-tls:
#	cat draft-ietf-mls-protocol.md | python3 -c 'exec("""import sys, re\nmatch = False\nfor line in sys.stdin:\n if match:\n  if re.match("^~~~$", line):\n   match = False\n   print ("")\n  else:\n   print (line.rstrip())\n elif re.match("^~~~ tls$", line):\n  match = True\n""")' > draft-ietf-mls-protocol.tls
