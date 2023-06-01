DRAFT=draft-ietf-mls-protocol
RFC=9420
RFC_ED_URL="https://www.rfc-editor.org/authors/rfc${RFC}.xml"

.PHONY: prepare gen diff

init:
	curl -s ${RFC_ED_URL} | \
		xmllint --exc-c14n - | \
		xmllint --format - \
		>rfc${RFC}.authors.xml 

gen: rfc${RFC}.gen.xml

rfc${RFC}.gen.xml: ../${DRAFT}.md
	make -C .. ${DRAFT}.xml
	mv ../${DRAFT}.xml .
	python3 xml-clean.py <${DRAFT}.xml | \
		xmllint --exc-c14n - | \
		xmllint --format - | \
		python3 text-clean.py >rfc${RFC}.gen.xml
	rm ${DRAFT}.xml

diff: rfc${RFC}.authors.xml rfc${RFC}.gen.xml
	mvim -d rfc${RFC}.gen.xml rfc${RFC}.authors.xml

clean:
	rm *.xml
