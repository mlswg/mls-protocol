Approving AUTH48 with Markdown Alignment
====================================================

The Makefile included in this directory provides some quick commands to
facilitate AUTH48 negotiations.  You should update the `RFC` variable to reflect
your assigned RFC number and the `DRAFT` variable to reflect your draft name.

The overall process flow here is:

1. RFC Editor provides XML file in email.  This becomes the basis of the
   authors' XML file, which will include the authors' proposed changes to the
   RFC Editor's XML.
2. Authors generate an XML file from the WG's Markdown file.
3. Authors review the diff between generated XML file and the authors' XML file.
   * Changes that the authors approve of should be reflected in the Markdown
     (and thus the generated XML)
   * Changes that the authors reject should be reverted in the authors' XML
     file.
4. Steps 2 and 3 are repeated until there are effectively no differences between
   the generated and authors XML files (some XML technicalities may remain). At
   this point, the authors' XML file reflects only the approved changes, and the
   approved changes are reflected in the Markedown.
5. Authors reply to the RFC editor with the authors' XML file.  If there are
   further rounds of negotiation, the process repeats.

## Initializing the repo

```
make init
```

This command downloads the RFC Editor's proposed XML file and canonicalizes it
to facilitate comparison.  The canonicalized XML is the basis for the authors'
XML file, which we will use to communicate changes back to the RFC Editor.

This should only be done once.  If you re-run `make init` again after making
changes to the authors' XML file, it will reset the authors' XML file to a
pristine state.

## Generating the XML

```
make gen
```

This command generates the XML from the WG's Markdown file, applies some
normalization to deal with known incompatibilities between `kramdown-rfc` and
the RFC Editor's XML, and canonicalizes it.  While `make diff` will
auto-generate the generated XML if it is not present, this command can be useful
for regenerating once the diff is open, after making changes to the Markdown.


## Reviewing the diff

```
make diff
```

This command generates the XML from the WG's Markdown file and opens a MacVim
window with a diff between the generated XML and the authors' XML.  (For
non-macOS platforms, you can change `mvim -d` to `vimdiff`.)  In this view, you
can make edits to the authors' XML file to reflect gaps from the generated XML.
To make edits to the generated XML file, put the edits in the Markdown and run
`make gen`.
