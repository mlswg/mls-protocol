---
title: Messaging Layer Security Protocol
abbrev: MLS Protocol
docname: draft-barnes-mls-protocol-latest
category: info

ipr: trust200902
area: Security
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -  ins: R. Barnes
    name: Richard Barnes
    organization: Cisco
    email: rlb@ipv.sx
 -
    ins: J. Millican
    name: Jon Millican
    organization: Facebook
    email: jmillican@fb.com
 -
    ins: E. Omara
    name: Emad Omara
    organization: Google
    email: emadomara@google.com
 -
    ins: K. Cohn-Gordon
    name: Katriel Cohn-Gordon
    organization: University of Oxford
    email: me@katriel.co.uk


normative:
  RFC2119:

informative:
        

--- abstract

Messaging applications are increasingly making use of end-to-end
security mechanisms to ensure that messages are only accessible to
the communicating endpoints, not any servers involved in delivering
messages.  Establishing keys to provide such protections is
challenging for group chat settings, in which more than two
participants need to agree on a key but may not be online at the same
time.  In this document, we specify a group key establishment
protocol that provides efficient asynchronous group key establishment
with forward secrecy and post-compromise security.


--- middle

# Introduction

[[ TODO - Group keying is necessary, but hard.  State of the art is
sender keys, which have bad FS / PCS and bad rekey efficiency ]]


# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in {{!RFC2119}}.


# Asynchronous Ratchet Trees

## Computing the Root Key

## Updating a Leaf Key Pair

## Adding a Leaf

## Removing a Leaf

# Session State

[[ Session comprised of (1) ART (2) pre-stage key (3) message key
chains ]]

[[ Each node caches... ]]

# Session Management

## State Machine

## Messages

### PreKey

### Initiate

### Add

### Update

# Security Considerations

[[ What trust is placed in the server? ]]

# IANA Considerations

# Acknowledgements

--- back
