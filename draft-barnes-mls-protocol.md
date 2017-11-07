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

Groups of agents who want to send each other encrypted messages need
a way to derive shared symmetric encryption keys. For two parties
this problem has been studied thoroughly, with the Double Ratchet
emerging as a common solution; channels implementing the Double
Ratchet enjoy fine-grained forward secrecy as well as post-compromise
security, but are nonetheless efficient enough for heavy use over
low-bandwidth networks.

For groups of size greater than two, the state of the art is to
unilaterally broadcast symmetric "sender" keys over existing shared
symmetric channels, and then for each agent to send messages to the
group encrypted with their own sender key. Unfortunately, while this
is efficient and (with the addition of a hash ratchet) provides
forward secrecy, it does not have post-compromise security. An
adversary who learns a sender key can therefore indefinitely and
passively eavesdrop on that sender's messages.

Rekeying, or generating new sender keys, provides a form of
post-compromise security. However, it requires a separate message to
each potential receiver. In this document we describe a tree-based
system for deriving group keys which provides post-compromise
security with efficient rekeys and without requiring any two parties
to be online concurrently.

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
