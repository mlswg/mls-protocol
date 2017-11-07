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


normative:
  RFC2119:

informative:
        

--- abstract

Messaging applications are increasingly making use of end-to-end
security mechanisms to ensure that messages are only accessible to
the communicating endpoints, not any servers involved in delivering
messages.  Establishing keys to provide such protections is
challenging for group chat settings, in which more than two
participants need to agree on a key.  In this document, we specify a
group key establishment protocol that provides efficient group key
establishment with forward secrecy and post-compromise security.


--- middle

# Introduction

[[ TODO - Group keying is necessary, but hard.  State of the art is
sender keys, which have bad FS / PCS and bad rekey efficiency ]]


# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in {{!RFC2119}}.


# Asynchronous Ratchet Trees

The Asynchronous Ratcheting Tree is the building block around which this
protocol is built. It was originally specified by Cohn-Gordon et al with a
formal proof of its security properties (https://eprint.iacr.org/2017/666).

ART uses a Diffie-Hellman Key Tree to derive a shared secret for a group,
allowing it to be efficiently updated (ratcheted) by any group member (leaf
node) to provide the properties of Forward Secrecy and Post-Compromise Security.
Alongside ratcheting, receiving messages, and changing the group membership can
also be efficiently achieved.

## Computing the Root Key

ART uses a recursive structure, in which every node is a Diffie-Hellman public
key or key pair. The value of a given parent node's private key is computed as follows:

~~~~
     KDF(DH(Alice, Bob))
    /                   \
   /                     \
Alice                    Bob
~~~~

(TODO: define our KDF).

The ART root secret is the private Diffie-Hellman key of the root of the tree.
This should not be used directly within the protocol, but rather computed into a
Stage Key (TODO: below).

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
