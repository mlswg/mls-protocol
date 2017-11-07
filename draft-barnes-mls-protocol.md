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
key or key pair. The value of a given parent node's private key is computed as
follows:

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

For this document, we will use the shorthand notation [A,B] to indicate
KDF(DH(Alice, Bob)).

## Updating a Leaf Key Pair

Changing a leaf DH key will inherently update its entire path to and including the
root.

~~~~
         [[A,B],[C,D]]
        /             \
       /               \
  [A,B]                 [C,D]
 /     \               /     \
A       B             C       D
~~~~

In the above tree, if C updates to C', the path of all nodes referencing C is updated,
resulting in the below tree.

~~~~
         [[A,B],[C',D]]
        /              \
       /                \
  [A,B]                  [C',D]
 /     \                /      \
A       B             C'        D
~~~~

C must transmit the public keys of her entire path to the other participants in the tree.
Each participant will update their copath with their respective element from this path,
and thus recompute the same updated tree that C has computed.

## Adding a Leaf

## Removing a Leaf

# Session State

[[ Session comprised of (1) ART (2) pre-stage key (3) message key
chains ]]

[[ Each node caches... ]]

# Session Management


~~~~~
    A         B   C   D          E
    |  PreKey |   |   |          |
    |<--------|   |   |          |
    |  PreKey |   |   |          |
    |<------------|   |          |
    |  PreKey |   |   |          |
    |<----------------|          |
    |         |   |   |          |
    |  Setup  |   |   |          |
    |-------->|   |   |          |
    |  Setup  |   |   |          |
    |------------>|   |          |
    |  Setup  |   |   |          |
    |---------------->|          |
    |         |   |   |          |
    ~         ~   ~   ~          ~
    |         |   |   |          |
    |  Setup  |   |   |          |
    |--------------------------->|
    |         |   |   |          |
    |   Add   |   |   |          |
    |-------->|   |   |          |
    |------------>|   |          |
    |---------------->|          |
    |         |   |   |          |
    ~         ~   ~   ~          ~
    |         |   |   |          |
    |         |   |   |  Update  |
    |         |   |   |<---------|
    |         |   |<-------------|
    |         |<-----------------|
    |<---------------------------|
    |         |   |   |          |
~~~~~


## State Machine

Each endpoint caches the following state:

* For the group:
  * The current epoch
  * The list of identity keys for the group
  * The current frontier
  * The current preStageKey
* For the endpoint:
  * Index in the tree
  * Leaf key pair
  * Copath


~~~~~
                  +-----------------+
                  |      START      |---+
                  +-----------------+   | Not space creator
                        |               | Send PreKey
          Space creator |               V
            Set epoch=0 |       +-----------------+
                        |       |    ADD-WAIT     |
                        |       +-----------------+
               +---+    |               |
      Send Add |   |    |               | Recv Setup
               +->+-----------------+   | 
                  |  JOINED(epoch)  |<--+
               +->+-----------------+
   Send Update |   |    |    |
               +---+    |    |
                        |    |
                        |    | Recv Add(epoch+1, ...)
                        V    V
                  +-----------------+
                  | JOINED(epoch+1) |
                  +-----------------+
~~~~~


## Messages

~~~~~
enum {
  (255)
} ARTMessageType;

struct {
  SignatureScheme algorithm;
  opaque key<1..2^16-1>;
} SignatureKey;

struct {
  ARTMessageType type;
  opaque message;
  PublicKey publicKey;
  opaque signature<1..2^16-1>;
} ARTMessage;

struct {
  KeyShareEntry value;
  uint16 size;
} FrontierEntry;
~~~~~

### PreKey

~~~~~
struct {
  uint32 preKeyID;
  KeyShareEntry preKey;
} PreKey;
~~~~~

### Setup

~~~~~
struct {
  uint32 epoch;
  uint32 index;
  uint32 preKeyID;
  KeyShareEntry identities<1..2^16-1>;
  KeyShareEntry ephemeralKey;
  KeyShareEntry copath<1..2^16-1>;
  FrontierEntry frontier<1..2^16-1>;
  opaque wrappedPreStageKey<1..2^16-1>;
} Setup;
~~~~~

### Add

~~~~~
struct {
  uint32 epoch;
  KeyShareEntry newIdentity;
  KeyShareEntry directPath<1..2^16-1>;
} Add;
~~~~~

### Update

~~~~~
struct {
  uint32 epoch;
  uint32 index;
  KeyShareEntry directPath<1..2^16-1>;
} Setup;
~~~~~

# Security Considerations

[[ What trust is placed in the server? ]]

# IANA Considerations

# Acknowledgements

--- back
