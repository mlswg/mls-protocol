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

* Participant: Holder of a private key.  Could be user or device
* Group: A collection of participants with shared private state
* Assumed to be used over a messaging system, see arch doc


# Protocol Overview

* Goal: Produce a series of states whose private values are known only to group members
  * Forward secrecy
  * Post compromise secrecy (with respect to...)
* Creator of a group creates an initial state that includes an initial set of participants
* Participants exchange message to produce new shared states
  * Add and remove participants
  * Update for PCS
* Each state has a causal link to its successor(s); a logical DAG

* Potential participants publish UserInitKey messages
* Init:
  * Group creator downloads UserInitKeys for participants, broadcasts GroupInit message
  * Participants receive GroupInit message, compute group state
  * Note that creator is "double-joined" with all participants until they update
* Group-initiated Add
  * Group member downloads UserInitKey for new participant, broadcasts GroupAdd message
  * Existing participants receive GroupAdd, compute new group state from current state
  * New participant receives GroupAdd, computes new group state from private key ~ UserInitKey
  * Note that add sender is "double-joined" until all participants update
* User-initiated Add
  * On state changes, relevant public data gathered in a GroupInitKey message
  * New participant downloads GroupInitKey, brodcasts UserAdd message
  * Existing participants receive UserAdd, compute new group state from current state
  * New participant receives UserAdd, computes new group state from private key
* Key Update
  * Updating participant generates fresh key pair and Update message
  * Participants receive Update message, compute new group state
  * This prevents the holder of the old key pair from computing future group states
* Delete
  * Deleting participant generates and broadcasts a Delete message
  * Participants receive Delete message, compute new group state
  * This prevents the holders of the deleted users' private keys from computing future group states
  * Those private keys will still be included in group computations until siblings / cousins update


# Balanced Binary Trees

* The protocol uses two types of tree structures:
  * Merkle trees for commitment to a set + compact membership proofs
  * Ratchet trees for deriving secrets shared among a group of participants
  * Both trees share a common structure and terminology
  * Differ only in how nodes are created and combined
* Structure: Maximally balanced
  * Note flat representation
* Terminology:
  * Frontier of a tree
  * Copath for a node in a tree (== Merkle inclusion proof)
  * Direct path for a node in a tree
* Instance must specify:
  * Required crypto parameters
  * Node content
  * Combining rule
  * Leaf creation rule


## Merkle Trees

* Used to generate a compact committment of a collection of values, with short proofs
* Requires: Hash function
* Node content: Hash value
* Leaf creation: Leaf hash
* Combining rule: Pair hash


## Ratchet Trees

* Used to generate secrets known to a group
* Requires:
  * DH group
  * Injection from DH outputs to private keys
* Node content:
  * Public key
  * Private key (optional)
  * Privaate key seed data (optional)
* Leaf creation: Just import data


### Blank Ratchet Tree Nodes

* Nodes can have a special value "\_"
* Combining rules:
  * \_ + \_ = \_
  * \_ + A = A + \_ = A
* Effectively moves neighbor up a level without changing tree structure


### Punctured Ratchet Trees

* Used to send to a subset of a ratchet tree group, for update or delete
* "Punctured tree" == ordered list of intermediate nodes that cover all but punctures
  * Ordering is breadth-first
  * ... or equivalently, numerical
* To compute from a full ratchet tree + list of punctures:
  * For each puncture, mark nodes in its direct path as "not OK"
  * Puncture tree heads are nodes that are OK whose parents are not OK


[[ Following sections to be filled from earlier PDF/code + diffs from the London meeting ]]

# Group State

# State-Changing Messages

## Roster Signing

## Init

## GroupAdd

## UserAdd

## Update

## Delete


# Sequencing of State Changes [stub]

* Each state-changing message is premised on a given starting state
* Thus, there is a need to deconflict if two messages are generated from the same state
* General approaches
  * Have the server enforce a total order
  * Create some in-message tie-breaker
* In any case, risk of starvation


# Message Protection [stub]

* The primary purpose of this protocol is AKE
* No current specification for how negotiated keys are used
* Message protection scheme will need to indicate which state a key was derived from
* Will probably also want:
  * Hash-based key ratchets
  * ... per sender, to avoid races
  * Transcript integrity


# Security Considerations [stub]

* Key Secrecy
* Authentication
* Re-use of InitKeys




# [[[ OLD TEXT BELOW THIS LINE ]]]

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

In MLS, the endpoints involved in a session collaborate to establish
and maintain an Asynchronous Ratchet Tree for the session.  There
are three major phases in the life-cycle of a group:

* Initializing the tree
* Adding a new endpoint
* Updating a leaf in the tree

Leaves are never removed from tree.  One endpoint can remove another
endpoint by updating that endpoint's leaf to a key that the endpoint
being removed does not possess.

At any point, an endpoint can publish a PreKey message, which
contains information that another endpoint can use to add that
endpoint to a group.  Typically applications provide a PreKey cache
to which endpoints periodically push fresh PreKey messages.

Suppose an endpoint A wants to initiate a group conversation with
otehr endpoints B, C, and D.  A accomplishes this by downloading
PreKeys fro B, C, and D, computing a tree over (A, B, C, D), and
sending different individual Setup messages to B, C, and D.


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
~~~~~

If A subsequently wants to add another endpoint E to the
conversation, then the process is similar.  First A downloads a
PreKey for E and uses it to add E to the tree.  From these
computations, A generates a Setup message for E and an Add message
that can be broadcast to B, C, and D.


~~~~~
    A         B   C   D          E
    |         |   |   |          |
    |  PreKey |   |   |          |
    |<---------------------------|
    |         |   |   |          |
    |  Setup  |   |   |          |
    |--------------------------->|
    |         |   |   |          |
    |   Add   |   |   |          |
    |-------->|   |   |          |
    |------------>|   |          |
    |---------------->|          |
    |         |   |   |          |
~~~~~

Upon being added, E should update its leaf key so that its leaf key
will not be known to A.  To update a leaf key in the tree, an
endpoint simply generates a new key pair, creates an Update message,
and broadcasts it to the group.

~~~~~
    A         B   C   D          E
    |         |   |   |          |
    |         |   |   |  Update  |
    |         |   |   |<---------|
    |         |   |<-------------|
    |         |<-----------------|
    |<---------------------------|
    |         |   |   |          |
~~~~~


## State Machine

Each MLS endpoint caches a view of the overall tree including
certain global elements and certain elements specific to the
endpoint:

* For the group:
  * The current epoch
  * The list of identity keys for the group
  * The current frontier
  * The current preStageKey
* For the endpoint:
  * Index in the tree
  * Leaf key pair
  * Copath

MLS messages synchronize this state information across the
participants in the group.

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
Send Setup+Add |   |    |               | Recv Setup
               +->+-----------------+   | 
                  |  JOINED(epoch)  |<--+
               +->+-----------------+
   Send Update |   |    |    |
               +---+    |    |
                        |    | Recv Add(epoch+1, ...)
                        V    V
                  +-----------------+
                  | JOINED(epoch+1) |
                  +-----------------+
                        |    |
                        V    V
                       ...  ...
~~~~~

Note that no state is modified when an endpoint sends a Setup, Add,
or Update message.  Because all endpoints need to process updates to
the tree in the same order, there is a risk that any given message
of these types will be rejected.  To avoid the need to roll back on
such rejections, endpoints only apply Setup / Add / Update messages
once they are published and accepted by the group.  For more
discussion of how modifications to the tree should be sequenced, see
{{#sequencing-of-modifications}}.


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

## Sequencing of Modifications

[[ Endpoints need to make modifications to the tree in the same order.  How does that happen? ]]

# Security Considerations

[[ What trust is placed in the server? ]]

# IANA Considerations

# Acknowledgements

--- back
