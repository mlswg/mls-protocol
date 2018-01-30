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
 -
    ins: R. Robert
    name: Raphael Robert
    organization: Wire
    email: raphael@wire.com


normative:

informative:
  dhreuse: DOI.10.1504/IJACT.2010.038308
        

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

We use the TLS presentation language {{!I-D.ietf-tls-tls13}} to
describe the structure of protocol messages.


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
  * Asynchronous ratchet trees for deriving secrets shared among a group of participants
  * Both trees share a common structure and terminology
  * Differ only in how nodes are created and combined
* Structure: Maximally balanced
  * Note flat representation
* Terminology:
  * Direct path for a node in a tree
    * The direct path for a node consists of the node, and each of its ancestors until the root
  * Copath for a node in a tree (== Merkle inclusion proof)
    * The copath for a node consists of every node in its path's sibling node (aside from the root
      node, which has no sibling)
  * Frontier of a tree
    * The frontier of a tree is the set of nodes that would be the copath of a node added to the right
      of the tree
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

Ratchet trees are used for generating the shared group secrets. These are
constructed as a series of Diffie-Hellman keys in a binary tree arrangement,
with each user knowing their direct path, and thus being able to compute the
shared root secret.

To construct these trees, we require:
* A Diffie-Hellman group
* A key-derivation function providing a key pair from the output of a
  Diffie-Hellman key exchange

Ratchet trees are constructed as left-balanced trees, defined such that each
parent node's key pair is derived from the Diffie-Hellman shared secret of its
two child nodes. To compute the root key pair, a participant must know the
public keys of nodes in its own copath, as well as its own leaf private key.

Ratchet trees constructed this way provide the property that one must hold at
least one private key from the tree to compute the root key. With all
participants holding one leaf private key; this allows any individual to update
their own key and change the shared root key, such that only group members can
compute the new key.


### Blank Ratchet Tree Nodes

Nodes in a ratchet tree can have a special value "\_", used to indicate that the
node should be ignored during path computations. Such nodes are used to replace
leaves when participants are deleted from the group (see section 7.5 below).

If any node in the copath of a leaf is \_, it should be ignored during the
computation of the path. For example, if `A`'s copath is `B, \_, C, D`; its path
is computed as

~~~~~
DH(A, B), DH(DH(A, B), C), DH(DH(DH(A, B), C), D)
~~~~~

If two sibling nodes are both \_, their parent value also becomes \_.

Blank nodes effectively result in an unbalanced tree, but allow the
tree management to behave as for a balanced tree for programming simplicity.

### Punctured Ratchet Trees

* Used to send to a subset of a ratchet tree group, for update or delete
* "Punctured tree" == ordered list of intermediate nodes that cover all but punctures
  * Ordering is breadth-first
  * ... or equivalently, numerical
* To compute from a full ratchet tree + list of punctures:
  * For each puncture, mark nodes in its direct path as "not OK"
  * Puncture tree heads are nodes that are OK whose parents are not OK


# Group State

Logically, the state of an MLS group at a given time comprises:

* A group ID 
* A ciphersuite used for cryptographic computations
* A Merkle tree over the participants' identity keys
* A ratchet tree over the participants' leaf key pairs
* A message root key (known only to participants)
* An add key pair (private key known only to participants)
* An init secret (known only to participants)

Since a group can evolve over time, a session logically comprises a
sequence of states.  The time in which each individual state is used
is called an "epoch", and each state is assigned an epoch number
that increments when the state changes.

MLS handshake message provide each node with enough information
about the trees to authenticate messages within the group and
compute the group secrets.

Thus, each participant will need store the following information
about each state of the group:

1. The participant's index in the identity/ratchet trees
2. The private key for the participant's leaf key pair
3. The private key for the participant's identity key pair
4. The current epoch number
5. The group ID
6. A subset of the identity tree comprising at least the copath for
   the participant's leaf
7. A subset of the ratchet tree comprising at least the copath for
   the participant's leaf
8. The current message root key
9. The current update key pair
10. The current init secret


## Cryptographic Objects

Each MLS session uses a single cipher suite that specifies the
following values to be used in group key computations:

* A hash function
* A Diffie-Hellman group

Public keys used in the protocol are opaque values in a format
defined by the ciphersuite.

~~~~~
uint16 CipherSuite;
opaque DHPublicKey<1..2^16-1>;
opaque SignaturePublicKey<1..2^16-1>;
~~~~~


## Key Schedule

Group keys are derived using the HKDF-Extract and HKDF-Expand
functions as defined in {{!RFC5869}}, as well as the functions
defined below:

~~~~~
Derive-Secret(Secret, Label, ID, Epoch, Msg) =
     HKDF-Expand(Secret, HkdfLabel, Length)

Where HkdfLabel is specified as:

struct {
    uint16 length = Length;
    opaque label<7..255> = "mls10 " + Label;
    opaque group_id<0..2^16-1> = ID;
    uint32 epoch = Epoch;
    opaque message<1..2^16-1> = Msg
} HkdfLabel;
~~~~~

The Hash function used by HKDF is the cipher suite hash algorithm.
Hash.length is its output length in bytes.  In the below diagram:

* HKDF-Extract takes its Salt argument form the top and its IKM
  argument from the left
* Derive-Secret takes its Secret argument from the incoming arrow

When processing a handshake message, a participant combines the
following information to derive new epoch secrets:

* The init secret from the previous epoch
* The update secret for the current epoch
* The handshake message that caused the epoch change
* The current group ID and epoch

The derivation of the epoch key pair depends on the change being
made.  For the first epoch, when there is no previous epoch key
pair, the creator of the group generates a fresh key pair and
publishes it to the initial set of participants.

Given these inputs, the derivation of secrets for an epoch
proceeds as shown in the following diagram:

~~~~~
               Init Secret [n-1]
                     |
                     V
Update Secret -> HKDF-Extract = Epoch Secret
                     |
                     |
                     +--> Derive-Secret(., "msg", ID, Epoch, Msg)
                     |       = message_master_secret
                     |
                     +--> Derive-Secret(., "add", ID, Epoch, Msg)
                     |       |
                     |       V
                     |    Derive-Key-Pair(.) = Add Key Pair
                     |
                     V
               Derive-Secret(., "init", ID, Epoch, Msg)
                     |
                     V
               Init Secret [n-1]
~~~~~


# Initialization Keys

In order to facilitate asynchronous addition of participants to a
group, it is possible to pre-publish initialization keys that
provide some public information about a user or group.  UserInitKey
messages provide information a user that a group member can use to
add the user to a group without the user being online.  GroupInitKey
messages provide information about a group that a new user can use
to join the group without any of the existing members of the group
being online.


## UserInitKey

A UserInitKey object specifies what cipher suites a client supports,
as well as providing public keys that the client can use for key
derivation and signing.  The client's identity key is intended to be
stable through the lifetime of the group; there is no mechanism to
change it.  Init keys are intend to be used one time only (or
perhaps a small number of times, see {{init-key-reuse}}).

The init\_keys array MUST have the same length as the cipher\_suites
array, and each entry in the init\_keys array MUST be a public key
for the DH group defined by the corresponding entry in the
cipher\_suites array.

The whole structure is signed using the client's identity key.  A
UserInitKey object with an invalid signature field MUST be
considered mal-formed.  The input to the signature computation
comprises all of the fields except for the signture field.

~~~~~
struct {
    CipherSuite cipher_suites<0..255>;
    DHPublicKey init_keys<1..2^16-1>;
    SignaturePublicKey identity_key;
    SignatureScheme algorithm;
    opaque signature<0..2^16-1>;
} UserInitKey;
~~~~~


## GroupInitKey

A GroupInitKey object specifies the aspects of a group's state that
a new member needs to initialize its state (together with an
identity key and a fresh leaf key pair).

* The current epoch number
* The number of participants currently in the group
* The group ID
* The cipher suite used by the group
* The public key of the current update key pair for the group
* The frontier of the identity tree, as a sequence of hash values
* The frontier of the ratchet tree, as a sequence of public keys

GroupInitKey messages are not themselves signed.  A GroupInitKey
should not be published "bare"; instead, it should be published by
constructing a handshake message with type "none", which will
include a signature by a member of the group and a proof of
membership in the group.

~~~~~
struct {
    uint32 epoch;
    uint32 group_size;
    opaque group_id<0..2^16-1>;
    CipherSuite cipher_suite;
    DHPublicKey update_key;
    MerkleNode identity_frontier<0..2^16-1>;
    DHPublicKey ratchet_frontier<0..2^16-1>;
} GroupInitKey;
~~~~~


# Handshake Messages

Over the lifetime of a group, changes need to be made to the group's
state:

* Initializing a group
* A current member adding a new participant
* A new participant adding themselves
* A current participant updating its leaf key
* A current member deleting another current member

In MLS, these changes are accomplished by broadcasting "handshake"
messages to the group.  Note that unlike TLS and DTLS, there is not
a consolidated handshake phase to the protocol.  Rather, handshake
messages are exchanged throughout the lifetime of a group, whenever
a change is made to the group state.

An MLS handshake message encapsulates a specific message that
accomplishes a change in group state, and also includes two other
important features: First, it provides a GroupInitKey so that a new
participant can observe the latest state of the handshake and
initialize itself.  Second, it provides a signature by a member of
the group, together with a Merkle inclusion proof that demonstrates
that the signer is a legitimate member of the group.

Before considering a handshake message valid, the recipient MUST
verify both that the signature is valid and that the Merkle
inclusion proof is valid.  The input to the signature computations
comprises the entire handshake message except for the signature
field.

The Merkle tree head to be used for validating the inclusion
proof MUST be one that the recipient trusts to represent the current
list of participant identity keys.

~~~~~
enum {
    none(0), 
    init(1),
    user_add(2), 
    group_add(3),
    update(4),
    delete(5),
    (255)
} HandshakeType;

struct {
    HandshakeType msg_type;
    uint24 inner_length;
    select (Handshake.msg_type) {
        case none:      struct{};
        case init:      Init;
        case user_add:  UserAdd;
        case group_add: GroupAdd;
        case update:    Update;
        case delete:    Delete;
    };

    GroupInitKey init_key;

    uint32 signer_index;
    MerkleNode identity_proof<1..2^16-1>;
    SignaturePublicKey identity_key;

    SignatureScheme algorithm;
    opaque signature<1..2^16-1>;
} Handshake;
~~~~~


## Init

[[ Direct initialization is currently undefined.  A participant can
create a group by initializing its own state to reflect a group
including only itself, then adding the initial participants.  This
has computation and communication complexity O(N log N) instead of
the O(N) complexity of direct initialization. ]]


## GroupAdd

An GroupAdd message is sent by a group member to add a new
participant to the group.  The contents of the message are simply
the UserInitKey for the user being added.

~~~~~
struct {
    UserInitKey init_key;
} GroupAdd;
~~~~~

A group member generates such a message by downloading a UserInitKey
for the user to be added.  The added participant processes the
message together with the private key corresponding to the
UserInitKey to initialize his state as follows:

* Compute the participant's leaf key pair by combining the init key in
  the UserInitKey with the prior epoch's update key pair
* Use the frontiers in the GroupInitKey of the Handshake message to
  add its keys to the trees

An existing participant receiving a GroupAdd message first verifies
the signature on the message, then verifies its identity proof
against the identity tree held by the participant.  The participant
then updates its state as follows:

* Compute the new participant's leaf key pair by combining the leaf
  key in the UserInitKey with the prior epoch add key pair
* Update the group's identity tree and ratchet tree with the new
  participant's information

The update secret resulting from this change is the output of a DH
computation between the private key for the root of the ratchet tree
and the add public key from the previous epoch.

[[ ALTERNATIVE: The sender could also generate the new participant's
leaf using a fresh key pair, as opposed to a key pair derived from
the prior epoch's secret.  This would reduce the "double-join"
problem, at the cost of the GroupAdd having to include a new ratchet
frontier. ]]


## UserAdd

A UserAdd message is sent by a new group participant to add
themselves to the group, based on having already had access to a
GroupInitKey for the group.

~~~~~
struct {
    DHPublicKey add_path<1..2^16-1>;
} UserAdd;
~~~~~

A new participant generates this message using the following steps:

* Fetch a GroupInitKey for the group
* Use the frontiers in the GroupInitKey to add its keys to the trees
* Compute the direct path from the new participant's leaf in the new
  ratchet tree (the add\_path).

An existing participant receiving a UserAdd first verifies the
signature on the message, then verifies its identity inclusion proof
against the updated identity tree expressed in the GroupInitKey of
the Handshake message (since the signer is not included in the prior
group state held by the existing participant).  The participant then
updates its state as follows:

* Update trees with the descriptions in the new GroupInitKey
* Update the local ratchet tree with the add path in the UserAdd
  message, replacing any common nodes with the values in the add
  path

The update secret resulting from this change is the secret for the
root node of the ratchet tree.


## Update

An Update message is sent by a group participant to update its leaf
key pair.  This operation provides post-compromise security with
regard to the participant's prior leaf private key.

~~~~~
struct {
    DHPublicKey ratchetPath<1..2^16-1>;
} Update;
~~~~~

The sender of an Update message creates it in the following way:

* Generate a fresh leaf key pair
* Compute its direct path in the current ratchet tree

An existing participant receiving a Update message first verifies
the signature on the message, then verifies its identity proof
against the identity tree held by the participant.  The participant
then updates its state as follows:

* Update the cached ratchet tree by replacing nodes in the direct
  path from the updated leaf with the corresponding nodes in the
  Update message

The update secret resulting from this change is the secret for the
root node of the ratchet tree.


## Delete

A delete message is sent by a group member to remove one or more
participants from the group.

~~~~~
struct {
    uint32 deleted<1..2^16-1>;
    DHPublicKey heads<1..2^16-1>;
    DHPublicKey path<1..2^16-1>;
} Delete;
~~~~~

The sender of a Delete message creates it in the following way:

* Compute the ordered list of subtree heads by puncturing the deleted
  participants' leaves from the current ratchet tree
* Generate a fresh DH key pair and initialize a "delete path" to the
  one-element list containing that key pair
* For each subtree head in the list:
  * Perform a DH computation between the subtree head's public key
    and the private key from the last key pair in the delete path
  * Derive a DH key pair from the output of that DH computation
  * Append the resulting key pair to the delete path

The head field in the Delete message holds the public keys
corresponding to the subtree heads.  The path field holds the public
keys corresponding to the delete path, with the last element omitted
(it is unnecessary).  As a result, the heads and path arrays MUST
have the same length.

Note that the sender of a Delete message must enough information
about the ratchet tree so that it has all of the subtree heads
resulting from the puncture operation.  This criterion is met if the
sender has a copath for each of the deleted participants.

An existing participant receiving a Delete message first verifies
the signature on the message, then verifies its identity proof
against the identity tree held by the participant.  The participant
then updates its state as follows:

* Compute the ordered list of subtree heads by puncturing the deleted
  participants' leaves from the current ratchet tree
* Find a public key in the list of subtree heads for which the
  private key is known to the recipient
* Perform a DH computation between the known subtree head private
  key and the public key in the delete path at the same index
* For each remaining element in the list of subtree heads:
  * Derive a DH key pair from the last DH output
  * Perform a DH computation between the private key of the derived
    key pair with the subtree head's public key

The update secret for this change is the last DH output from the
delete path.



# Sequencing of State Changes

* Each state-changing message is premised on a given starting state
* Thus, there is a need to deconflict if two messages are generated from the same state
* General approaches
  * Have the server enforce a total order
  * Create some in-message tie-breaker
* In any case, risk of starvation

## Server-side enforced ordering

With this approach, the server ensures that incoming messages are added to an ordered queue and outgoing messages are dispatched in the same order. The server is trusted to resolve conflicts during race-conditions (when two members send a message at the same time), as the server doesn't have any additional knowledge thanks to the confidentiality of the messages.

Messages should have a counter field sent in clear-text that can be checked by the server and used for tie-breaking. The counter starts at 0 and is incremented for every new incoming message. If two group members send a message with the same counter, the first message to arrive will be accepted by the server and the second one will be rejected. The rejected message needs to be sent again with the correct counter number.

To prevent counter manipulation by the server, the counter's integrity can be ensured by including the counter in a signed message envelope.

This apllies to all messages, not only state changing messages.


## Client-side enforced ordering
Order enforcing can be implemented on the client as well, one way to achieve it is to use two steps update protocol, first 
client sends a proposal to update and the proposal is accepted when it gets 50%+ approval from the rest of the group, then it sends the approved update. Clients which didn't get their proposal accepted, will wait for the winner to send their update before retrying new proposals. 

While this seems safer as it doesn't rely on the server, it is more complex and harder to implement. It also could cause starvation for some clients if they keep failing to get their proposal accepted.


# Message Protection

* The primary purpose of this protocol is AKE
* No current specification for how negotiated keys are used
* Message protection scheme will need to indicate which state a key was derived from
* Will probably also want:
  * Hash-based key ratchets
  * ... per sender, to avoid races
  * Transcript integrity

For every epoch, the root key of the ratcheting tree can be used to derive key material for: 

 * symmetric encryption (using AEAD)
 * symmetric signatures (HMAC) (optional)
 
In addition, asymmetric signatures should be used to ensure message athenticity.

In combination with server-side enforced ordering, data from previous messages can be used (as a salt when hashing) to:

 * add freshness to derived symmetric keys
 * create channel-binding between messages to achieve some form of transcript security
 
Possible candidates for that are:

 * the key used for the previous message (hash ratcheting)
 * the counter of the previous message (needs to be known to new members of the group)
 * the hash of the previous message (strong indication that other participants saw the same history)
 * ... ?
 
The requirement for this is that all participants know these values.
If additional clear-text fields are attached to messages (like the counter), those fields can be protected by a signed message envelope.

Alternatively, the hash of the previous message can also be included as an additional field rather than change the encryption key. This allows for a more flexible approach, because the receiving party can choose to ignore it (if the value is not known, or if transcript security is not required).

# Security Considerations

The security goals of MLS are described in [[the architecture doc]]. We describe here how the
protocol achieves its goals at a high level, though a complete security analysis is outside of the
scope of this document.

## Confidentiality of the Group Secrets

Group secrets are derived from (i) previous group secrets, and (ii) the root key of a ratcheting
tree. As long only group members know a leaf key in the group, therefore, the root key of the
group's ratcheting tree is secret and thus so are all values derived from it.

Initial leaf keys are known only by their owner and the group creator, because they are derived from
an authenticated key exchange protocol. Subsequent leaf keys are known only by their owner. [[TODO:
or by someone who replaced them.]]

Note that the long-term identity keys used by the protocol must be distributed correctly for parties
to authenticate their peers.

## Authentication

There are two forms of authentication we consider: that the group key is known only to group
members, and that only the sender of a message could have sent it. The former property comes from
the ratcheting trees: only group members know a leaf key, and thus only group members can compute
the shared secret. The latter property is provided by the message signatures under identity keys.

## Forward and post-compromise security

Message keys are derived via a hash ratchet, which provides a form of forward secrecy: learning a
message key does not reveal previous message or root keys. Post-compromise security is provided by
Update operations, in which a new root key is generated from the latest racheting tree. If the
adversary cannot derive the updated root key after an Update operation, it cannot compute any
derived secrets.

## Init Key Reuse

Prekeys are intended to be used only once and then deleted. Reuse of prekeys is not believed to be
inherently insecure {{dhreuse}}, although it can complicate protocol analyses.
