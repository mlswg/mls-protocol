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

For groups of size greater than two, common strategy is to
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

The goal of this protocol is to allow a group of participants to exchange confidential and
authenticated messages. It does so by deriving a sequence of keys known only to group members. Keys
should be secret against an active network adversary and should have both forward and
post-compromise secrecy with respect to compromise of a participant.

We describe the information stored by each participant as a _state_, which includes both public and
private data. An initial state, including an initial set of participants, is set up by a group
creator using the _Init_ algorithm and based on information pre-published bythe initial members. The creator
sends the GroupInit message to the participants, who can then set up their own group state deriving
the same shared keys. Participants then exchange messages to produce new shared states which are
causally linked to their predecessors, forming a logical DAG of states. Participants can send
_Update_ messages for post-compromise secrecy, and new participants can be added or existing
participants removed.

The protocol algorithms we specify here follow. Each algorithm specifies both (i) how a participant
performs the operation and (ii) how other participants update their state based on it.

* PreRegister [[TODO: need to specify this]]

  This algorithm describes how potential group participants can publish UserInitKey messages which
  can later be used to add them to groups without further input.

* Init

  This algorithm describes how a group is created. The creator downloads UserInitKeys for the
  initial group participants, and performs an initial computation to derive a shared group key. They
  produce a GroupInit message describing the new group, which is broadcast to all members. Upon
  receiving this members, new participants perform a similar computation to derive the same group
  key and group state. After executing this algorithm, all group members share an authenticated
  secret key.

* Group-initiated Add

  This algorithm describes how a group participant can add a new user to a group. The adder
  downloads a UserInitKey for the new participant, and performs a local computation to derive a new
  group key. They produce a GroupAdd message which is broadcast to all current members as well as
  the newly-added member. All recipients of the GroupAdd message compute the updated group state;
  the new member uses their private key to do so, while existing members use their current group
  state. After executing this algorithm, the new member is added to the group and shares the group
  state.

* User-initiated Add

  This algorithm describes how a new user can join a group without a direct invitation. When the
  group state changes, relevant public data is gathered into a GroupInitKey message which is sent to
  the new user. The new user can then perform a local computation to derive an updated group state,
  and produce a UserAdd message which is sent to all existing members. All recipients of the UserAdd
  update their group state based on their existing state. After executing this algorithm, the new
  member is added to the group and shares the group state.

* Key Update

  This algorithm describes how any participant can update their own private keys to fresh ones,
  updating the group state and group key. The updater generates a fresh key pair and produces an
  Update message which describes the change to the group state, broadcasting it to the group. All
  recipients then update their group state based on the Update message, deriving a new group
  state. After executing this algorithm, all members share an updated group state which a holder of
  the old key pair can no longer derive; thus, Update provides a form of PCS.

* Delete

  This algorithm describes how any participant can remove another participant from a group. The
  deleting participant generates and broadcasts a Delete message. Upon receiving this message, all
  participants except the deleted one can compute a new group state. After executing this algorithm,
  holders of the deleted users' private keys cannot compute this or future group states (although
  these private keys will still be included in group computations until siblings / cousins update).

Note that the group creator is "double-joined" with all participants until they update, as is the
sender of a group-initiated add until the newly added member updates.

# Binary Trees

The protocol uses two types of binary tree structures:

  * Merkle trees for efficiently committing to a set of group participants.
  * Asychronous ratcheting trees for deriving shared secrets among this group of
    participants.

The two trees in the protocol share a common structure, allowing us to maintain
a direct mapping between their nodes when manipulating group membership. The
`nth` leaf in each tree is owned by the `nth` group participant.

## Terminology

We use a common set of terminology to refer to both types of binary tree.

**Nodes**

Trees consist of various different types of _nodes_. A node is a _leaf_ if it has no children, and a
_parent_ otherwise; note that all parents in our Merkle or asynchronous ratcheting trees have
precisely two children. A node is the _root_ of a tree if it has no parents, and _intermediate_ if
it has both children and parents. The _descendants_ of a node are that node, its children, and the
descendants of its children, and we say a tree _contains_ a node if that node is a descendant of the
root of the tree. Nodes are _siblings_ if they share the same parent.

**Trees**

A _subtree_ of a tree is the tree given by the descendants of any node. The _size_ of a tree or
subtree is the number of leaf nodes it contains.

A binary tree is _balanced_ if it is either a single leaf, or if it is a parent node for which both of
its subtrees are balanced binary trees of the same size. This implies that a balanced binary tree has a
power-of-two number of leaves.

A binary tree is _left-balanced_ if the left child of every non-leaf node `x` is a balanced binary
tree of size `2^ceil(lg |S| - 1)`, where `S` is the subtree rooted at `x`. In a left-balanced tree,
the `nth` leaf node refers to the `nth` leaf node in the tree when counting from the left.

**Paths**

The _direct path_ of a root is the empty list, and of any other node is the concatenation of that
node with the direct path of its parent. The _copath_ of a node is the list of siblings of nodes in
its direct path, excluding the root, which has no sibling. The _frontier_ of a node is the set of
nodes that would constitute the copath of a new leaf node added to the tree, whilst maintaining the
tree as left-balanced.

**Blank nodes**

We extend both types of tree to include a concept of "blank" nodes; which are
used to replace group members who have been removed. We expand on how these are
used and implemented in the sections below.

## Merkle Trees

Merkle trees are used to efficiently commit to a collection of group members.
We require a hash function to construct this tree.

Our Merkle trees are constructed as left-balanced binary trees. The value of
each parent node is the hash of the concatenation of its child nodes. The value
of the `nth` leaf node is the public identity key of the nth group member.
Blank leaf nodes have a value of the empty string.

The below tree provides an example of a size 2 tree, containing identity keys
`A` and `B`.

~~~~~
   Hash( A || B )
 /               \
A                 B
~~~~~


[[EKR: Isn't the convention here to have some sort of disambiguator to
prevent substitution]]


### Merkle Proofs

A proof of a given leaf being a member of the Merkle tree consists of the value
of the leaf node, as well as the values of each node in its copath. From these
values, its path to the root can be verified; proving the inclusion of the leaf
in the Merkle tree.

In the below tree, we star the Merkle proof of membership for leaf node
`A`. For brevity, we notate `Hash( A || B)` as `AB`.

~~~~~
      ABCD
    /      \
  AB        CD*
 /  \      /  \
A   B*    C    D
~~~~~

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

For example, the ratchet tree consisting of the private keys (A, B, C, D)
is constructed as follows:

~~~~~
DH(DH(AB), DH(CD))
    /      \
 DH(AB)    DH(CD)
 /  \      /  \
A    B    C    D
~~~~~

Ratchet trees constructed this way provide the property that one must hold at
least one private key from the tree to compute the root key. With all
participants holding one leaf private key; this allows any individual to update
their own key and change the shared root key, such that only group members can
compute the new key.



### Blank Ratchet Tree Nodes

Nodes in a ratchet tree can have a special value "\_", used to indicate that the
node should be ignored during path computations. Such nodes are used to replace
leaves when participants are deleted from the group.

If any node in the copath of a leaf is \_, it should be ignored during the
computation of the path. For example, the tree consisting of the private
keys (A, _, C, D)

~~~~~
  DH(A, DH(CD))
   /      \
  A       DH(CD)
 / \      /  \
A   _    C    D
~~~~~

If two sibling nodes are both \_, their parent value also becomes \_.

Blank nodes effectively result in an unbalanced tree, but allow the
tree management to behave as for a balanced tree for programming simplicity.

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
defined by the ciphersuite, using the following three types:

~~~~~
uint16 CipherSuite;
opaque DHPublicKey<1..2^16-1>;
opaque SignaturePublicKey<1..2^16-1>;
opauqe MerkleNode<1..255>
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
considered malformed.  The input to the signature computation
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


# Tree Operations

Over the lifetime of a group, changes need to be made to its state; which are
accomplished via a number of primitives on the underlying trees:

* Initializing a group.
* Adding a participant.
* Updating a leaf key.
* Blanking out a leaf key.

## Initializing a group

An individual can initialize a group by creating its Asynchronous Ratcheting Tree and
Merkle Tree.

First the individual fetches identity keys and initialization keys for all group
participants from the Messaging Service.

The identity keys are sequenced in some order, which will dictate the nth leaf
in each of the trees. From this we can immediately form the Merkle tree of
identities.

At this point the initiator must generate two new key pairs:

* Her own leaf key pair.
* An ephemeral setup key pair.

For every sibling pair (apart from her own), she computes the leaf key of the
left member of this pair as KDF( DH( Member's Init Key, Ephemeral Setup Key) ),
giving her one of the private keys in every pair. The right leaf in these pairs
should just be the raw initialization key from the relevant identities. From this
the initiator can compute the entire tree; which can be broadcast.

Having computed the tree, she MUST delete the ephemeral setup key pair.

In practice, group members may not wish to rely on her having deleterd this key
pair; and so the keys for which she knew a private key should be noted. [Note:
book-keeping left unspecified for now, and will be common with book-keeping for
deletion; allowing the group security properties to still hold in the face of
double-joins].

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

* Compute the ordered list of subtree heads by removing the deleted
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
resulting from the delete operation.  This criterion is met if the
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
