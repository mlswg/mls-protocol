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

## Server-side enforced ordering

With this approach, the server ensures that incoming messages are added to an ordered queue and outgoing messages are dispatched in the same order. The server is trusted to resolve conflicts during race-conditions (when two members send a message at the same time), as the server doesn't have any additional knowledge thanks to the confidentiality of the messages.

Messages should have a counter field sent in clear-text that can be checked by the server and used for tie-breaking. The counter starts at 0 and is incremented for every new incoming message. If two group members send a message with the same counter, the first message to arrive will be accepted by the server and the second one will be rejected. The rejected message needs to be sent again with the correct counter number.

To prevent counter manipulation by the server, the counter's integrity can be ensured by including the counter in a signed message envelope.

This apllies to all messages, not only state changing messages.


# Message Protection [stub]

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

## Confidentiality of the Group Secrets

## Authentication

## Init Key Reuse

