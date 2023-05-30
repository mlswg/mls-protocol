# RFC Editor Questions

> 1) <!-- [rfced] xml2rfc returns a number of warnings and suggest that
> viewBox be used.  Please review and let us know if you would like to make
> any updates. 
> 
> Examples:
> rfc9420.xml(434): Warning: Found SVG with width or height specified, which will make the artwork not scale.  Specify a viewBox only to let the artwork scale.
> rfc9420.xml(568): Warning: Found SVG with width or height specified, which will make the artwork not scale.  Specify a viewBox only to let the artwork scale.
> ...
> rfc9420.xml(5759): Warning: Found SVG with width or height specified, which will make the artwork not scale.  Specify a viewBox only to let the artwork scale.
> rfc9420.xml(8128): Warning: Found SVG with width or height specified, which will make the artwork not scale.  Specify a viewBox only to let the artwork scale.
> -->

The document's viewBox setting is correct; xml2rfc's default is wrong.  Setting
width and height ensures that the SVG's scale and positioning is consistent with
the text across scaling.


> 2) <!-- [rfced] Please insert any keywords (beyond those that appear in
> the title) for use on https://www.rfc-editor.org/search. -->

The authors' XML file now has 


> 3) <!--[rfced] Section 2. Should the terminology be placed in alphabetical
> order, or do you prefer the current ordering? Please review and
> let us know your preference.
> -->     
> 
> 
> 4) <!-- [rfced] Please review the "type" attribute of each sourcecode
> element in the XML file to ensure correctness.
> 
> Note that "tls-presentation" (not "tls") is already considered an
> acceptable "type" per the current list of preferred values
> (https://www.rfc-editor.org/materials/sourcecode-types.txt). Would it make
> sense to update instances of type "tls" to "tls-presentation".  Are you
> recommending that "tls" be added as a new type?  Note that it is also
> acceptable to leave the "type" attribute not set.
> 
> In addition, review each artwork element. Specifically,
> should any artwork element be tagged as sourcecode or another
> element?
>  -->
> 
> 
> 5) <!-- [rfced] In the html and pdf outputs, the text enclosed in <tt> is
> output in fixed-width font. In the txt output, there are no changes to the
> font, and the quotation marks have been removed.
> 
> In the html and pdf outputs, the text enclosed in <em> is output in
> italics. In the txt output, the text enclosed in <em> appears with an
> underscore before and after.
> 
> Please review carefully and let us know if the output is acceptable or if
> any updates are needed.
> -->
> 
> 
> 6) <!--[rfced] We note that <sup> is used for superscript, but not for
> all instances. Please review and let us know if you would like to
> use <sup> for the instances that do not contain the <sup> element.
> -->
> 
> 
> 7) <!--[rfced] Would it be correct to say that a member "sends" a Welcome
> message to a new client instead of "broadcasts" it since the
> Welcome is only being distributed to one client?
> 
> Original:
>    Any member of the group can download a KeyPackage for a new client
>    and broadcast Add and Commit messages that the current group will
>    use to update their state, and a Welcome message that the new client
>    can use to initialize its state and join the group.
> 
> Perhaps:
>    Any member of the group can download a KeyPackage for a new client
>    and broadcast Add and Commit messages that the current group will
>    use to update their state, and send a Welcome message that
>    the new client can use to initialize its state and join the group.
> -->
> 
> 
> 8) <!--[rfced] Please review whether any of the notes in this document
> should be in the <aside> element. It is defined as "a container for
> content that is semantically less important or tangential to the
> content that surrounds it" (https://authors.ietf.org/en/rfcxml-vocabulary#aside).
> -->
> 
> 
> 9) <!--[rfced] May we shorten the title for Figure 4 by moving the second
> sentence to a note below the figure? The note may be indented or
> in an <aside> element. Please let us know your preference.
> 
> Original:
>    Figure 4: Client B proposes to update its key, and client A commits the
>    proposal. As a result, the keys for both B and A updated, so
>    the group has post-compromise security with respect to both
>    of them.
> 
> Perhaps:
>    Figure 4: Client B proposes to update its key, and client A commits the
>    proposal
> 
>    Note: As a result of client A commiting client B's proposal,
>    the keys for both A and B updated, so the group has
>    post-compromise security with respect to both of them.
> -->
> 
> 
> 10) <!--[rfced] Is the intended meaning that the right subtree is the same
> as the left subtree? If so, may we update the text in parentheses
> for clarity as follows?
> 
> Original:
>    For a given parent node, its left subtree is the subtree with
>    its left child as head (respectively right subtree).
> 
> Perhaps:
>    For a given parent node, its left subtree is the subtree with its
>    left child as the head (and respectively, its right subtree has its
>    right child as the head).
> -->
> 
> 
> 11) <!--[rfced] Tables 2, 3, 5, 7, and 15 do not have titles. If you would
> like to add titles, please provide the desired text.
> -->
> 
> 
> 12) <!--[rfced] We capitalized the following instance of "r" and "s" to
> match use in RFC 8032; please let us know of any objections.
> 
> Original:
>    In particular, ECDSA signatures are DER-encoded and EdDSA
>    signatures are defined as the concatenation of r and s as
>    specified in [RFC8032].
> 
> Current:
>    In particular, ECDSA signatures are DER encoded, and EdDSA
>    signatures are defined as the concatenation of R and S,
>    as specified in [RFC8032].
> -->
> 
> 
> 13) <!--[rfced] We do not see "SealBase" or "OpenBase" in RFC 9180, but we
> do see "Seal()" and "Open()". We assume that these are one in the
> same; however, if any further updates are needed for consistency,
> please let us know.
> 
> Current:
>    Here, the functions SealBase and OpenBase are defined [RFC9180],
>    using the HPKE algorithms specified by the group's ciphersuite.
> -->
> 
> 
> 14) <!--[rfced] The following lines are over the 72-character limit (and
> over the 69-character limit for ASCII artwork). Please let us
> know how you would like to shorten/wrap the lines.
> 
> Section 5.2:
>   MakeKeyPackageRef(value) = RefHash("MLS 1.0 KeyPackage Reference", value) (4 over)
>   MakeProposalRef(value)   = RefHash("MLS 1.0 Proposal Reference", value)   (2 over)
> 
> Figure 12:
>   Proposal        Commit     Application Data   (1 over)
>   V           |                  +- Asymmetric  (9 over)
>   FramedContentAuthData |     |   Sign / Verify (12 over)
>   +- Symmetric        (8 over)
>   Protect / Unprotect (18 over)
> 
> Section 7.7
>   +- - new member (2 over)
> 
> Section 12.4.3.1:
>   encrypted_group_info, group_secrets) (10 over)
> 
> Section 12.4.3.1:
>   encrypted_group_info, kem_output, ciphertext) (9 over)
> 
> Appendix D:
>   raise Exception("Cannot truncate a tree with 0 or 1 nodes") (2 over)
> -->
> 
> 
> 15) <!--[rfced] We notice that the text "See IANA registry for registered
> values" is included within four of the sourcecode elements (see
> Sections 5.3, 6, 7.2, and 12.1).  Would it be better to refer to the registry name and add a pointer to the relevant section in the document? 
> 
> One example:
> 
> Original:
>    Using the terminology from [RFC6125], a Credential provides
>    "presented identifiers", and it is up to the application to
>    supply a "reference identifier" for the authenticated client,
>    if any.
> 
>    // See IANA registry for registered values
>    uint16 CredentialType;
> 
>    struct {
>        opaque cert_data<V>;
>    } Certificate;
> 
>    struct {
>        CredentialType credential_type;
>        select (Credential.credential_type) {
>            case basic:
>                opaque identity<V>;
> 
>            case x509:
>                Certificate certificates<V>;
>        };
>    } Credential;
> 
> Perhaps:
>    Using the terminology from [RFC6125], a Credential provides
>    "presented identifiers", and it is up to the application to
>    supply a "reference identifier" for the authenticated client,
>    if any.
> 
>    Note: See the "MLS Credential Types" registry (Section 17.5).
> 
>    uint16 CredentialType;
> 
>    struct {
>        opaque cert_data<V>;
>    } Certificate;
> 
>    struct {
>        CredentialType credential_type;
>        select (Credential.credential_type) {
>            case basic:
>                opaque identity<V>;
> 
>            case x509:
>                Certificate certificates<V>;
>        };
>    } Credential;
> -->
> 
> 
> 16) <!--[rfced] FYI: We added "and" before "represented". If that is not
> correct, please let us know.
> 
> Original:
>    Whether these fields can be computed by the client represented by the
>    LeafNode depends on when the LeafNode was created.
> 
> Current:
>    Whether these fields can be computed by the client and represented by the
>    LeafNode depends on when the LeafNode was created.
> -->
> 
> 
> 17) <!--[rfced] The first part of the following sentence does not parse;
> is there text missing after "ratchet"? Please let us know how we
> may update this for clarity.
> 
> Original:
>    After generating fresh key material and applying it to ratchet
>    forward their local tree state as described in the Section 7.4, the
>    generator broadcasts this update to other members of the group in a
>    Commit message, who apply it to keep their local views of the tree in
>    sync with the sender's.
> -->
> 
> 
> 18) <!--[rfced] Section 7.9. Should this example have a figure number?
> 
> Original:
> 
>          Y
>        __|__
>       /     \
>      _       _
>     / \     / \
>    E   _   G   _
> -->
> 
> 
> 19) <!--[rfced] Is this text intended to be a serial list? Also, should
> "credential" be singular or plural (i.e., "a credential" or "credentials")?
> 
> Original:
>     -  Ratchet tree: A tree with a single node, a leaf containing an
>        HPKE public key and credential for the creator
> 
> Perhaps:
>     -  Ratchet tree: A tree with a single node, a leaf containing an
>        HPKE public key, and a credential for the creator
> -->
> 
> 
> 20) <!--[rfced] To avoid redundancy, would you like to streamline this
>  list by updating the introductory sentence, removing "It
>  contains" from each bullet point, and rephrasing the last point
>  as follows?
> 
> Original:
>   For a regular, i.e. not external, commit the list is invalid if any of the following occurs:
> 
>   * It contains an individual proposal that is invalid as specified in Section 12.1.
>   * It contains an Update proposal generated by the committer.
>   * It contains a Remove proposal that removes the committer.
>   * It contains multiple Update and/or Remove proposals that apply to the same leaf.
>     If the committer has received multiple such proposals they SHOULD prefer any Remove
>     received, or the most recent Update if there are no Removes.
>   * It contains multiple Add proposals that contain KeyPackages that represent the same
>     client according to the application (for example, identical signature keys).
>   * It contains an Add proposal with a KeyPackage that represents a client already in
>     the group according to the application, unless there is a Remove proposal in the
>     list removing the matching client from the group.
>   * It contains multiple PreSharedKey proposals that reference the same PreSharedKeyID.
>   * It contains multiple GroupContextExtensions proposals.
>   * It contains a ReInit proposal together with any other proposal. If the committer has
>     received other proposals during the epoch, they SHOULD prefer them over the ReInit
>     proposal, allowing the ReInit to be resent and applied in a subsequent epoch.
>   * It contains an ExternalInit proposal.
>   * It contains a proposal with a non-default proposal type that is not supported by
>     some members of the group that will process the Commit (i.e., members being added or
>     removed by the Commit do not need to support the proposal type).
>   * After processing the commit the ratchet tree is invalid, in particular, if it contains
>     any leaf node that is invalid according to Section 7.3.
> 
> Perhaps:
>   For a regular, i.e., not external, commit, the list is invalid if it contains any of the
>   following:
> 
>   * An individual proposal that is invalid as specified in Section 12.1
>   * An Update proposal generated by the committer
>   * A Remove proposal that removes the committer
>   * Multiple Update and/or Remove proposals that apply to the same leaf.
>     If the committer has received multiple such proposals they SHOULD prefer any Remove
>     received, or the most recent Update if there are no Removes.
>   * Multiple Add proposals that contain KeyPackages that represent the same
>     client according to the application (for example, identical signature keys)
>   * An Add proposal with a KeyPackage that represents a client already in
>     the group according to the application, unless there is a Remove proposal in the
>     list removing the matching client from the group
>   * Multiple PreSharedKey proposals that reference the same PreSharedKeyID
>   * Multiple GroupContextExtensions proposals
>   * A ReInit proposal together with any other proposal. If the committer has
>     received other proposals during the epoch, they SHOULD prefer them over the ReInit
>     proposal, allowing the ReInit to be resent and applied in a subsequent epoch.
>   * An ExternalInit proposal
>   * A proposal with a non-default proposal type that is not supported by
>     some members of the group that will process the Commit (i.e., members being added or
>     removed by the Commit do not need to support the proposal type)
>   * An invalid ratchet tree after processing the commit, in particular, if it contains any
>     node that is invalid according to Section 7.3
> -->
> 
> 
> 21) <!--[rfced] Is the intended meaning that the proposals field is
> populated from "Proposals received during the current epoch" and
> "an empty path field" (option A) or that an initial Commit object
> and an empty path field should be constructed (option B)? Please
> clarify.
> 
> Original:
>    *  Construct an initial Commit object with the proposals field
>       populated from Proposals received during the current epoch,
>       and an empty path field.
> 
> Perhaps:
> A) *  Construct an initial Commit object with the proposals field
>       populated from Proposals received during the current epoch
>       and from an empty path field.
> 
> or
> 
> B) *  Construct an initial Commit object with the proposals field
>       populated from Proposals received during the current epoch,
>       and construct an empty path field.
> -->
> 
> 
> 22) <!--[rfced] In order for the following list to be parallel, we would
> like to update the first 3 points with verbs as shown below.
> Please let us know if this is agreeable or if you prefer otherwise.
> 
> Original:
>    *  Construct a GroupInfo reflecting the new state:
> 
>       -  Group ID, epoch, tree, confirmed transcript hash, interim
>          transcript hash, and group context extensions from the new
>          state
> 
>       -  The confirmation_tag from the FramedContentAuthData object
> 
>       -  Other extensions as defined by the application
> 
>       -  Optionally derive an external keypair as described in Section 8
>          (required for External Commits, see Section 12.4.3.2)
> 
>       -  Sign the GroupInfo using the member's private signing key
> 
>       -  Encrypt the GroupInfo using the key and nonce derived from the
>          joiner_secret for the new epoch (see Section 12.4.3.1)
> Perhaps:
>    *  Construct a GroupInfo reflecting the new state as follows:
> 
>       -  Derive a Group ID, an epoch, a tree, a confirmed transcript hash,
>          an interim transcript hash, and group context extensions from the
>          new state.
> 
>       -  Create the confirmation_tag from the FramedContentAuthData object.
> 
>       -  Use other extensions as defined by the application.
> 
>       -  Optionally derive an external key pair, as described in Section 8
>          (required for External Commits; see Section 12.4.3.2).
> 
>       -  Sign the GroupInfo using the member's private signing key.
> 
>       -  Encrypt the GroupInfo using the key and nonce derived from the
>          joiner_secret for the new epoch (see Section 12.4.3.1).
> -->
> 
> 
> 23) <!--[rfced] Should the first 2 items in this list perhaps be a part of
> the introductory sentence since they seem to be informational
> rather than actions?
> 
> Original:
>    *  Construct a new group state using the information in the GroupInfo
>       object.
> 
>       -  The GroupContext is the group_context field from the GroupInfo
>          object.
> 
>       -  The new member's position in the tree is at the leaf my_leaf,
>          as defined above.
> 
>       -  Update the leaf my_leaf with the private key corresponding to
>          the public key in the node.
> 
>       -  If the path_secret value is set in the GroupSecrets object:
>          Identify the lowest common ancestor of the leaf node my_leaf
>          [...]
> 
> Perhaps:
>    *  Construct a new group state using the information in the GroupInfo
>       object. Note that the GroupContext is the group_context field from
>       the GroupInfo object, and the new member's position in the tree is
>       at the leaf my_leaf, as defined above.
> 
>       -  Update the leaf my_leaf with the private key corresponding to
>          the public key in the node.
> 
>       -  If the path_secret value is set in the GroupSecrets object:
>          Identify the lowest common ancestor of the leaf node my_leaf
>          [...]
> -->
> 
> 
> 24) <!--[rfced] Please clarify how "or in the path field of a Commit"
> relates to this sentence. Is the uniqueness of keys in leaf
> nodes or in the path field of a Commit?
> 
> Original:
>    Uniqueness of keys in leaf nodes is assured by explicit checks on
>    leaf nodes being added to the tree by Add or Update proposals, or in
>    the path field of a Commit.
> 
> Perhaps:
>    Uniqueness of keys in leaf nodes, or in the path field of a Commit,
>    is assured by explicit checks on leaf nodes being added to the tree
>    by Add or Update proposals.
> -->
> 
> 
> 25) <!-- [rfced] Note that we have updated the "MLS Extension Types" registry and added the IETF as the change controller for the media type registration per this note from IANA.  Please let us know if any updates are needed.
> 
> NOTE: We've listed the IETF as the change controller for the media type registration, and per the authors, have changed "KP, GI" to "KP, GI, LN" in the MLS Extension Types. We understand that these changes will be included in the AUTH48 edits.
> -->
> 
> 
> 26) <!--[rfced] Section 17.1. Regarding the author note below, please note
> that at the time of writing, "draft-ietf-tls-rfc8447bis" has not
> entered EDIT state yet. Currently, the sections are similar but
> not identical. Please review and let us know if any further
> changes are desired. Note that we added one instance of "it" as
> outlined below.
> 
> Author note:
>    "This section should be the same as the corresponding
>    text in draft-ietf-tls-rfc8447bis.  Please align the two documents if
>    they have diverged in the approval process".
> 
> Original:
>    The IETF could recommend mechanisms that have limited applicability,
>    but will provide applicability statements that describe any
>    limitations of the mechanism or necessary constraints on its use.
> 
> Current:
>    The IETF could recommend mechanisms that have limited applicability,
>    but it will provide applicability statements that describe any
>    limitations of the mechanism or necessary constraints on its use.
> -->     
> 
> 
> 27) <!--[rfced] Should the citations for RFCs 8446 and 9180 follow "The
>      mapping of ciphersuites" or "TLS signature schemes" instead of
>      "is as follows"? We see that "ciphersuites" are mentioned in both
>      of these references. "HPKE", "HMAC", and "TLS" are mentioned in
>      RFC 9180 and "HMAC" and "TLS" are mentioned in RFC 8446.
> 
> Original:
>    The mapping of ciphersuites to HPKE primitives, HMAC hash functions,
>    and TLS signature schemes is as follows [RFC9180] [RFC8446]:
> 
> Perhaps:
>    The mapping of ciphersuites [RFC8446][RFC9180] to HPKE primitives,
>    HMAC hash functions, and TLS signature schemes is as follows:
> -->
> 
> 
> 28) <!--[rfced] FYI: We have removed instances of "MIME" from Section
> 17.10 per guidance from IANA. Note that it states the following
> under the "Media Types" registry
> (https://www.iana.org/assignments/media-types/media-types.xhtml):
> 
>    [RFC2046] specifies that Media Types (formerly known as MIME types) and Media
>    Subtypes will be assigned and listed by the IANA.
> -->
> 
> 
> 29) <!-- [rfced] Should the text about "Provisional registration" be included in this document?  It does not appear in the IANA registration - see https://www.iana.org/assignments/media-types/message/mls. 
> 
>    Provisional registration? (standards tree only):  No
> -->
> 
> 
> 30) <!--[rfced] Appendices A and B: Would it be correct to add "and" to
> the list of letters in these tree examples for consistency as shown below?
> 
> Appendix A:
> a)
> Original:
>    To construct the tree in Figure 11:
>    * A creates a group with B, ..., G
>    * F sends an empty Commit, setting X, Y, W
>    * G removes C and D, blanking V, U, and setting Y, W
> 
> Perhaps:
>    To construct the tree in Figure 11:
>    * A creates a group with B, ..., G
>    * F sends an empty Commit, setting X, Y, and W
>    * G removes C and D, blanking V and U, and setting Y and W
> 
> b)
> Original:
>    To construct the tree in Figure 13:
>    *  A creates a group with B, C, D
> 
> Perhaps:
>    To construct the tree in Figure 13:
>    *  A creates a group with B, C, and D
> 
> Appendix B:
> c)
> Original:
>    2.  B adds C, D: set B', X', Y
> 
>    3.  C sends empty Commit: set C', Z', Y'
> 
> Perhaps:
>    2.  B adds C and D: set B', X', and Y
> 
>    3.  C sends empty Commit: set C', Z', and Y'
> -->
> 
> 
> 31) <!-- [rfced] Terminology
> 
> a) Throughout the text, the following terminology appears to be used
> inconsistently. Please review these occurrences and let us know if/how they
> may be made consistent. 
> 
>  - Client vs. client
>      (Note: all instances are lowercase except "...to a Client" and
>       "...receiving Client"; should these be made lowercase?)
> 
> 
>  - Commit vs. commit
>      (some examples: in a Commit, for each Commit, processing a Commit, sends a Commit,
>       malformed Commit, malformed commit, creating a commit, an external commit,
>       in the commit, the first commit)
> 
>  - Credential vs. credential
>      (some examples: encoded in Credentials, the Credentials, a Credential, a credential,
>       this credential, credential type)
> 
>  - External Commit vs. external Commit vs. external commit
> 
>  - Fetch vs. fetch (1 instance each)
> 
>  - Parent Hash vs. parent hash
> 
>  - Proposal vs. proposal
>      (Please clarify if all capitalized instances are referring to a
>      "Proposal message" or "Proposal object" or if updates are needed.
>      Note that there are instances of "Add Proposal" vs. "Add proposal"
>      and "a proposal or a commit" vs. "the Proposal and Commit".)
> 
>  - Secret Tree vs. secret tree
> 
>  - Update vs. update
>      (Please clarify if all capitalized instances are referring to an
>       "Update message" or "Update proposal" or if updates are needed.)
> 
> b) The Web Portion of the RFC Style Guide
> (https://www.rfc-editor.org/styleguide/part2/) recommends that once an
> abbreviation has been introduced, the abbreviated form should be used
> thereafter. After the first expansion of the following terms, would you
> like to use the abbreviated forms thereafter?
> 
>  - Authentication Service
>  - Delivery Service
>  - forward secrecy
>  - post-compromise security
>  - pre-shared key
> 
> c) Some numbers are spelled out and some are represented as digits for
> bits and bytes, for instance, "4 bytes" vs. "four bytes". Would you
> like to make this consistent by using digits when referring to bits
> and bytes? Please let us know your preference.
> 
> d) Note that we updated the following terms to the latter forms as
> indicated below; please let us know of any objections.
> 
>  - cipher suite -> ciphersuite (for consistency)
>  - hybrid public-key encryption (HPKE) -> hybrid public key encryption (HPKE) (per RFC 9180)
>  - Input Key Material (IKM) -> Input Keying Material (IKM) (per use in other RFCs)
>  - keypair -> key pair (for consistency)
>  - public-key encryption -> public key encrption (per IANA registry and use in other RFCs)
>  - Signature algorithm -> signature algorithm (for consistency and per 8032)
> -->
> 
> 
> 32) <!-- [rfced] Please review the "Inclusive Language" portion of the online
> Style Guide <https://www.rfc-editor.org/styleguide/part2/#inclusive_language> and let
> us know if any changes are needed.
> 
> In addition, please consider whether "tradition" should be updated for clarity. 
> While the NIST website
> <https://www.nist.gov/nist-research-library/nist-technical-series-publications-author-instructions#table1>
> indicates that this term is potentially biased, it is also ambiguous. 
> "Tradition" is a subjective term, as it is not the same for everyone.
>  -->
