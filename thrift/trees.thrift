namespace java com.x.dmv2.thriftjava
#@namespace scala com.x.dmv2.thriftscala
#@namespace strato com.x.dmv2
#@namespace py com.x.dmv2.thriftpython

// thrifts for new tree updates
struct Member {
  1: required i64 userId
  2: required i64 keyVersion
}

struct PubKeyBytes {
  1: required binary pubKeyBytes
}

struct MemberKeyInfo {
  1: optional binary identityPublicKey
  2: optional binary signingPublicKey
  3: optional binary identityKeySignature
}

struct TreeKeyData {
  1: required PubKeyBytes publicKey
  2: required binary subTreeHash
}

struct TreeNode {
  1: optional Member member
  2: optional TreeKeyData keyData
  // secret key of this node, encrypted to the public key of its children
  // map because if child is null we recurse and encrypt to children of children, etc
  3: optional map<binary, binary> nodeSecretKeyEncryptions
}

struct MaybeTreeNode {
  1: optional TreeNode node
}

enum GroupOpType {
  GenGroup = 1,
  Edit = 6,
}

struct GroupOpData {
  1: optional string groupId
  2: optional i64 treeVersion
  3: optional Member actionBy
  4: optional TypeData typeData
  // 5: optional map<i64, string> memberPublicKeys // DEPRECATED - backend never shipped this
  6: optional map<i64, MemberKeyInfo> memberKeyInfo // extensible key material per member
}

union TypeData {
  1: GenGroupOpData genGroup
  6: EditOpData edit
}

struct GenGroupOpData {
  1: optional map<i32, map<binary, binary>> updateMap  // Keys/values → ByteString in generated code
  2: optional map<i32, binary> newPathPks
  3: optional list<Member> initialMembers
}

struct EditOpData {
  1: optional map<i32, map<binary, binary>> updateMap
  2: optional map<i32, binary> newPathPks
  3: optional list<Member> membersLeft
  4: optional list<Member> membersToAdd
  5: optional list<Member> membersUpdated
  6: optional list<MaybeTreeNode> fullTreeList
}
