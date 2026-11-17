//! The nested group tree, modelled as a flat arena.
//!
//! # Why an arena and not a recursive struct
//!
//! The obvious model for an arbitrary-depth tree is a recursive struct such as
//! `struct Group { children: Vec<Group>, .. }`. We deliberately do not use it.
//! Instead the whole forest lives in one flat map, [`GroupTree::nodes`], keyed
//! by [`GroupId`], where each [`Group`] stores its `parent` and its `children`
//! as ids rather than owning the child structs.
//!
//! This buys three things that matter for a wallet.
//!
//! 1. Serialization is trivial and safe. A flat `map<id, node>` round-trips
//!    through CBOR without any recursion, so a pathologically deep tree cannot
//!    blow the stack while (de)serialising, and there is no ownership puzzle to
//!    encode.
//! 2. Moving a subtree is a pointer re-link, not a deep move. Reparenting a
//!    node means editing three vectors (drop from the old parent's `children`,
//!    push onto the new parent's, rewrite the node's `parent`) in place. In a
//!    recursive struct the same operation forces you to lift an owned subtree
//!    out of one `Vec<Group>` and graft it into another, fighting the borrow
//!    checker the whole way.
//! 3. Ids stay stable across every reorganisation, so other objects can
//!    reference a group by id and never dangle.
//!
//! The cost is that the parent/children invariant is maintained by hand in the
//! mutators rather than guaranteed by the shape of the data. All mutation goes
//! through the methods on [`GroupTree`], which are the only place that
//! invariant is enforced.

use crate::id::GroupId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A single node in the [`GroupTree`].
///
/// A group is a labelled folder. It carries display metadata (`name`, `notes`,
/// `tags`) and its structural links (`parent`, `children`) as ids. Accounts are
/// not stored inline here; an [`crate::account::Account`] points back at the
/// group it belongs to (see [`crate::account::Account::group`]), so listing a
/// group's accounts is a filter over the account map rather than a field on the
/// node.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Group {
    /// This group's own id. The root group's id is [`GroupTree::root`].
    pub id: GroupId,
    /// The parent group's id, or `None` for the root.
    pub parent: Option<GroupId>,
    /// Child group ids, in display order.
    pub children: Vec<GroupId>,
    /// Human-facing name.
    pub name: String,
    /// Free-form notes.
    pub notes: String,
    /// Arbitrary user tags.
    pub tags: Vec<String>,
}

/// An arbitrary-depth tree of [`Group`] nodes held in a flat arena.
///
/// Construct one with [`GroupTree::new`], which seeds the arena with a single
/// root node. Every other node descends from that root. The tree never becomes
/// empty: the root cannot be removed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupTree {
    /// The id of the root node, which always exists and has no parent.
    root: GroupId,
    /// The arena: every node in the tree, keyed by id. See the module docs for
    /// why nodes are stored flat rather than nested.
    nodes: BTreeMap<GroupId, Group>,
}

impl GroupTree {
    /// Create a new tree containing only a root group with the given name.
    pub fn new(root_name: impl Into<String>) -> Self {
        let root = GroupId::generate();
        let node = Group {
            id: root.clone(),
            parent: None,
            children: Vec::new(),
            name: root_name.into(),
            notes: String::new(),
            tags: Vec::new(),
        };
        let mut nodes = BTreeMap::new();
        nodes.insert(root.clone(), node);
        Self { root, nodes }
    }

    /// The root group's id.
    pub fn root(&self) -> &GroupId {
        &self.root
    }

    /// Borrow a group by id, or `None` if no such node exists.
    pub fn get(&self, id: &GroupId) -> Option<&Group> {
        self.nodes.get(id)
    }

    /// Iterate over every group in the tree in id order.
    ///
    /// The order is stable but not structural; use [`GroupTree::children`] or
    /// [`GroupTree::path_to`] when hierarchy matters.
    pub fn iter(&self) -> impl Iterator<Item = &Group> {
        self.nodes.values()
    }

    /// The direct child ids of a group, or `None` if the group is unknown.
    pub fn children(&self, id: &GroupId) -> Option<&[GroupId]> {
        self.nodes.get(id).map(|g| g.children.as_slice())
    }

    /// The chain of ids from the root down to and including `id`.
    ///
    /// Returns `None` if the id is unknown. The first element is always the
    /// root and the last is always `id`.
    pub fn path_to(&self, id: &GroupId) -> Option<Vec<GroupId>> {
        if !self.nodes.contains_key(id) {
            return None;
        }
        let mut chain = Vec::new();
        let mut cursor = Some(id.clone());
        while let Some(current) = cursor {
            let node = self.nodes.get(&current)?;
            cursor = node.parent.clone();
            chain.push(current);
        }
        chain.reverse();
        Some(chain)
    }

    /// Add a new child group under `parent` and return its fresh id.
    ///
    /// Fails with [`crate::Error::GroupNotFound`] if `parent` does not exist.
    pub fn add(&mut self, parent: &GroupId, name: impl Into<String>) -> crate::Result<GroupId> {
        if !self.nodes.contains_key(parent) {
            return Err(crate::Error::GroupNotFound(parent.clone()));
        }
        let id = GroupId::generate();
        let node = Group {
            id: id.clone(),
            parent: Some(parent.clone()),
            children: Vec::new(),
            name: name.into(),
            notes: String::new(),
            tags: Vec::new(),
        };
        self.nodes.insert(id.clone(), node);
        // The parent is known to exist from the guard above.
        self.nodes
            .get_mut(parent)
            .expect("parent checked present")
            .children
            .push(id.clone());
        Ok(id)
    }

    /// Rename a group in place.
    pub fn rename(&mut self, id: &GroupId, name: impl Into<String>) -> crate::Result<()> {
        match self.nodes.get_mut(id) {
            Some(node) => {
                node.name = name.into();
                Ok(())
            }
            None => Err(crate::Error::GroupNotFound(id.clone())),
        }
    }

    /// Reparent `id` under `new_parent`, re-linking both parents' child lists.
    ///
    /// Fails with [`crate::Error::RootImmutable`] if `id` is the root, and with
    /// [`crate::Error::GroupCycle`] if `new_parent` is `id` itself or any node
    /// in `id`'s own subtree.
    pub fn move_node(&mut self, id: &GroupId, new_parent: &GroupId) -> crate::Result<()> {
        if *id == self.root {
            return Err(crate::Error::RootImmutable);
        }
        if !self.nodes.contains_key(id) {
            return Err(crate::Error::GroupNotFound(id.clone()));
        }
        if !self.nodes.contains_key(new_parent) {
            return Err(crate::Error::GroupNotFound(new_parent.clone()));
        }
        // Moving a node under itself or any of its descendants would sever that
        // subtree from the root. `new_parent` is inside `id`'s subtree exactly
        // when `id` appears on the path from the root down to `new_parent`.
        let target_path = self
            .path_to(new_parent)
            .expect("new_parent checked present");
        if target_path.contains(id) {
            return Err(crate::Error::GroupCycle);
        }

        let old_parent = self
            .nodes
            .get(id)
            .expect("id checked present")
            .parent
            .clone();
        if let Some(old) = old_parent
            && let Some(old_node) = self.nodes.get_mut(&old)
        {
            old_node.children.retain(|c| c != id);
        }
        self.nodes.get_mut(id).expect("id checked present").parent = Some(new_parent.clone());
        self.nodes
            .get_mut(new_parent)
            .expect("new_parent checked present")
            .children
            .push(id.clone());
        Ok(())
    }

    /// Remove a leaf group.
    ///
    /// This is the low-level primitive: it only unlinks the node from its
    /// parent and drops it from the arena, and it fails with
    /// [`crate::Error::GroupNotEmpty`] if the node still has children. The
    /// wallet-level [`crate::Wallet::remove_group`] layers account-handling
    /// policy on top of this.
    pub fn remove(&mut self, id: &GroupId) -> crate::Result<Group> {
        if *id == self.root {
            return Err(crate::Error::RootImmutable);
        }
        let node = self
            .nodes
            .get(id)
            .ok_or_else(|| crate::Error::GroupNotFound(id.clone()))?;
        if !node.children.is_empty() {
            return Err(crate::Error::GroupNotEmpty);
        }
        let parent = node.parent.clone();
        if let Some(parent) = parent
            && let Some(parent_node) = self.nodes.get_mut(&parent)
        {
            parent_node.children.retain(|c| c != id);
        }
        Ok(self.nodes.remove(id).expect("id checked present"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_tree_has_only_a_root() {
        let tree = GroupTree::new("Root");
        assert_eq!(tree.iter().count(), 1);
        assert_eq!(tree.get(tree.root()).unwrap().name, "Root");
        assert!(tree.get(tree.root()).unwrap().parent.is_none());
    }

    #[test]
    fn add_links_parent_and_child() {
        let mut tree = GroupTree::new("Root");
        let root = tree.root().clone();
        let child = tree.add(&root, "Child").unwrap();
        assert_eq!(tree.children(&root).unwrap(), std::slice::from_ref(&child));
        assert_eq!(tree.get(&child).unwrap().parent, Some(root));
    }

    #[test]
    fn add_under_missing_parent_fails() {
        let mut tree = GroupTree::new("Root");
        let err = tree.add(&GroupId::from_raw("nope"), "x").unwrap_err();
        assert!(matches!(err, crate::Error::GroupNotFound(_)));
    }

    #[test]
    fn path_to_runs_root_to_node() {
        let mut tree = GroupTree::new("Root");
        let root = tree.root().clone();
        let a = tree.add(&root, "A").unwrap();
        let b = tree.add(&a, "B").unwrap();
        assert_eq!(tree.path_to(&b).unwrap(), vec![root, a, b]);
        assert!(tree.path_to(&GroupId::from_raw("nope")).is_none());
    }

    #[test]
    fn move_node_relinks_both_parents() {
        let mut tree = GroupTree::new("Root");
        let root = tree.root().clone();
        let a = tree.add(&root, "A").unwrap();
        let b = tree.add(&root, "B").unwrap();
        let c = tree.add(&a, "C").unwrap();
        tree.move_node(&c, &b).unwrap();
        assert_eq!(tree.get(&c).unwrap().parent, Some(b.clone()));
        assert!(tree.children(&a).unwrap().is_empty());
        assert_eq!(tree.children(&b).unwrap(), &[c]);
    }

    #[test]
    fn move_node_rejects_cycles_and_root() {
        let mut tree = GroupTree::new("Root");
        let root = tree.root().clone();
        let a = tree.add(&root, "A").unwrap();
        let b = tree.add(&a, "B").unwrap();
        // Moving A under its own descendant B must be rejected.
        assert!(matches!(
            tree.move_node(&a, &b).unwrap_err(),
            crate::Error::GroupCycle
        ));
        // Moving A under itself must be rejected.
        assert!(matches!(
            tree.move_node(&a, &a).unwrap_err(),
            crate::Error::GroupCycle
        ));
        // The root cannot be moved.
        assert!(matches!(
            tree.move_node(&root, &a).unwrap_err(),
            crate::Error::RootImmutable
        ));
    }

    #[test]
    fn remove_unlinks_leaf_and_refuses_non_empty() {
        let mut tree = GroupTree::new("Root");
        let root = tree.root().clone();
        let a = tree.add(&root, "A").unwrap();
        let _b = tree.add(&a, "B").unwrap();
        assert!(matches!(
            tree.remove(&a).unwrap_err(),
            crate::Error::GroupNotEmpty
        ));
        assert!(matches!(
            tree.remove(&root).unwrap_err(),
            crate::Error::RootImmutable
        ));
        // The leaf B can go, which then lets A go.
        let leaf = tree.children(&a).unwrap()[0].clone();
        tree.remove(&leaf).unwrap();
        tree.remove(&a).unwrap();
        assert!(tree.children(&root).unwrap().is_empty());
    }
}
