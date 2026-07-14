use std::collections::HashMap;
use pspm_core::types::{DuplicateGroup, DuplicateMatchReason, Item};

pub struct DuplicateDetector;

impl DuplicateDetector {
    pub fn find_duplicates(items: &[Item]) -> Vec<DuplicateGroup> {
        let mut groups = Vec::new();

        groups.extend(Self::find_by_same_website(items));
        groups.extend(Self::find_by_same_username(items));
        groups.extend(Self::find_by_same_password_hash(items));
        groups.extend(Self::find_by_same_title(items));

        groups
    }

    fn find_by_same_password_hash(items: &[Item]) -> Vec<DuplicateGroup> {
        let mut by_hash: HashMap<&str, Vec<&Item>> = HashMap::new();
        for item in items {
            if let Some(ref hash) = item.password_hash {
                by_hash.entry(hash).or_default().push(item);
            }
        }

        build_groups(by_hash, DuplicateMatchReason::SamePasswordHash)
    }

    fn find_by_same_website(items: &[Item]) -> Vec<DuplicateGroup> {
        let mut by_uri: HashMap<&str, Vec<&Item>> = HashMap::new();
        for item in items {
            if let Some(uri) = item.uris.first() {
                by_uri.entry(uri.as_str()).or_default().push(item);
            }
        }

        build_groups(by_uri, DuplicateMatchReason::SameWebsite)
    }

    fn find_by_same_username(items: &[Item]) -> Vec<DuplicateGroup> {
        let mut by_user: HashMap<&str, Vec<&Item>> = HashMap::new();
        for item in items {
            if let Some(ref username) = item.username {
                by_user.entry(username).or_default().push(item);
            }
        }

        build_groups(by_user, DuplicateMatchReason::SameUsername)
    }

    fn find_by_same_title(items: &[Item]) -> Vec<DuplicateGroup> {
        let mut by_name: HashMap<&str, Vec<&Item>> = HashMap::new();
        for item in items {
            by_name.entry(item.name.as_str()).or_default().push(item);
        }

        build_groups(by_name, DuplicateMatchReason::SameTitle)
    }
}

fn build_groups<'a>(
    grouped: HashMap<&'a str, Vec<&'a Item>>,
    reason: DuplicateMatchReason,
) -> Vec<DuplicateGroup> {
    grouped
        .into_values()
        .filter(|group| group.len() > 1)
        .map(|group| {
            let canonical = group[0].id;
            let duplicates: Vec<_> = group[1..].iter().map(|i| i.id).collect();

            let can_merge = matches!(
                reason,
                DuplicateMatchReason::SamePasswordHash
                    | DuplicateMatchReason::SameWebsite
                    | DuplicateMatchReason::SameTitle
            );

            DuplicateGroup {
                canonical_item_id: canonical,
                duplicate_item_ids: duplicates,
                match_reason: reason.clone(),
                can_merge,
                merge_suggestion: format!("Keep {} and remove the rest", group[0].name),
            }
        })
        .collect()
}
