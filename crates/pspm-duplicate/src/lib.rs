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

#[cfg(test)]
mod tests {
    use super::*;
    use pspm_core::types::{ItemType, RepromptType};

    fn make_item(id: u32, name: &str, uri: &str, username: &str, hash: &str) -> Item {
        Item {
            id: uuid::Uuid::from_u128(id as u128),
            vault_id: uuid::Uuid::nil(),
            folder_id: None,
            organization_id: None,
            name: name.into(),
            username: Some(username.into()),
            password_hash: Some(hash.into()),
            password_encrypted: Some(hash.into()),
            uris: vec![uri.into()],
            notes: None,
            fields: vec![],
            totp_secret_encrypted: None,
            totp_uri: None,
            passkey: false,
            mfa_enabled: false,
            item_type: ItemType::Login,
            favorite: false,
            reprompt: RepromptType::None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            last_used: None,
        }
    }

    #[test]
    fn test_no_duplicates() {
        let items = vec![
            make_item(1, "Site A", "https://a.com", "user1", "hash1"),
            make_item(2, "Site B", "https://b.com", "user2", "hash2"),
        ];
        let groups = DuplicateDetector::find_duplicates(&items);
        assert!(groups.is_empty());
    }

    #[test]
    fn test_duplicate_by_hash() {
        let items = vec![
            make_item(1, "Site A", "https://a.com", "user1", "same_hash"),
            make_item(2, "Site B", "https://b.com", "user2", "same_hash"),
        ];
        let groups = DuplicateDetector::find_duplicates(&items);
        let hash_groups: Vec<_> = groups.iter().filter(|g| matches!(g.match_reason, DuplicateMatchReason::SamePasswordHash)).collect();
        assert_eq!(hash_groups.len(), 1);
        assert!(hash_groups[0].can_merge);
    }

    #[test]
    fn test_duplicate_by_website() {
        let items = vec![
            make_item(1, "Site A", "https://same.com", "user1", "hash1"),
            make_item(2, "Site B", "https://same.com", "user2", "hash2"),
        ];
        let groups = DuplicateDetector::find_duplicates(&items);
        let web_groups: Vec<_> = groups.iter().filter(|g| matches!(g.match_reason, DuplicateMatchReason::SameWebsite)).collect();
        assert_eq!(web_groups.len(), 1);
    }

    #[test]
    fn test_duplicate_by_username() {
        let items = vec![
            make_item(1, "Site A", "https://a.com", "sameuser", "hash1"),
            make_item(2, "Site B", "https://b.com", "sameuser", "hash2"),
        ];
        let groups = DuplicateDetector::find_duplicates(&items);
        let user_groups: Vec<_> = groups.iter().filter(|g| matches!(g.match_reason, DuplicateMatchReason::SameUsername)).collect();
        assert_eq!(user_groups.len(), 1);
    }

    #[test]
    fn test_duplicate_by_title() {
        let items = vec![
            make_item(1, "Same Title", "https://a.com", "user1", "hash1"),
            make_item(2, "Same Title", "https://b.com", "user2", "hash2"),
        ];
        let groups = DuplicateDetector::find_duplicates(&items);
        let title_groups: Vec<_> = groups.iter().filter(|g| matches!(g.match_reason, DuplicateMatchReason::SameTitle)).collect();
        assert_eq!(title_groups.len(), 1);
    }

    #[test]
    fn test_three_way_duplicate() {
        let items = vec![
            make_item(1, "A", "https://a.com", "u1", "same"),
            make_item(2, "B", "https://b.com", "u2", "same"),
            make_item(3, "C", "https://c.com", "u3", "same"),
        ];
        let groups = DuplicateDetector::find_duplicates(&items);
        let hash_groups: Vec<_> = groups.iter().filter(|g| matches!(g.match_reason, DuplicateMatchReason::SamePasswordHash)).collect();
        assert_eq!(hash_groups.len(), 1);
        assert_eq!(hash_groups[0].duplicate_item_ids.len(), 2);
    }
}
