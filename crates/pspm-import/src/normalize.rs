use pspm_core::types::Item;

pub fn normalize_items(items: &mut [Item]) {
    for item in items.iter_mut() {
        if item.name.trim().is_empty() {
            if let Some(uri) = item.uris.first() {
                item.name = extract_title_from_url(uri);
            }
        }

        item.uris = item
            .uris
            .iter()
            .map(|u| normalize_url(u))
            .filter(|u| !u.is_empty())
            .collect();

        item.name = item.name.trim().to_string();
    }
}

fn normalize_url(url: &str) -> String {
    let url = url.trim();
    if url.is_empty() {
        return String::new();
    }
    let url = url.trim_end_matches('/');
    url.to_lowercase()
}

fn extract_title_from_url(url: &str) -> String {
    let url = url.trim().trim_end_matches('/').to_lowercase();
    if let Some(domain) = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
    {
        domain.split('/').next().unwrap_or(domain).to_string()
    } else {
        url.split('/').next().unwrap_or(&url).to_string()
    }
}
