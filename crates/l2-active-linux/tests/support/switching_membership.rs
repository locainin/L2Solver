use std::{collections::BTreeMap, error::Error};

/// Snapshot multicast address user counts on the selected interface
pub fn snapshot(index: u32) -> Result<BTreeMap<String, u32>, Box<dyn Error>> {
    let mut result = BTreeMap::new();
    for line in std::fs::read_to_string("/proc/net/dev_mcast")?.lines() {
        let mut fields = line.split_whitespace();
        let Some(raw_index) = fields.next() else {
            continue;
        };
        let _name = fields.next();
        let users = fields
            .next()
            .ok_or("missing multicast user count")?
            .parse::<u32>()?;
        let _global = fields.next();
        let address = fields.next().ok_or("missing multicast address")?;
        if raw_index.parse::<u32>()? == index {
            result.insert(address.to_owned(), users);
        }
    }
    Ok(result)
}

/// Assert the helper added only the supplied exact multicast memberships
pub fn assert_added(
    before: &BTreeMap<String, u32>,
    after: &BTreeMap<String, u32>,
    groups: impl IntoIterator<Item = String>,
) -> Result<(), Box<dyn Error>> {
    let mut expected = before.clone();
    for address in groups {
        let count = expected.entry(address).or_default();
        *count = count.checked_add(1).ok_or("multicast count overflow")?;
    }
    assert_eq!(*after, expected, "unexpected multicast memberships");
    Ok(())
}
