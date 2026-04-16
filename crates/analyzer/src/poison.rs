use guardian_core::{RiskFinding, Severity};

pub fn check_poison(incoming: &str, known_addresses: &[String]) -> Option<RiskFinding> {
    for known in known_addresses {
        if incoming == known {
            continue;
        }

        let prefix_match =
            incoming.len() >= 10 && known.len() >= 10 && incoming[..10] == known[..10];
        let suffix_match = incoming.len() >= 6
            && known.len() >= 6
            && incoming[incoming.len() - 6..] == known[known.len() - 6..];
        let distance = levenshtein(incoming, known);

        if prefix_match && suffix_match && distance < 10 {
            return Some(RiskFinding {
                module: "poison".to_string(),
                severity: Severity::Critical,
                weight: 85,
                description: format!(
                    "Address {} visually mimics your known address {}",
                    shorten(incoming),
                    shorten(known)
                ),
                payload: serde_json::json!({
                    "suspicious": incoming,
                    "mimics": known,
                    "levenshtein_distance": distance,
                }),
            });
        }
    }

    None
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut dp = vec![vec![0usize; b.len() + 1]; a.len() + 1];

    for (index, row) in dp.iter_mut().enumerate() {
        row[0] = index;
    }
    for column in 0..=b.len() {
        dp[0][column] = column;
    }

    for i in 1..=a.len() {
        for j in 1..=b.len() {
            dp[i][j] = if a[i - 1] == b[j - 1] {
                dp[i - 1][j - 1]
            } else {
                1 + dp[i - 1][j].min(dp[i][j - 1]).min(dp[i - 1][j - 1])
            };
        }
    }

    dp[a.len()][b.len()]
}

fn shorten(address: &str) -> String {
    if address.len() <= 14 {
        address.to_string()
    } else {
        format!("{}...{}", &address[..8], &address[address.len() - 6..])
    }
}
