use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// 連続ログイン失敗を記録し、一定回数を超えたキーを一時的にロックする
/// インプロセスのガード。キーは呼び出し側が付与する（`user:<name>` /
/// `client:<id>` など）。プロセス再起動でリセットされる割り切りの実装で、
/// オンラインのブルートフォース／クレデンシャルスタッフィングの速度を
/// 落とすことが目的。
pub struct LoginGuard {
    max_failures: u32,
    lockout: Duration,
    entries: Mutex<HashMap<String, Entry>>,
}

struct Entry {
    failures: u32,
    last_failure: Instant,
}

/// 記録済みキーがこの数を超えたら、ロック期間を過ぎた古いエントリを掃除する。
const PRUNE_THRESHOLD: usize = 10_000;

impl LoginGuard {
    /// `max_failures` に 0 を渡すとガードは無効化される。
    pub fn new(max_failures: u32, lockout: Duration) -> Self {
        Self {
            max_failures,
            lockout,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// キーが現在ロック中なら残り時間を返す。ロックが期限切れならエントリを
    /// 破棄して `None`（＝再試行を許可）。
    pub fn check(&self, key: &str) -> Option<Duration> {
        if self.max_failures == 0 {
            return None;
        }
        let mut map = self.entries.lock().expect("login guard lock poisoned");
        let entry = map.get(key)?;
        if entry.failures >= self.max_failures {
            let elapsed = entry.last_failure.elapsed();
            if elapsed < self.lockout {
                return Some(self.lockout - elapsed);
            }
            map.remove(key);
        }
        None
    }

    /// 失敗を1回記録し、そのキーの連続失敗回数を返す。
    pub fn record_failure(&self, key: &str) -> u32 {
        if self.max_failures == 0 {
            return 0;
        }
        let now = Instant::now();
        let mut map = self.entries.lock().expect("login guard lock poisoned");
        if map.len() >= PRUNE_THRESHOLD {
            let lockout = self.lockout;
            map.retain(|_, e| e.last_failure.elapsed() < lockout);
        }
        let entry = map.entry(key.to_string()).or_insert(Entry {
            failures: 0,
            last_failure: now,
        });
        entry.failures += 1;
        entry.last_failure = now;
        entry.failures
    }

    /// ログイン成功でそのキーの失敗履歴をリセットする。
    pub fn record_success(&self, key: &str) {
        let mut map = self.entries.lock().expect("login guard lock poisoned");
        map.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locks_after_max_failures() {
        let guard = LoginGuard::new(3, Duration::from_secs(60));
        assert!(guard.check("user:alice").is_none());
        guard.record_failure("user:alice");
        guard.record_failure("user:alice");
        assert!(guard.check("user:alice").is_none(), "below threshold");
        guard.record_failure("user:alice");
        assert!(guard.check("user:alice").is_some(), "locked at threshold");
        // 別キーには影響しない
        assert!(guard.check("user:bob").is_none());
    }

    #[test]
    fn success_resets_failures() {
        let guard = LoginGuard::new(2, Duration::from_secs(60));
        guard.record_failure("user:alice");
        guard.record_success("user:alice");
        guard.record_failure("user:alice");
        assert!(guard.check("user:alice").is_none());
    }

    #[test]
    fn lock_expires_after_lockout() {
        let guard = LoginGuard::new(1, Duration::from_millis(10));
        guard.record_failure("user:alice");
        assert!(guard.check("user:alice").is_some());
        std::thread::sleep(Duration::from_millis(20));
        assert!(guard.check("user:alice").is_none(), "lock expired");
    }

    #[test]
    fn zero_max_failures_disables_guard() {
        let guard = LoginGuard::new(0, Duration::from_secs(60));
        for _ in 0..100 {
            guard.record_failure("user:alice");
        }
        assert!(guard.check("user:alice").is_none());
    }
}
