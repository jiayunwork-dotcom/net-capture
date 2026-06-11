use std::collections::{VecDeque, HashMap};
use std::time::SystemTime;

pub struct SlidingWindowCounter {
    window_secs: u32,
    per_ip_counters: HashMap<String, VecDeque<(u64, u32)>>,
    global_counters: VecDeque<(u64, u32)>,
}

impl SlidingWindowCounter {
    pub fn new(window_secs: u32) -> Self {
        let window_secs = window_secs.min(60).max(1);
        Self {
            window_secs,
            per_ip_counters: HashMap::new(),
            global_counters: VecDeque::new(),
        }
    }

    pub fn window_secs(&self) -> u32 {
        self.window_secs
    }

    pub fn record(&mut self, ip: Option<&str>, timestamp_secs: u64) {
        self.cleanup_old_entries(timestamp_secs);

        if let Some(ip) = ip {
            let counter = self.per_ip_counters
                .entry(ip.to_string())
                .or_insert_with(VecDeque::new);
            Self::add_to_counter(counter, timestamp_secs);
        }

        Self::add_to_counter(&mut self.global_counters, timestamp_secs);
    }

    fn add_to_counter(counter: &mut VecDeque<(u64, u32)>, timestamp_secs: u64) {
        if let Some(last) = counter.back_mut() {
            if last.0 == timestamp_secs {
                last.1 += 1;
                return;
            }
        }
        counter.push_back((timestamp_secs, 1));
    }

    pub fn count(&self, ip: Option<&str>, timestamp_secs: u64) -> u32 {
        let threshold = timestamp_secs.saturating_sub(self.window_secs as u64);
        let counter = match ip {
            Some(ip) => match self.per_ip_counters.get(ip) {
                Some(c) => c,
                None => return 0,
            },
            None => &self.global_counters,
        };

        counter.iter()
            .filter(|(ts, _)| *ts > threshold)
            .map(|(_, count)| *count)
            .sum()
    }

    fn cleanup_old_entries(&mut self, current_secs: u64) {
        let threshold = current_secs.saturating_sub(self.window_secs as u64);

        while let Some(front) = self.global_counters.front() {
            if front.0 <= threshold {
                self.global_counters.pop_front();
            } else {
                break;
            }
        }

        let mut ips_to_remove = Vec::new();
        for (ip, counter) in self.per_ip_counters.iter_mut() {
            while let Some(front) = counter.front() {
                if front.0 <= threshold {
                    counter.pop_front();
                } else {
                    break;
                }
            }
            if counter.is_empty() {
                ips_to_remove.push(ip.clone());
            }
        }

        for ip in ips_to_remove {
            self.per_ip_counters.remove(&ip);
        }
    }

    pub fn current_timestamp_secs() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

pub struct RateCounterManager {
    counters: HashMap<(u32, bool), SlidingWindowCounter>,
}

impl RateCounterManager {
    pub fn new() -> Self {
        Self {
            counters: HashMap::new(),
        }
    }

    pub fn get_or_create(&mut self, window_secs: u32, per_ip: bool) -> &mut SlidingWindowCounter {
        let key = (window_secs, per_ip);
        if !self.counters.contains_key(&key) {
            self.counters.insert(key, SlidingWindowCounter::new(window_secs));
        }
        self.counters.get_mut(&key).unwrap()
    }

    pub fn record_packet(&mut self, src_ip: &str, dst_ip: &str, timestamp_secs: u64) {
        for (key, counter) in self.counters.iter_mut() {
            let (_, per_ip) = key;
            if *per_ip {
                counter.record(Some(src_ip), timestamp_secs);
                counter.record(Some(dst_ip), timestamp_secs);
            } else {
                counter.record(None, timestamp_secs);
            }
        }
    }

    pub fn check_rate(&mut self, window_secs: u32, threshold: u32, src_ip: bool, ip: &str, timestamp_secs: u64) -> bool {
        let counter = self.get_or_create(window_secs, src_ip);
        let count = if src_ip {
            counter.count(Some(ip), timestamp_secs)
        } else {
            counter.count(None, timestamp_secs)
        };
        count > threshold
    }
}

impl Default for RateCounterManager {
    fn default() -> Self {
        Self::new()
    }
}
