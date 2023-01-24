use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use crate::{Mid, Rtc};
use rtp::Rid;

pub struct Stats {
    pub peer: BitsCount,
    last_peer: BitsCount,
    last_now: Option<Instant>,
    last_snapshot: StatsSnapshot,
    events: VecDeque<PeerStats>,
}

#[derive(Clone, Copy)]
pub struct BitsCount {
    pub tx: usize,
    pub rx: usize,
}

type Bytes = u64;

pub struct StatsSnapshot {
    pub peer_tx: Bytes,
    pub peer_rx: Bytes,
    pub tx: Bytes,
    pub rx: Bytes,
    pub ts: Instant,
}

impl StatsSnapshot {
    fn new(ts: Instant) -> StatsSnapshot {
        // TODO: is there a way to only provide the `ts` property
        // which does not conform to Default,
        // and have the rest generated by ..Default::default() ?
        StatsSnapshot {
            peer_rx: 0,
            peer_tx: 0,
            tx: 0,
            rx: 0,
            ts,
        }
    }

    pub fn from(rtc: &mut Rtc, now: Instant) -> StatsSnapshot {
        let session = &mut rtc.session;
        let peer_tx = rtc.peer_bytes_tx;
        let peer_rx = rtc.peer_bytes_rx;
        let rx: Bytes = session
            .media()
            .flat_map(|m| &m.sources_rx)
            .map(|s| s.bytes_rx)
            .sum();
        let tx: Bytes = session
            .media()
            .flat_map(|m| &m.sources_tx)
            .map(|s| s.bytes_tx)
            .sum();

        StatsSnapshot {
            peer_tx,
            peer_rx,
            tx,
            rx,
            ts: now,
        }
    }
}

const TIMING_ADVANCE: Duration = Duration::from_secs(1);

impl Stats {
    pub fn new() -> Stats {
        Stats {
            last_now: None,
            peer: BitsCount { rx: 0, tx: 0 },
            last_peer: BitsCount { rx: 0, tx: 0 },
            last_snapshot: StatsSnapshot::new(Instant::now()),
            events: VecDeque::new(),
        }
    }

    pub fn handle_timeout(&mut self, snapshot: StatsSnapshot) {
        let now = snapshot.ts;
        let Some(last_now) = self.last_now else {
            self.last_now = Some(now);
            return;
        };
        let min_step = last_now + TIMING_ADVANCE;
        if now < min_step {
            return;
        }

        let elapsed = (now - last_now).as_secs_f32();

        // enqueue stas and timestampt them so they can be sent out

        let event = PeerStats {
            peer_bitrate_rx: (snapshot.peer_rx - self.last_snapshot.peer_rx) as f32 * 8.0 / elapsed,
            peer_bitrate_tx: (snapshot.peer_tx - self.last_snapshot.peer_tx) as f32 * 8.0 / elapsed,
            bitrate_rx: (snapshot.rx - self.last_snapshot.rx) as f32 * 8.0 / elapsed,
            bitrate_tx: (snapshot.tx - self.last_snapshot.tx) as f32 * 8.0 / elapsed,
            ts: now,
        };

        self.events.push_back(event);
        self.last_peer = self.peer;

        self.last_snapshot = snapshot;
        self.last_now = Some(now);
    }

    /// Poll for the next time to call [`self::handle_timeout`].
    pub fn poll_timeout(&mut self) -> Option<Instant> {
        let last_now = self.last_now?;

        Some(last_now + TIMING_ADVANCE)
    }

    pub fn poll_output(&mut self) -> Option<PeerStats> {
        self.events.pop_front()
    }
}

// TODO: removed other derives to quickly add Instant, rethink
#[derive(Debug, Clone)]
pub struct PeerStats {
    pub peer_bitrate_rx: f32,
    pub peer_bitrate_tx: f32,
    pub bitrate_rx: f32,
    pub bitrate_tx: f32,
    pub ts: Instant,
}

// TODO: ztuff below

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MediaEgressStats {
    pub mid: Mid,
    pub rid: Option<Rid>,

    pub bitrate_tx: f32,
    // TODO
    pub remote: RemoteIngressStats,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RemoteIngressStats {
    pub bitrate_rx: f32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MediaIngressStats {
    pub bitrate_tx: f32,
    // TODO
    pub remote: RemoteEgressStats,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RemoteEgressStats {
    pub bitrate_rx: f32,
}