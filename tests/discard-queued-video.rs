use std::time::{Duration, Instant};
use str0m::bwe::Bitrate;
use str0m::media::MediaKind;
use str0m::rtp::{RtpWrite, Ssrc};
use str0m::{Input, Rtc, RtcError};
mod common;
use common::{connect_l_r_with_rtc, init_crypto_default};

#[test]
fn capacity_collapse_discards_queued_video() -> Result<(), RtcError> {
    init_crypto_default();
    let now = Instant::now();
    let sender = Rtc::builder()
        .set_rtp_mode(true)
        .enable_bwe(Some(Bitrate::kbps(100)))
        .build(now);
    let receiver = Rtc::builder().set_rtp_mode(true).build(now);
    let (mut l, mut r) = connect_l_r_with_rtc(sender, receiver);
    let mid = "vid".into();
    let ssrc: Ssrc = 42.into();
    l.direct_api().declare_media(mid, MediaKind::Video);
    l.direct_api()
        .declare_stream_tx(ssrc, None, mid, None)
        .set_unpaced(false);
    r.direct_api().declare_media(mid, MediaKind::Video);
    let pt = l
        .codec_config()
        .params()
        .iter()
        .find(|p| p.spec().codec.is_video())
        .unwrap()
        .pt();
    let now = l.last.max(r.last) + Duration::from_millis(1);
    for seq in 1..=100 {
        l.direct_api()
            .stream_tx(&ssrc)
            .unwrap()
            .write_rtp(RtpWrite::new(pt, seq.into(), 90_000, now, vec![0; 1_000]));
    }
    l.handle_input(Input::Timeout(now))?;
    assert_eq!(
        l.direct_api()
            .stream_tx(&ssrc)
            .unwrap()
            .queue_info()
            .unwrap()
            .packet_count(),
        100
    );
    // Existing allocator/transport API can lower probe demand, but cannot
    // revoke packets already queued by the frame writer.
    l.bwe().set_desired_bitrate(Bitrate::ZERO);
    assert!(l.direct_api().discard_queued_media(mid));
    l.handle_input(Input::Timeout(now + Duration::from_secs(3)))?;
    assert_eq!(
        l.direct_api()
            .stream_tx(&ssrc)
            .unwrap()
            .queue_info()
            .unwrap()
            .packet_count(),
        0,
        "suspended video must not be force-drained over the audio path"
    );
    Ok(())
}

#[test]
fn running_loop_blackout_discards_video_but_preserves_audio_and_stream_identity()
-> Result<(), RtcError> {
    use common::progress;
    use netem::{NetemConfig, Probability, RandomLoss};
    use str0m::Event;
    init_crypto_default();
    let now = Instant::now();
    let sender = Rtc::builder()
        .set_rtp_mode(true)
        .enable_bwe(Some(Bitrate::kbps(100)))
        .build(now);
    let receiver = Rtc::builder().set_rtp_mode(true).build(now);
    let (mut l, mut r) = connect_l_r_with_rtc(sender, receiver);
    let video = "vid".into();
    let audio = "aud".into();
    let video_ssrc: Ssrc = 42.into();
    let audio_ssrc: Ssrc = 43.into();
    for (mid, kind, ssrc) in [
        (video, MediaKind::Video, video_ssrc),
        (audio, MediaKind::Audio, audio_ssrc),
    ] {
        l.direct_api().declare_media(mid, kind);
        l.direct_api().declare_stream_tx(ssrc, None, mid, None);
        r.direct_api().declare_media(mid, kind);
        r.direct_api().expect_stream_rx(ssrc, None, mid, None);
    }
    let vpt = l.params_vp8().pt();
    let apt = l.params_opus().pt();
    let at = l.last.max(r.last);
    l.last = at;
    r.last = at;
    r.set_netem(NetemConfig::new().loss(RandomLoss::new(Probability(1.0))));
    for seq in 1..=100 {
        l.direct_api()
            .stream_tx(&video_ssrc)
            .unwrap()
            .write_rtp(RtpWrite::new(
                vpt,
                seq.into(),
                90_000,
                at,
                vec![0x11; 1_000],
            ));
    }
    l.handle_input(Input::Timeout(at))?;
    l.bwe().set_probe_limit(Some(Bitrate::ZERO));
    assert!(l.direct_api().discard_queued_media(video));
    let end_blackout = at + Duration::from_secs(3);
    while l.last.min(r.last) < end_blackout {
        progress(&mut l, &mut r)?;
    }
    r.set_netem(NetemConfig::new());
    let at = l.last.max(r.last);
    l.direct_api()
        .stream_tx(&audio_ssrc)
        .unwrap()
        .write_rtp(RtpWrite::new(apt, 1.into(), 48_000, at, vec![0x22; 80]));
    l.direct_api()
        .stream_tx(&video_ssrc)
        .unwrap()
        .write_rtp(RtpWrite::new(vpt, 101.into(), 180_000, at, vec![0x33; 100]));
    let end = at + Duration::from_secs(1);
    while l.last.min(r.last) < end {
        progress(&mut l, &mut r)?;
    }
    let packets: Vec<_> = r
        .events
        .iter()
        .filter_map(|(_, event)| match event {
            Event::RtpPacket(packet) => Some(packet),
            _ => None,
        })
        .collect();
    assert!(
        packets
            .iter()
            .any(|packet| packet.header.ssrc == audio_ssrc && packet.payload[0] == 0x22)
    );
    assert!(packets.iter().any(|packet| packet.header.ssrc == video_ssrc
        && packet.header.sequence_number == 101
        && packet.payload[0] == 0x33));
    assert!(
        packets.iter().all(|packet| packet.payload[0] != 0x11),
        "revoked video must not leak after recovery"
    );
    assert_eq!(
        l.direct_api().stream_tx(&video_ssrc).unwrap().ssrc(),
        video_ssrc
    );
    Ok(())
}
