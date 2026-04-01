//! PTP message exchange and delay computation integration tests.
//!
//! Tests the full PTP E2E delay measurement cycle:
//! Sync -> FollowUp -> DelayReq -> DelayResp, plus BMCA comparison.

use rtime_core::timestamp::PtpTimestamp;
use rtime_ptp::bmca::{compare_announce, select_best_master, BmcaResult};
use rtime_ptp::delay::{compute_e2e, E2eDelayState};
use rtime_ptp::message::{
    AnnounceBody, ClockQuality, MessageType, PtpFlags, PtpHeader, PtpMessage, PortIdentity,
};

fn master_port() -> PortIdentity {
    PortIdentity {
        clock_identity: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77],
        port_number: 1,
    }
}

fn slave_port() -> PortIdentity {
    PortIdentity {
        clock_identity: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11],
        port_number: 1,
    }
}

#[test]
fn full_e2e_sync_exchange() {
    // Simulate a complete two-step E2E delay measurement cycle.

    // 1. Master sends Sync (two-step: origin timestamp is approximate).
    let sync_approx_ts = PtpTimestamp::new(1_000_000, 0);
    let mut sync_header = PtpHeader::new(MessageType::Sync, 0, master_port(), 100);
    sync_header.flags.set(PtpFlags::TWO_STEP);
    let sync_msg = PtpMessage::Sync {
        header: sync_header,
        origin_timestamp: sync_approx_ts,
    };

    // Serialize and parse the Sync message.
    let sync_bytes = sync_msg.serialize();
    let parsed_sync = PtpMessage::parse(&sync_bytes).unwrap();
    match &parsed_sync {
        PtpMessage::Sync { header, .. } => {
            assert_eq!(header.message_type, MessageType::Sync);
            assert_eq!(header.sequence_id, 100);
            assert!(header.flags.has(PtpFlags::TWO_STEP));
        }
        _ => panic!("expected Sync"),
    }

    // T2: slave receive timestamp for the Sync.
    let t2 = PtpTimestamp::new(1_000_000, 1_500_000); // 1.5ms after master sent

    // 2. Master sends FollowUp with precise T1.
    let t1_precise = PtpTimestamp::new(1_000_000, 100_000); // precise departure time
    let follow_up_header = PtpHeader::new(MessageType::FollowUp, 0, master_port(), 100);
    let follow_up_msg = PtpMessage::FollowUp {
        header: follow_up_header,
        precise_origin_timestamp: t1_precise,
    };

    let fu_bytes = follow_up_msg.serialize();
    let parsed_fu = PtpMessage::parse(&fu_bytes).unwrap();
    match &parsed_fu {
        PtpMessage::FollowUp {
            header,
            precise_origin_timestamp,
        } => {
            assert_eq!(header.message_type, MessageType::FollowUp);
            assert_eq!(header.sequence_id, 100);
            assert_eq!(*precise_origin_timestamp, t1_precise);
        }
        _ => panic!("expected FollowUp"),
    }

    // 3. Slave sends Delay_Req.
    let t3 = PtpTimestamp::new(1_000_000, 2_000_000); // slave sends at 2ms
    let delay_req_header = PtpHeader::new(MessageType::DelayReq, 0, slave_port(), 50);
    let delay_req_msg = PtpMessage::DelayReq {
        header: delay_req_header,
        origin_timestamp: t3,
    };

    let dr_bytes = delay_req_msg.serialize();
    let parsed_dr = PtpMessage::parse(&dr_bytes).unwrap();
    match &parsed_dr {
        PtpMessage::DelayReq {
            header,
            origin_timestamp,
        } => {
            assert_eq!(header.message_type, MessageType::DelayReq);
            assert_eq!(*origin_timestamp, t3);
        }
        _ => panic!("expected DelayReq"),
    }

    // 4. Master responds with Delay_Resp.
    let t4 = PtpTimestamp::new(1_000_000, 3_500_000); // master receives at 3.5ms
    let delay_resp_header = PtpHeader::new(MessageType::DelayResp, 0, master_port(), 50);
    let delay_resp_msg = PtpMessage::DelayResp {
        header: delay_resp_header,
        receive_timestamp: t4,
        requesting_port: slave_port(),
    };

    let dresp_bytes = delay_resp_msg.serialize();
    let parsed_dresp = PtpMessage::parse(&dresp_bytes).unwrap();
    match &parsed_dresp {
        PtpMessage::DelayResp {
            header,
            receive_timestamp,
            requesting_port,
        } => {
            assert_eq!(header.message_type, MessageType::DelayResp);
            assert_eq!(*receive_timestamp, t4);
            assert_eq!(*requesting_port, slave_port());
        }
        _ => panic!("expected DelayResp"),
    }

    // 5. Compute E2E delay and offset.
    // T1 = 1_000_000.000_100_000 (master Sync departure)
    // T2 = 1_000_000.001_500_000 (slave Sync arrival)
    // T3 = 1_000_000.002_000_000 (slave DelayReq departure)
    // T4 = 1_000_000.003_500_000 (master DelayReq arrival)
    //
    // forward = T2 - T1 = 1.4ms
    // reverse = T4 - T3 = 1.5ms
    // offset = (forward - reverse) / 2 = (1.4 - 1.5) / 2 = -0.05ms = -50us
    // delay  = (forward + reverse) / 2 = (1.4 + 1.5) / 2 = 1.45ms
    let (offset, delay) = compute_e2e(t1_precise, t2, t3, t4);

    let offset_us = offset.to_nanos() as f64 / 1000.0;
    let delay_us = delay.to_nanos() as f64 / 1000.0;

    assert!(
        (offset_us - (-50.0)).abs() < 1.0,
        "expected ~-50us offset, got {:.1}us",
        offset_us
    );
    assert!(
        (delay_us - 1450.0).abs() < 1.0,
        "expected ~1450us delay, got {:.1}us",
        delay_us
    );
}

#[test]
fn e2e_state_tracker_full_cycle() {
    let mut state = E2eDelayState::new();
    assert!(!state.is_complete());

    // Symmetric path: 1ms delay each way, zero offset.
    let t1 = PtpTimestamp::new(100, 0);
    let t2 = PtpTimestamp::new(100, 1_000_000);
    let t3 = PtpTimestamp::new(100, 2_000_000);
    let t4 = PtpTimestamp::new(100, 3_000_000);

    state.set_sync_departure(t1);
    assert!(!state.is_complete());

    state.set_sync_arrival(t2);
    assert!(!state.is_complete());

    state.set_delay_req_departure(t3);
    assert!(!state.is_complete());

    state.set_delay_resp_arrival(t4);
    assert!(state.is_complete());

    let (offset, delay) = state.compute().expect("should compute");

    assert!(
        offset.to_nanos().abs() < 10,
        "expected ~0 offset, got {} ns",
        offset.to_nanos()
    );
    assert!(
        (delay.to_nanos() - 1_000_000).abs() < 10,
        "expected ~1ms delay, got {} ns",
        delay.to_nanos()
    );

    // Reset and verify clean state.
    state.reset();
    assert!(!state.is_complete());
    assert!(state.compute().is_none());
}

#[test]
fn ptp_message_serialize_parse_all_types() {
    // Verify all supported message types survive serialization roundtrip.
    let source = master_port();

    // Sync
    let sync = PtpMessage::Sync {
        header: PtpHeader::new(MessageType::Sync, 0, source, 1),
        origin_timestamp: PtpTimestamp::new(1000, 500_000),
    };
    let parsed = PtpMessage::parse(&sync.serialize()).unwrap();
    assert!(matches!(parsed, PtpMessage::Sync { .. }));

    // FollowUp
    let fu = PtpMessage::FollowUp {
        header: PtpHeader::new(MessageType::FollowUp, 0, source, 2),
        precise_origin_timestamp: PtpTimestamp::new(2000, 0),
    };
    let parsed = PtpMessage::parse(&fu.serialize()).unwrap();
    assert!(matches!(parsed, PtpMessage::FollowUp { .. }));

    // DelayReq
    let dreq = PtpMessage::DelayReq {
        header: PtpHeader::new(MessageType::DelayReq, 0, source, 3),
        origin_timestamp: PtpTimestamp::new(3000, 999_999_999),
    };
    let parsed = PtpMessage::parse(&dreq.serialize()).unwrap();
    assert!(matches!(parsed, PtpMessage::DelayReq { .. }));

    // DelayResp
    let dresp = PtpMessage::DelayResp {
        header: PtpHeader::new(MessageType::DelayResp, 0, source, 4),
        receive_timestamp: PtpTimestamp::new(4000, 0),
        requesting_port: slave_port(),
    };
    let parsed = PtpMessage::parse(&dresp.serialize()).unwrap();
    match &parsed {
        PtpMessage::DelayResp {
            requesting_port, ..
        } => {
            assert_eq!(*requesting_port, slave_port());
        }
        _ => panic!("expected DelayResp"),
    }

    // Announce
    let announce = PtpMessage::Announce {
        header: PtpHeader::new(MessageType::Announce, 0, source, 5),
        announce: AnnounceBody {
            origin_timestamp: PtpTimestamp::ZERO,
            current_utc_offset: 37,
            grandmaster_priority1: 128,
            grandmaster_clock_quality: ClockQuality {
                clock_class: 6,
                clock_accuracy: 0x21,
                offset_scaled_log_variance: 0x4E5D,
            },
            grandmaster_priority2: 128,
            grandmaster_identity: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            steps_removed: 0,
            time_source: 0x20,
        },
    };
    let parsed = PtpMessage::parse(&announce.serialize()).unwrap();
    match &parsed {
        PtpMessage::Announce { announce: body, .. } => {
            assert_eq!(body.current_utc_offset, 37);
            assert_eq!(body.grandmaster_priority1, 128);
            assert_eq!(body.time_source, 0x20);
        }
        _ => panic!("expected Announce"),
    }
}

fn make_announce(
    priority1: u8,
    clock_class: u8,
    clock_accuracy: u8,
    variance: u16,
    priority2: u8,
    identity: [u8; 8],
) -> AnnounceBody {
    AnnounceBody {
        origin_timestamp: PtpTimestamp::ZERO,
        current_utc_offset: 37,
        grandmaster_priority1: priority1,
        grandmaster_clock_quality: ClockQuality {
            clock_class,
            clock_accuracy,
            offset_scaled_log_variance: variance,
        },
        grandmaster_priority2: priority2,
        grandmaster_identity: identity,
        steps_removed: 0,
        time_source: 0x20,
    }
}

#[test]
fn bmca_selects_best_gps_clock() {
    // GPS clock (class 6) vs. two internal oscillators (class 248).
    let gps = make_announce(128, 6, 0x21, 0x4E5D, 128, [0x01; 8]);
    let osc1 = make_announce(128, 248, 0xFE, 0xFFFF, 128, [0x02; 8]);
    let osc2 = make_announce(128, 248, 0xFE, 0xFFFF, 128, [0x03; 8]);

    assert_eq!(compare_announce(&gps, &osc1), BmcaResult::ThisBetter);
    assert_eq!(compare_announce(&gps, &osc2), BmcaResult::ThisBetter);
    assert_eq!(compare_announce(&osc1, &gps), BmcaResult::OtherBetter);

    let announces = vec![osc1, gps.clone(), osc2];
    let best = select_best_master(&announces).expect("should find best");
    assert_eq!(best, 1, "GPS clock at index 1 should be best");
}

#[test]
fn bmca_priority1_overrides_clock_quality() {
    // A worse clock with better priority1 should win.
    let high_priority = make_announce(50, 248, 0xFE, 0xFFFF, 128, [0x01; 8]);
    let good_quality = make_announce(128, 6, 0x21, 0x4E5D, 128, [0x02; 8]);

    assert_eq!(
        compare_announce(&high_priority, &good_quality),
        BmcaResult::ThisBetter
    );
}

#[test]
fn bmca_identity_breaks_ties() {
    // Two identical clocks -- lower identity wins.
    let lower = make_announce(128, 6, 0x21, 0x4E5D, 128, [0, 0, 0, 0, 0, 0, 0, 1]);
    let higher = make_announce(128, 6, 0x21, 0x4E5D, 128, [0, 0, 0, 0, 0, 0, 0, 2]);

    assert_eq!(compare_announce(&lower, &higher), BmcaResult::ThisBetter);
    assert_eq!(compare_announce(&higher, &lower), BmcaResult::OtherBetter);
}

#[test]
fn bmca_equal_clocks() {
    let a = make_announce(128, 6, 0x21, 0x4E5D, 128, [0x42; 8]);
    let b = make_announce(128, 6, 0x21, 0x4E5D, 128, [0x42; 8]);
    assert_eq!(compare_announce(&a, &b), BmcaResult::Equal);
}

#[test]
fn bmca_select_from_five_candidates() {
    let announces = vec![
        make_announce(200, 248, 0xFE, 0xFFFF, 128, [0x05; 8]),
        make_announce(128, 248, 0xFE, 0xFFFF, 128, [0x04; 8]),
        make_announce(128, 6, 0x21, 0x4E5D, 128, [0x03; 8]), // best: good quality, lower identity
        make_announce(128, 6, 0x21, 0x4E5D, 128, [0x04; 8]),
        make_announce(100, 248, 0xFE, 0xFFFF, 128, [0x01; 8]), // priority1=100, but class=248
    ];

    let best = select_best_master(&announces).expect("should find best");
    // Index 4 has priority1=100 which beats everyone else's priority1.
    assert_eq!(
        best, 4,
        "clock with priority1=100 should win despite worse class"
    );
}

#[test]
fn ptp_header_preservation() {
    // Verify header fields survive serialization.
    let mut hdr = PtpHeader::new(MessageType::Sync, 42, master_port(), 1234);
    hdr.correction_field = -123_456_789;
    hdr.flags.set(PtpFlags::TWO_STEP);
    hdr.flags.set(PtpFlags::PTP_TIMESCALE);
    hdr.log_message_interval = -4;

    let msg = PtpMessage::Sync {
        header: hdr,
        origin_timestamp: PtpTimestamp::new(999, 888),
    };

    let bytes = msg.serialize();
    let parsed = PtpMessage::parse(&bytes).unwrap();

    let parsed_hdr = parsed.header();
    assert_eq!(parsed_hdr.domain_number, 42);
    assert_eq!(parsed_hdr.sequence_id, 1234);
    assert_eq!(parsed_hdr.correction_field, -123_456_789);
    assert!(parsed_hdr.flags.has(PtpFlags::TWO_STEP));
    assert!(parsed_hdr.flags.has(PtpFlags::PTP_TIMESCALE));
    assert_eq!(parsed_hdr.log_message_interval, -4);
    assert_eq!(parsed_hdr.source_port_identity, master_port());
}

#[test]
fn e2e_delay_with_asymmetric_path() {
    // Forward delay = 2ms, reverse delay = 1ms, slave offset = +500us.
    // T1 = 100.000_000_000
    // T2 = T1 + forward_delay + offset = 100.000 + 0.002 + 0.0005 = 100.002_500_000
    // T3 = T2 + gap = 100.003_500_000 (1ms gap)
    // T4 = T3 - offset + reverse_delay = 100.0035 - 0.0005 + 0.001 = 100.004_000_000
    let t1 = PtpTimestamp::new(100, 0);
    let t2 = PtpTimestamp::new(100, 2_500_000);
    let t3 = PtpTimestamp::new(100, 3_500_000);
    let t4 = PtpTimestamp::new(100, 4_000_000);

    let (offset, delay) = compute_e2e(t1, t2, t3, t4);

    // With asymmetric path: reported offset includes asymmetry error.
    // forward = T2-T1 = 2.5ms, reverse = T4-T3 = 0.5ms
    // offset = (2.5 - 0.5)/2 = 1.0ms (includes both real offset and asymmetry)
    // delay  = (2.5 + 0.5)/2 = 1.5ms
    let offset_us = offset.to_nanos() as f64 / 1000.0;
    let delay_us = delay.to_nanos() as f64 / 1000.0;

    assert!(
        (offset_us - 1000.0).abs() < 1.0,
        "expected ~1000us offset, got {:.1}us",
        offset_us
    );
    assert!(
        (delay_us - 1500.0).abs() < 1.0,
        "expected ~1500us delay, got {:.1}us",
        delay_us
    );
}
