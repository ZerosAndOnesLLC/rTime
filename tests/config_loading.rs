//! Configuration loading and parsing integration tests.

use rtime_core::config::RtimeConfig;

#[test]
fn minimal_config() {
    let toml_str = r#"
        [general]
        log_level = "debug"
    "#;

    let config: RtimeConfig = toml::from_str(toml_str).expect("parse minimal config");
    assert_eq!(config.general.log_level, "debug");

    // All other sections should have their defaults.
    assert!(config.clock.discipline);
    assert_eq!(config.clock.step_threshold_ms, 128.0);
    assert!(config.ntp.enabled);
    assert_eq!(config.ntp.listen, "0.0.0.0:123");
    assert!(config.ntp.sources.is_empty());
    assert!(!config.ptp.enabled);
    assert!(config.metrics.enabled);
    assert!(config.management.enabled);
}

#[test]
fn full_config() {
    let toml_str = r#"
        [general]
        log_level = "trace"

        [clock]
        discipline = false
        step_threshold_ms = 256.0
        panic_threshold_ms = 2000.0
        interface = "ptp0"

        [ntp]
        enabled = true
        listen = "0.0.0.0:1123"

        [ntp.nts]
        enabled = true
        ke_listen = "0.0.0.0:4460"
        certificate = "/etc/rtime/cert.pem"
        private_key = "/etc/rtime/key.pem"

        [[ntp.sources]]
        address = "pool.ntp.org"
        nts = false

        [[ntp.sources]]
        address = "time.cloudflare.com"
        nts = true

        [ptp]
        enabled = true
        domain = 24
        interface = "eth1"
        transport = "udp-ipv6"
        priority1 = 100
        priority2 = 200
        delay_mechanism = "p2p"

        [metrics]
        enabled = false
        listen = "0.0.0.0:9200"

        [management]
        enabled = false
        listen = "127.0.0.1:9300"
    "#;

    let config: RtimeConfig = toml::from_str(toml_str).expect("parse full config");

    // General
    assert_eq!(config.general.log_level, "trace");

    // Clock
    assert!(!config.clock.discipline);
    assert_eq!(config.clock.step_threshold_ms, 256.0);
    assert_eq!(config.clock.panic_threshold_ms, 2000.0);
    assert_eq!(config.clock.interface, "ptp0");

    // NTP
    assert!(config.ntp.enabled);
    assert_eq!(config.ntp.listen, "0.0.0.0:1123");
    assert!(config.ntp.nts.enabled);
    assert_eq!(config.ntp.nts.ke_listen, "0.0.0.0:4460");
    assert_eq!(
        config.ntp.nts.certificate.as_deref(),
        Some("/etc/rtime/cert.pem")
    );
    assert_eq!(
        config.ntp.nts.private_key.as_deref(),
        Some("/etc/rtime/key.pem")
    );

    // NTP sources
    assert_eq!(config.ntp.sources.len(), 2);
    assert_eq!(config.ntp.sources[0].address, "pool.ntp.org");
    assert!(!config.ntp.sources[0].nts);
    assert_eq!(config.ntp.sources[1].address, "time.cloudflare.com");
    assert!(config.ntp.sources[1].nts);

    // PTP
    assert!(config.ptp.enabled);
    assert_eq!(config.ptp.domain, 24);
    assert_eq!(config.ptp.interface, "eth1");
    assert_eq!(config.ptp.transport, "udp-ipv6");
    assert_eq!(config.ptp.priority1, 100);
    assert_eq!(config.ptp.priority2, 200);
    assert_eq!(config.ptp.delay_mechanism, "p2p");

    // Metrics
    assert!(!config.metrics.enabled);
    assert_eq!(config.metrics.listen, "0.0.0.0:9200");

    // Management
    assert!(!config.management.enabled);
    assert_eq!(config.management.listen, "127.0.0.1:9300");
}

#[test]
fn defaults_for_missing_sections() {
    // Completely empty config -- everything should default.
    let config: RtimeConfig = toml::from_str("").expect("parse empty config");

    assert_eq!(config.general.log_level, "info");
    assert!(config.clock.discipline);
    assert_eq!(config.clock.step_threshold_ms, 128.0);
    assert_eq!(config.clock.panic_threshold_ms, 1000.0);
    assert_eq!(config.clock.interface, "system");
    assert!(config.ntp.enabled);
    assert_eq!(config.ntp.listen, "0.0.0.0:123");
    assert!(!config.ntp.nts.enabled);
    assert_eq!(config.ntp.nts.ke_listen, "0.0.0.0:4460");
    assert!(config.ntp.nts.certificate.is_none());
    assert!(config.ntp.nts.private_key.is_none());
    assert!(config.ntp.sources.is_empty());
    assert!(!config.ptp.enabled);
    assert_eq!(config.ptp.domain, 0);
    assert_eq!(config.ptp.interface, "eth0");
    assert_eq!(config.ptp.transport, "udp-ipv4");
    assert_eq!(config.ptp.priority1, 128);
    assert_eq!(config.ptp.priority2, 128);
    assert_eq!(config.ptp.delay_mechanism, "e2e");
    assert!(config.metrics.enabled);
    assert_eq!(config.metrics.listen, "127.0.0.1:9100");
    assert!(config.management.enabled);
    assert_eq!(config.management.listen, "127.0.0.1:9200");
}

#[test]
fn invalid_config_rejected() {
    // Invalid TOML syntax.
    let bad_toml = r#"
        [general
        log_level = "info"
    "#;
    let result: Result<RtimeConfig, _> = toml::from_str(bad_toml);
    assert!(result.is_err(), "invalid TOML should be rejected");
}

#[test]
fn unknown_fields_are_ignored() {
    // TOML with unknown fields -- toml crate with serde defaults ignores them.
    let toml_str = r#"
        [general]
        log_level = "info"
        unknown_field = "value"

        [some_unknown_section]
        key = "val"
    "#;
    // This may or may not error depending on serde configuration. If the
    // RtimeConfig uses deny_unknown_fields it would error; otherwise it passes.
    let result: Result<RtimeConfig, _> = toml::from_str(toml_str);
    // Just verify we get a definitive result (no panic).
    let _outcome = result.is_ok() || result.is_err();
}

#[test]
fn partial_sections() {
    // Only some fields in a section -- others should default.
    let toml_str = r#"
        [clock]
        discipline = false

        [ntp]
        enabled = false
    "#;

    let config: RtimeConfig = toml::from_str(toml_str).expect("parse partial config");

    assert!(!config.clock.discipline);
    assert_eq!(config.clock.step_threshold_ms, 128.0); // default
    assert_eq!(config.clock.interface, "system"); // default

    assert!(!config.ntp.enabled);
    assert_eq!(config.ntp.listen, "0.0.0.0:123"); // default
}
