use crate::RefClockError;
use rtime_core::clock::LeapIndicator;
use rtime_core::source::{SourceId, SourceMeasurement};
use rtime_core::timestamp::{NtpDuration, NtpTimestamp};

/// GPS time fix extracted from NMEA sentences.
#[derive(Debug, Clone)]
pub struct GpsFix {
    /// UTC hours from GPS.
    pub hours: u8,
    /// UTC minutes from GPS.
    pub minutes: u8,
    /// UTC seconds from GPS.
    pub seconds: u8,
    /// Sub-second milliseconds from GPS.
    pub subsec_ms: u16,
    /// Day of month.
    pub day: u8,
    /// Month (1-12).
    pub month: u8,
    /// Full year (e.g. 2026).
    pub year: u16,
    /// Whether the fix is valid.
    pub valid: bool,
}

impl GpsFix {
    /// Convert this GPS fix to an NTP timestamp.
    ///
    /// Returns `None` if the fix is not valid.
    pub fn to_ntp_timestamp(&self) -> Option<NtpTimestamp> {
        if !self.valid {
            return None;
        }

        // Compute days from NTP epoch (1900-01-01) to this date.
        let days = days_from_ntp_epoch(self.year, self.month, self.day)?;

        let seconds_in_day =
            self.hours as u64 * 3600 + self.minutes as u64 * 60 + self.seconds as u64;
        let total_seconds = days * 86400 + seconds_in_day;

        // NTP timestamp: upper 32 bits = seconds since 1900-01-01
        let ntp_seconds = total_seconds as u32; // wraps at 2036, same as NTP era 0
        let fraction = (self.subsec_ms as u64 * (1u64 << 32)) / 1000;

        Some(NtpTimestamp::new(ntp_seconds, fraction as u32))
    }
}

/// Compute number of days from NTP epoch (1900-01-01) to a given date.
fn days_from_ntp_epoch(year: u16, month: u8, day: u8) -> Option<u64> {
    if month < 1 || month > 12 || day < 1 || day > 31 || year < 1900 {
        return None;
    }

    let mut total_days: u64 = 0;

    // Add days for full years from 1900 to year-1.
    for y in 1900..year {
        total_days += if is_leap_year(y) { 366 } else { 365 };
    }

    // Add days for full months in the current year.
    let days_in_months: [u8; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 1..month {
        let mut d = days_in_months[(m - 1) as usize] as u64;
        if m == 2 && is_leap_year(year) {
            d = 29;
        }
        total_days += d;
    }

    total_days += (day - 1) as u64;

    Some(total_days)
}

fn is_leap_year(y: u16) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}

/// Validate NMEA checksum.
///
/// The checksum is the XOR of all bytes between `$` and `*`, compared against the
/// two hex digits after `*`.
fn validate_checksum(sentence: &str) -> bool {
    let sentence = sentence.trim();

    // Find the '$' start and '*' before checksum.
    let start = match sentence.find('$') {
        Some(i) => i + 1,
        None => return false,
    };
    let star = match sentence.find('*') {
        Some(i) => i,
        None => return false,
    };

    if star <= start || star + 3 > sentence.len() {
        return false;
    }

    let payload = &sentence[start..star];
    let expected_hex = &sentence[star + 1..star + 3];

    let computed: u8 = payload.bytes().fold(0u8, |acc, b| acc ^ b);

    let Ok(expected) = u8::from_str_radix(expected_hex, 16) else {
        return false;
    };

    computed == expected
}

/// Parse a $GPRMC sentence (Recommended Minimum Navigation Information).
///
/// Format: `$GPRMC,hhmmss.ss,A,lat,N,lon,W,speed,course,ddmmyy,magvar,E*checksum`
pub fn parse_gprmc(sentence: &str) -> Result<GpsFix, RefClockError> {
    if !validate_checksum(sentence) {
        return Err(RefClockError::ParseError(
            "GPRMC checksum mismatch".to_string(),
        ));
    }

    // Strip checksum portion for field parsing.
    let data = sentence
        .trim()
        .strip_prefix('$')
        .unwrap_or(sentence.trim());
    let data = data.split('*').next().unwrap_or(data);

    let fields: Vec<&str> = data.split(',').collect();
    if fields.len() < 10 {
        return Err(RefClockError::ParseError(format!(
            "GPRMC: expected at least 10 fields, got {}",
            fields.len()
        )));
    }

    // fields[0] = "GPRMC"
    // fields[1] = time "hhmmss.ss"
    // fields[2] = status "A"=active "V"=void
    // fields[9] = date "ddmmyy"

    let (hours, minutes, seconds, subsec_ms) = parse_nmea_time(fields[1])?;
    let valid = fields[2] == "A";
    let (day, month, year) = parse_rmc_date(fields[9])?;

    Ok(GpsFix {
        hours,
        minutes,
        seconds,
        subsec_ms,
        day,
        month,
        year,
        valid,
    })
}

/// Parse a $GPZDA sentence (Time & Date).
///
/// Format: `$GPZDA,hhmmss.ss,dd,mm,yyyy,tzh,tzm*checksum`
pub fn parse_gpzda(sentence: &str) -> Result<GpsFix, RefClockError> {
    if !validate_checksum(sentence) {
        return Err(RefClockError::ParseError(
            "GPZDA checksum mismatch".to_string(),
        ));
    }

    let data = sentence
        .trim()
        .strip_prefix('$')
        .unwrap_or(sentence.trim());
    let data = data.split('*').next().unwrap_or(data);

    let fields: Vec<&str> = data.split(',').collect();
    if fields.len() < 5 {
        return Err(RefClockError::ParseError(format!(
            "GPZDA: expected at least 5 fields, got {}",
            fields.len()
        )));
    }

    // fields[0] = "GPZDA"
    // fields[1] = time "hhmmss.ss"
    // fields[2] = day "dd"
    // fields[3] = month "mm"
    // fields[4] = year "yyyy"

    let (hours, minutes, seconds, subsec_ms) = parse_nmea_time(fields[1])?;

    let day: u8 = fields[2]
        .parse()
        .map_err(|_| RefClockError::ParseError(format!("GPZDA: invalid day '{}'", fields[2])))?;
    let month: u8 = fields[3]
        .parse()
        .map_err(|_| RefClockError::ParseError(format!("GPZDA: invalid month '{}'", fields[3])))?;
    let year: u16 = fields[4]
        .parse()
        .map_err(|_| RefClockError::ParseError(format!("GPZDA: invalid year '{}'", fields[4])))?;

    Ok(GpsFix {
        hours,
        minutes,
        seconds,
        subsec_ms,
        day,
        month,
        year,
        valid: true, // ZDA has no status field; presence implies valid time.
    })
}

/// Parse NMEA time field "hhmmss.ss" into (hours, minutes, seconds, subsec_ms).
fn parse_nmea_time(field: &str) -> Result<(u8, u8, u8, u16), RefClockError> {
    if field.len() < 6 {
        return Err(RefClockError::ParseError(format!(
            "NMEA time too short: '{field}'"
        )));
    }

    let hours: u8 = field[0..2]
        .parse()
        .map_err(|_| RefClockError::ParseError(format!("invalid hours in '{field}'")))?;
    let minutes: u8 = field[2..4]
        .parse()
        .map_err(|_| RefClockError::ParseError(format!("invalid minutes in '{field}'")))?;

    // Seconds may have a decimal portion.
    let sec_str = &field[4..];
    let (sec_whole, subsec_ms) = if let Some(dot_pos) = sec_str.find('.') {
        let whole: u8 = sec_str[..dot_pos]
            .parse()
            .map_err(|_| RefClockError::ParseError(format!("invalid seconds in '{field}'")))?;
        let frac_str = &sec_str[dot_pos + 1..];
        // Normalize to milliseconds (pad or truncate to 3 digits).
        let ms: u16 = if frac_str.is_empty() {
            0
        } else {
            let padded = format!("{frac_str:0<3}");
            padded[..3]
                .parse()
                .map_err(|_| RefClockError::ParseError(format!("invalid subsec in '{field}'")))?
        };
        (whole, ms)
    } else {
        let whole: u8 = sec_str
            .parse()
            .map_err(|_| RefClockError::ParseError(format!("invalid seconds in '{field}'")))?;
        (whole, 0u16)
    };

    Ok((hours, minutes, sec_whole, subsec_ms))
}

/// Parse RMC date field "ddmmyy" into (day, month, year).
fn parse_rmc_date(field: &str) -> Result<(u8, u8, u16), RefClockError> {
    if field.len() < 6 {
        return Err(RefClockError::ParseError(format!(
            "RMC date too short: '{field}'"
        )));
    }

    let day: u8 = field[0..2]
        .parse()
        .map_err(|_| RefClockError::ParseError(format!("invalid day in date '{field}'")))?;
    let month: u8 = field[2..4]
        .parse()
        .map_err(|_| RefClockError::ParseError(format!("invalid month in date '{field}'")))?;
    let yy: u16 = field[4..6]
        .parse()
        .map_err(|_| RefClockError::ParseError(format!("invalid year in date '{field}'")))?;

    // Two-digit year: 80-99 -> 1980-1999, 00-79 -> 2000-2079
    let year = if yy >= 80 { 1900 + yy } else { 2000 + yy };

    Ok((day, month, year))
}

/// GPS reference clock driver.
///
/// Reads NMEA sentences from a serial device (e.g. `/dev/ttyUSB0`) and produces
/// [`SourceMeasurement`] values when a valid time fix is parsed.
pub struct GpsDriver {
    device: String,
    source_id: SourceId,
}

impl GpsDriver {
    /// Create a new GPS driver for the given serial device path.
    pub fn new(device: &str) -> Self {
        Self {
            device: device.to_string(),
            source_id: SourceId::RefClock {
                driver: "GPS".to_string(),
                unit: 0,
            },
        }
    }

    /// Return the device path.
    pub fn device(&self) -> &str {
        &self.device
    }

    /// Parse a line of NMEA data and return a measurement if valid.
    ///
    /// `recv_time` is the local clock timestamp when the serial data was received,
    /// used to compute the offset between GPS time and local time.
    pub fn process_line(&self, line: &str, recv_time: NtpTimestamp) -> Option<SourceMeasurement> {
        let trimmed = line.trim();

        let fix = if trimmed.starts_with("$GPRMC") || trimmed.starts_with("$GNRMC") {
            parse_gprmc(trimmed).ok()?
        } else if trimmed.starts_with("$GPZDA") || trimmed.starts_with("$GNZDA") {
            parse_gpzda(trimmed).ok()?
        } else {
            return None;
        };

        let gps_time = fix.to_ntp_timestamp()?;

        // Offset = GPS time - local receive time.
        let offset = NtpDuration::between(recv_time, gps_time);

        // GPS via serial has relatively high and variable latency.
        // Typical serial delay is ~50-100ms, but the second boundary from NMEA is
        // only accurate to roughly +/- a few milliseconds without PPS.
        let delay = NtpDuration::from_millis(50);
        let dispersion = NtpDuration::from_millis(10);

        Some(SourceMeasurement {
            id: self.source_id.clone(),
            offset,
            delay,
            dispersion,
            jitter: 0.005, // 5ms initial jitter estimate
            stratum: 1,    // GPS is a stratum-0 source, we report as stratum-1
            leap_indicator: LeapIndicator::NoWarning,
            root_delay: NtpDuration::ZERO,
            root_dispersion: NtpDuration::ZERO,
            time: recv_time,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to build a correctly checksummed NMEA sentence from a payload.
    fn make_nmea(payload: &str) -> String {
        let cksum: u8 = payload.bytes().fold(0u8, |acc, b| acc ^ b);
        format!("${payload}*{cksum:02X}")
    }

    #[test]
    fn test_validate_checksum_valid() {
        let sentence = make_nmea("GPRMC,123519.00,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W");
        assert!(validate_checksum(&sentence));
    }

    #[test]
    fn test_validate_checksum_invalid() {
        // Take a valid sentence and corrupt the checksum.
        let sentence = make_nmea("GPRMC,123519.00,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W");
        let corrupted = format!("{}FF", &sentence[..sentence.len() - 2]);
        assert!(!validate_checksum(&corrupted));
    }

    #[test]
    fn test_validate_checksum_no_star() {
        assert!(!validate_checksum("$GPRMC,123519.00,A"));
    }

    #[test]
    fn test_parse_gprmc() {
        let sentence = make_nmea("GPRMC,123519.00,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W");
        let fix = parse_gprmc(&sentence).unwrap();
        assert_eq!(fix.hours, 12);
        assert_eq!(fix.minutes, 35);
        assert_eq!(fix.seconds, 19);
        assert_eq!(fix.subsec_ms, 0);
        assert_eq!(fix.day, 23);
        assert_eq!(fix.month, 3);
        assert_eq!(fix.year, 1994);
        assert!(fix.valid);
    }

    #[test]
    fn test_parse_gprmc_void() {
        // Compute correct checksum for this void sentence.
        let payload = "GPRMC,123519.00,V,,,,,,,230394,,";
        let cksum: u8 = payload.bytes().fold(0u8, |acc, b| acc ^ b);
        let sentence = format!("${payload}*{cksum:02X}");
        let fix = parse_gprmc(&sentence).unwrap();
        assert!(!fix.valid);
    }

    #[test]
    fn test_parse_gpzda() {
        // Build a GPZDA with correct checksum.
        let payload = "GPZDA,082710.00,16,09,2026,00,00";
        let cksum: u8 = payload.bytes().fold(0u8, |acc, b| acc ^ b);
        let sentence = format!("${payload}*{cksum:02X}");
        let fix = parse_gpzda(&sentence).unwrap();
        assert_eq!(fix.hours, 8);
        assert_eq!(fix.minutes, 27);
        assert_eq!(fix.seconds, 10);
        assert_eq!(fix.subsec_ms, 0);
        assert_eq!(fix.day, 16);
        assert_eq!(fix.month, 9);
        assert_eq!(fix.year, 2026);
        assert!(fix.valid);
    }

    #[test]
    fn test_gps_fix_to_ntp_timestamp() {
        let fix = GpsFix {
            hours: 0,
            minutes: 0,
            seconds: 0,
            subsec_ms: 0,
            day: 1,
            month: 1,
            year: 1970,
            valid: true,
        };
        let ts = fix.to_ntp_timestamp().unwrap();
        // NTP epoch diff is 70 years from 1900 to 1970 = 2208988800 seconds.
        assert_eq!(ts.seconds(), 2_208_988_800u32);
        assert_eq!(ts.fraction(), 0);
    }

    #[test]
    fn test_gps_fix_to_ntp_timestamp_invalid() {
        let fix = GpsFix {
            hours: 0,
            minutes: 0,
            seconds: 0,
            subsec_ms: 0,
            day: 1,
            month: 1,
            year: 2024,
            valid: false,
        };
        assert!(fix.to_ntp_timestamp().is_none());
    }

    #[test]
    fn test_gps_fix_subsec() {
        let fix = GpsFix {
            hours: 12,
            minutes: 0,
            seconds: 0,
            subsec_ms: 500, // 0.5 seconds
            day: 1,
            month: 1,
            year: 2000,
            valid: true,
        };
        let ts = fix.to_ntp_timestamp().unwrap();
        // Fraction for 500ms = 0.5 * 2^32 = 2147483648
        assert_eq!(ts.fraction(), 2_147_483_648);
    }

    #[test]
    fn test_is_leap_year() {
        assert!(is_leap_year(2000)); // divisible by 400
        assert!(!is_leap_year(1900)); // divisible by 100 but not 400
        assert!(is_leap_year(2024)); // divisible by 4
        assert!(!is_leap_year(2023)); // not divisible by 4
    }

    #[test]
    fn test_days_from_ntp_epoch_unix_epoch() {
        // 1970-01-01 should be 25567 days from 1900-01-01.
        // 70 years: 17 leap years (1904..1968 inclusive) + 53 normal = 17*366 + 53*365
        // = 6222 + 19345 = 25567
        let days = days_from_ntp_epoch(1970, 1, 1).unwrap();
        assert_eq!(days, 25567);
    }

    #[test]
    fn test_parse_nmea_time_with_frac() {
        let (h, m, s, ms) = parse_nmea_time("123519.50").unwrap();
        assert_eq!(h, 12);
        assert_eq!(m, 35);
        assert_eq!(s, 19);
        assert_eq!(ms, 500);
    }

    #[test]
    fn test_parse_nmea_time_no_frac() {
        let (h, m, s, ms) = parse_nmea_time("000000").unwrap();
        assert_eq!(h, 0);
        assert_eq!(m, 0);
        assert_eq!(s, 0);
        assert_eq!(ms, 0);
    }

    #[test]
    fn test_parse_rmc_date() {
        let (d, m, y) = parse_rmc_date("230394").unwrap();
        assert_eq!(d, 23);
        assert_eq!(m, 3);
        assert_eq!(y, 1994);
    }

    #[test]
    fn test_parse_rmc_date_2000s() {
        let (d, m, y) = parse_rmc_date("010126").unwrap();
        assert_eq!(d, 1);
        assert_eq!(m, 1);
        assert_eq!(y, 2026);
    }

    #[test]
    fn test_gps_driver_process_line_rmc() {
        let driver = GpsDriver::new("/dev/ttyUSB0");
        let sentence = make_nmea("GPRMC,123519.00,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W");
        let recv_time = NtpTimestamp::now();
        let measurement = driver.process_line(&sentence, recv_time);
        assert!(measurement.is_some());
        let m = measurement.unwrap();
        assert_eq!(m.stratum, 1);
        assert_eq!(m.leap_indicator, LeapIndicator::NoWarning);
    }

    #[test]
    fn test_gps_driver_process_line_unknown() {
        let driver = GpsDriver::new("/dev/ttyUSB0");
        let measurement = driver.process_line("$GPGGA,123519,...", NtpTimestamp::now());
        assert!(measurement.is_none());
    }

    #[test]
    fn test_gps_driver_process_line_invalid_checksum() {
        let driver = GpsDriver::new("/dev/ttyUSB0");
        let good = make_nmea("GPRMC,123519.00,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W");
        let sentence = format!("{}FF", &good[..good.len() - 2]);
        let measurement = driver.process_line(&sentence, NtpTimestamp::now());
        assert!(measurement.is_none());
    }
}
