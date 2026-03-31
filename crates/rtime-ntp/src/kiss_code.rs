/// Kiss-o'-Death (KoD) codes per RFC 5905 Section 7.4.
///
/// When stratum == 0, the reference_id field contains a KoD code
/// indicating the server's reason for rejecting the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KissCode {
    /// The association belongs to a anycast server.
    Acst,
    /// Server authentication failed.
    Auth,
    /// Autokey sequence failed.
    Auto,
    /// Server broadcast failed.
    Bcst,
    /// Cryptographic authentication or identification failed.
    Cryp,
    /// Access denied by remote server.
    Deny,
    /// Lost peer in symmetric mode.
    Drop,
    /// Access denied due to local policy.
    Rstr,
    /// The association has not yet synchronized for the first time.
    Init,
    /// The association belongs to a manycast server.
    Mcst,
    /// No key found.
    Nkey,
    /// Rate exceeded. Server will temporarily deny access.
    Rate,
    /// Somebody is tinkering with the association from a remote host.
    Rmot,
    /// A step change in system time has occurred, but association has not resynchronized.
    Step,
    /// Unknown/unrecognized code.
    Unknown([u8; 4]),
}

impl KissCode {
    /// Parse a KoD code from the 4-byte reference ID.
    pub fn from_reference_id(id: u32) -> Self {
        let bytes = id.to_be_bytes();
        match &bytes {
            b"ACST" => Self::Acst,
            b"AUTH" => Self::Auth,
            b"AUTO" => Self::Auto,
            b"BCST" => Self::Bcst,
            b"CRYP" => Self::Cryp,
            b"DENY" => Self::Deny,
            b"DROP" => Self::Drop,
            b"RSTR" => Self::Rstr,
            b"INIT" => Self::Init,
            b"MCST" => Self::Mcst,
            b"NKEY" => Self::Nkey,
            b"RATE" => Self::Rate,
            b"RMOT" => Self::Rmot,
            b"STEP" => Self::Step,
            _ => Self::Unknown(bytes),
        }
    }

    /// Whether the client should stop querying this server.
    pub fn is_fatal(&self) -> bool {
        matches!(self, Self::Deny | Self::Rstr)
    }

    /// Whether the client should reduce its polling rate.
    pub fn should_back_off(&self) -> bool {
        matches!(self, Self::Rate)
    }
}
