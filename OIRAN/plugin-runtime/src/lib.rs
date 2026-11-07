//! Stable in-process decoder contract. Protocol implementations remain separate crates.

use event_schema::{
    DecodeStatus, Endpoint, ExactTimestamp, NormalizedEvent, PacketReference, Protocol,
};

pub const PLUGIN_API_VERSION: &str = "1.1.0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecoderManifest {
    pub decoder_name: &'static str,
    pub decoder_version: &'static str,
    pub api_version: &'static str,
    pub protocol: Protocol,
    pub specification: &'static str,
    pub deterministic: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecoderCapabilities {
    pub message_families: &'static [&'static str],
    pub preserves_unknown_fields: bool,
    pub supports_extensions: bool,
    pub limitations: &'static [&'static str],
}
#[derive(Clone, Debug)]
pub struct DecoderInput<'a> {
    pub capture_id: &'a str,
    pub packet_references: &'a [PacketReference],
    pub timestamp: &'a ExactTimestamp,
    pub interface: &'a str,
    pub source_endpoint: Endpoint,
    pub destination_endpoint: Endpoint,
    pub payload: &'a [u8],
    pub raw_payload_reference: &'a str,
}
#[derive(Clone, Debug)]
pub struct DecoderOutput {
    pub status: DecodeStatus,
    pub events: Vec<NormalizedEvent>,
    pub errors: Vec<String>,
}

pub trait ProtocolDecoder: Send + Sync {
    fn manifest(&self) -> DecoderManifest;
    fn capabilities(&self) -> DecoderCapabilities;
    fn decode(&self, input: &DecoderInput<'_>) -> DecoderOutput;
}
pub fn validate_manifest(manifest: &DecoderManifest) -> Result<(), &'static str> {
    if manifest.api_version != PLUGIN_API_VERSION {
        return Err("incompatible plugin API");
    }
    if manifest.decoder_name.is_empty() || manifest.decoder_version.is_empty() {
        return Err("missing decoder identity");
    }
    if !manifest.deterministic {
        return Err("non-deterministic decoder rejected");
    }
    if manifest.specification.is_empty() {
        return Err("missing protocol specification");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_incompatible_plugin() {
        let m = DecoderManifest {
            decoder_name: "x",
            decoder_version: "0.1",
            api_version: "2",
            protocol: Protocol::Unknown,
            specification: "test",
            deterministic: true,
        };
        assert_eq!(validate_manifest(&m), Err("incompatible plugin API"));
    }
}
