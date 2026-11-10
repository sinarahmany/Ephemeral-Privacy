use crate::dns::sinkhole::is_tracker;
use simple_dns::rdata::RData;
use simple_dns::{Packet, PacketFlag, QTYPE, TYPE};

pub struct CnameCheckResult {
    pub is_cloaked_tracker: bool,
    pub original_domain: String,
    pub canonical_target: Option<String>,
    pub matched_tracker: Option<&'static str>,
}

/// Inspects a DNS response packet for CNAME cloaking.
/// If an answer maps to an ad/tracking broker via CNAME, flags it for sinkholing.
pub fn inspect_cname_response(packet_bytes: &[u8]) -> Option<CnameCheckResult> {
    let packet = Packet::parse(packet_bytes).ok()?;
    let original_domain = packet
        .questions
        .first()
        .map(|q| q.qname.to_string())
        .unwrap_or_default();

    for answer in &packet.answers {
        if let RData::CNAME(ref cname) = answer.rdata {
            let canonical_str = cname.0.to_string();
            let cleaned = canonical_str.trim_end_matches('.');
            if let Some(tracker) = is_tracker(cleaned) {
                return Some(CnameCheckResult {
                    is_cloaked_tracker: true,
                    original_domain,
                    canonical_target: Some(cleaned.to_string()),
                    matched_tracker: Some(tracker),
                });
            }
        }
    }

    None
}

/// Generates a synthesized NXDOMAIN response packet for blocked queries
pub fn build_nxdomain_response(query_packet_bytes: &[u8]) -> Option<Vec<u8>> {
    let mut packet = Packet::parse(query_packet_bytes).ok()?;
    packet.set_flags(PacketFlag::RESPONSE);
    packet.answers.clear();
    packet.additional_records.clear();
    packet.name_servers.clear();
    packet.build_bytes_vec_compressed().ok()
}

/// Generates a synthesized A-record response pointing to 0.0.0.0 (Sinkhole)
pub fn build_sinkhole_response(query_packet_bytes: &[u8]) -> Option<Vec<u8>> {
    let query = Packet::parse(query_packet_bytes).ok()?;
    let q = query.questions.first()?.clone();

    let mut response = query.into_reply();
    if q.qtype == QTYPE::TYPE(TYPE::A) {
        response.answers.push(simple_dns::ResourceRecord::new(
            q.qname,
            simple_dns::CLASS::IN,
            300,
            simple_dns::rdata::RData::A(simple_dns::rdata::A { address: 0 }),
        ));
    }
    response.build_bytes_vec_compressed().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use simple_dns::{Name, ResourceRecord, CLASS};

    #[test]
    fn test_cname_tracker_uncloaking() {
        let mut response = Packet::new_reply(1234);
        let tracker_alias = Name::new("adservice.google.com").unwrap();
        response.answers.push(ResourceRecord::new(
            Name::new("news.com").unwrap(),
            CLASS::IN,
            300,
            RData::CNAME(simple_dns::rdata::CNAME(tracker_alias)),
        ));

        let bytes = response.build_bytes_vec_compressed().unwrap();
        let result = inspect_cname_response(&bytes);
        assert!(result.is_some());
        let uncloaked = result.unwrap();
        assert!(uncloaked.is_cloaked_tracker);
        assert_eq!(uncloaked.canonical_target.as_deref(), Some("adservice.google.com"));
    }
}

