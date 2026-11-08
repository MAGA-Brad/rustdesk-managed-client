//! Just enough DNS wire format (RFC 1035) to ask a DoH resolver (RFC 8484) for a host's
//! HTTPS record (RFC 9460) and pull the `ech` SvcParam out of the answer.
use hbb_common::log;

const TYPE_HTTPS: u16 = 65;
const CLASS_IN: u16 = 1;
const FLAG_RD: u16 = 0x0100;
const FLAG_QR: u16 = 0x8000;
const RCODE_MASK: u16 = 0x000f;
const SVC_PARAM_ECH: u16 = 5;

pub fn build_query(host: &str, id: u16) -> Option<Vec<u8>> {
    let name = host.strip_suffix('.').unwrap_or(host);
    if name.is_empty() || name.len() > 253 {
        return None;
    }
    let mut msg = Vec::with_capacity(18 + name.len());
    msg.extend_from_slice(&id.to_be_bytes());
    msg.extend_from_slice(&FLAG_RD.to_be_bytes());
    msg.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        let len = u8::try_from(label.len())
            .ok()
            .filter(|len| (1..=63).contains(len))?;
        msg.push(len);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0);
    msg.extend_from_slice(&TYPE_HTTPS.to_be_bytes());
    msg.extend_from_slice(&CLASS_IN.to_be_bytes());
    Some(msg)
}

/// Returns the ECHConfigList carried by the first ServiceMode HTTPS record in the answer.
pub fn parse_ech_config_list(msg: &[u8], id: u16) -> Option<Vec<u8>> {
    let mut r = Reader::new(msg);
    let resp_id = r.u16()?;
    let flags = r.u16()?;
    let qdcount = r.u16()?;
    let ancount = r.u16()?;
    r.take(4)?;
    if resp_id != id || flags & FLAG_QR == 0 || flags & RCODE_MASK != 0 {
        log::warn!("unusable DNS response: id {resp_id:#06x}, flags {flags:#06x}");
        return None;
    }
    for _ in 0..qdcount {
        r.skip_name()?;
        r.take(4)?;
    }
    for _ in 0..ancount {
        r.skip_name()?;
        let rtype = r.u16()?;
        let class = r.u16()?;
        r.take(4)?;
        let rdlen = r.u16()?;
        let rdata = r.take(usize::from(rdlen))?;
        if rtype == TYPE_HTTPS && class == CLASS_IN {
            if let Some(ech) = svcb_ech(rdata) {
                return Some(ech);
            }
        }
    }
    None
}

fn svcb_ech(rdata: &[u8]) -> Option<Vec<u8>> {
    let mut r = Reader::new(rdata);
    // SvcPriority 0 is AliasMode, which carries no SvcParams.
    if r.u16()? == 0 {
        return None;
    }
    r.skip_name()?;
    while !r.is_empty() {
        let key = r.u16()?;
        let len = r.u16()?;
        let value = r.take(usize::from(len))?;
        if key == SVC_PARAM_ECH {
            return Some(value.to_vec());
        }
    }
    None
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let out = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(out)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }

    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.take(2)?.try_into().ok()?))
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    // Names are only skipped, so a compression pointer just ends the name.
    fn skip_name(&mut self) -> Option<()> {
        loop {
            let len = self.u8()?;
            match len & 0xc0 {
                0x00 if len == 0 => return Some(()),
                0x00 => {
                    self.take(usize::from(len))?;
                }
                0xc0 => {
                    self.u8()?;
                    return Some(());
                }
                _ => return None,
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    // A DoH answer for client.example.com HTTPS as a CDN that publishes ECH returns it (alpn,
    // address hints, its shared ECH config); the address hints are documentation addresses.
    pub(crate) const FIXTURE_ID: u16 = 0xabcd;
    pub(crate) const FIXTURE: &[u8] = &[
        0xab, 0xcd, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x06, 0x63, 0x6c,
        0x69, 0x65, 0x6e, 0x74, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f,
        0x6d, 0x00, 0x00, 0x41, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x41, 0x00, 0x01, 0x00, 0x00, 0x01,
        0x2c, 0x00, 0x88, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x06, 0x02, 0x68, 0x33, 0x02, 0x68,
        0x32, 0x00, 0x04, 0x00, 0x08, 0xc0, 0x00, 0x02, 0x0a, 0xc6, 0x33, 0x64, 0x0a, 0x00, 0x05,
        0x00, 0x47, 0x00, 0x45, 0xfe, 0x0d, 0x00, 0x41, 0x1c, 0x00, 0x20, 0x00, 0x20, 0x96, 0x73,
        0xe1, 0x0c, 0xe4, 0x8f, 0xed, 0x16, 0x26, 0x5d, 0x84, 0x8c, 0xab, 0xe1, 0x75, 0xb0, 0x6b,
        0x02, 0xef, 0x35, 0xdb, 0x6d, 0x61, 0x59, 0x90, 0x1f, 0x27, 0xad, 0xa0, 0x42, 0x84, 0x65,
        0x00, 0x04, 0x00, 0x01, 0x00, 0x01, 0x00, 0x12, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x66, 0x6c,
        0x61, 0x72, 0x65, 0x2d, 0x65, 0x63, 0x68, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x00, 0x06,
        0x00, 0x20, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x20,
    ];

    #[test]
    fn query_wire_format() {
        let q = build_query("client.example.com", 0xabcd).unwrap();
        let mut expected = vec![0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        expected.extend_from_slice(b"\x06client\x07example\x03com\x00\x00\x41\x00\x01");
        assert_eq!(q, expected);
        // The question section of the answer echoes our query.
        assert_eq!(&FIXTURE[12..q.len()], &q[12..]);
        assert_eq!(build_query("client.example.com.", 0xabcd).unwrap(), q);
    }

    #[test]
    fn query_rejects_bad_names() {
        assert!(build_query("", 1).is_none());
        assert!(build_query(".", 1).is_none());
        assert!(build_query("a..b", 1).is_none());
        assert!(build_query(&format!("{}.com", "a".repeat(64)), 1).is_none());
        assert!(build_query(&["abcdefghi"; 26].join("."), 1).is_none());
    }

    #[test]
    fn parses_live_fixture() {
        let ech = parse_ech_config_list(FIXTURE, FIXTURE_ID).unwrap();
        assert_eq!(ech.len(), 0x47);
        assert_eq!(&ech[..4], &[0x00, 0x45, 0xfe, 0x0d]);
        assert_eq!(ech[6], 0x1c, "config_id");
        assert!(ech.ends_with(b"\x12cloudflare-ech.com\x00\x00"));
    }

    #[test]
    fn rejects_mismatched_or_failed_responses() {
        assert!(parse_ech_config_list(FIXTURE, FIXTURE_ID ^ 1).is_none());
        let mut servfail = FIXTURE.to_vec();
        servfail[3] |= 0x02;
        assert!(parse_ech_config_list(&servfail, FIXTURE_ID).is_none());
        let mut query = FIXTURE.to_vec();
        query[2] &= 0x7f;
        assert!(parse_ech_config_list(&query, FIXTURE_ID).is_none());
    }

    #[test]
    fn truncated_input_never_panics() {
        for len in 0..FIXTURE.len() {
            assert!(parse_ech_config_list(&FIXTURE[..len], FIXTURE_ID).is_none());
        }
    }

    fn answer(owner: &[u8], rtype: u16, rdata: &[u8]) -> Vec<u8> {
        let mut rr = owner.to_vec();
        rr.extend_from_slice(&rtype.to_be_bytes());
        rr.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
        rr.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        rr.extend_from_slice(rdata);
        rr
    }

    #[test]
    fn skips_alias_mode_and_other_records() {
        let mut msg = build_query("example.com", 7).unwrap();
        msg[2] = 0x81;
        msg[3] = 0x80;
        msg[7] = 4;
        // CNAME with an uncompressed owner name.
        msg.extend(answer(b"\x07example\x03com\x00", 5, b"\x03foo\xc0\x0c"));
        // AliasMode HTTPS record.
        msg.extend(answer(b"\xc0\x0c", TYPE_HTTPS, b"\x00\x00\x03foo\x00"));
        // ServiceMode without ech.
        msg.extend(answer(
            b"\xc0\x0c",
            TYPE_HTTPS,
            b"\x00\x01\x00\x00\x01\x00\x03\x02h2",
        ));
        // ServiceMode with a target name, alpn, then ech.
        msg.extend(answer(
            b"\xc0\x0c",
            TYPE_HTTPS,
            b"\x00\x02\x03foo\x00\x00\x01\x00\x03\x02h2\x00\x05\x00\x03abc",
        ));
        assert_eq!(parse_ech_config_list(&msg, 7).unwrap(), b"abc");

        msg.truncate(msg.len() - 7);
        assert!(parse_ech_config_list(&msg, 7).is_none());
    }

    #[test]
    fn rejects_reserved_label_types() {
        let mut msg = FIXTURE.to_vec();
        // The answer's owner name, right after the question section.
        msg[36] = 0x80;
        assert!(parse_ech_config_list(&msg, FIXTURE_ID).is_none());
    }
}
