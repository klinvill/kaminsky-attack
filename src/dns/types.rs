#[repr(u16)]
#[derive(Copy, Clone)]
/// Subset of TYPE values specified in IETF RFC 1035
pub(crate) enum Type {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    TXT = 16,
}
