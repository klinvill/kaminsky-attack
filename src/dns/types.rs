use num_derive::FromPrimitive;

#[repr(u16)]
#[derive(FromPrimitive, PartialEq, Debug, Copy, Clone)]
/// Subset of TYPE values specified in IETF RFC 1035
pub(crate) enum Type {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    TXT = 16,
}
