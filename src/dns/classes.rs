use num_derive::FromPrimitive;

#[repr(u16)]
#[derive(FromPrimitive, PartialEq, Debug, Copy, Clone)]
/// Subset of CLASS values specified in IETF RFC 1035
pub(crate) enum Class {
    IN = 1, // the Internet
}
