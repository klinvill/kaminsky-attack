#[repr(u16)]
#[derive(Copy, Clone)]
/// Subset of CLASS values specified in IETF RFC 1035
pub(crate) enum Class {
    IN = 1, // the Internet
}
