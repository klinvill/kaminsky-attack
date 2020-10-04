use crate::dns::resource_record::ResourceRecord;

/// DNS authority section with fields as specified in IETF RFC 1035
pub type Authority<'authority> = ResourceRecord<'authority>;
