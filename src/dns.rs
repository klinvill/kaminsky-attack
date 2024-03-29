mod additional;
mod answer;
mod authority;
mod classes;
mod client;
mod header;
mod hostname;
pub mod message;
mod query;
mod question;
mod resource_record;
mod response;
mod types;

pub type Client = client::Client;
pub type Query = query::Query;
pub type Response = response::Response;
pub type Record = response::Record;
pub type ARecord = response::ARecord;
pub type NSRecord = response::NSRecord;
