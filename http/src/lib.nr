pub mod data;
pub mod tests;
pub mod utils;
pub mod parser;
pub mod setup;

pub comptime global CARRIAGE_RETURN: u8 = "\r".as_bytes()[0]; // 13
pub comptime global LINE_FEED: u8 = "\n".as_bytes()[0]; // 10
pub comptime global COLON: u8 = ":".as_bytes()[0]; // 58
pub comptime global SPACE: u8 = " ".as_bytes()[0]; // 32
