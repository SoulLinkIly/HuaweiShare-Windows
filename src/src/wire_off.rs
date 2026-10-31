#![allow(unused_variables)]
#[inline]
pub fn tx(channel: &str, data: &[u8], conn: u64) {}

#[inline]
pub fn rx(channel: &str, data: &[u8], conn: u64) {}

#[inline]
pub fn mark(channel: &str, note: &str) {}
