include!(concat!(env!("OUT_DIR"), "/fetched.rs"));

pub fn fetched() -> bool {
    FETCHED
}
