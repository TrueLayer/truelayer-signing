pub struct Unset;
pub struct Get;
pub struct Post;

impl Get {
    pub const fn name() -> &'static str {
        "GET"
    }
}

impl Post {
    pub const fn name() -> &'static str {
        "POST"
    }
}
