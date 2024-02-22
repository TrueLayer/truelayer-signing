use std::{
    fmt,
    hash::{Hash, Hasher},
};

/// A valid HTTP method
pub struct Get;

/// A valid HTTP method
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

/// A case-sensitive header name, with case-insensitive
/// `Eq` & `Hash` implementations.
#[derive(Clone, Copy, Eq)]
pub(crate) struct HeaderName<'a>(pub &'a str);

impl fmt::Debug for HeaderName<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for HeaderName<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Case-insensitive hash.
impl Hash for HeaderName<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for c in self.0.bytes() {
            c.to_ascii_lowercase().hash(state);
        }
    }
}

/// Case-insensitive equals.
impl PartialEq for HeaderName<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(other.0)
    }
}

#[test]
fn case_insensitive_eq() {
    let a = HeaderName("X-Custom");
    let b = HeaderName("x-custom");
    assert_eq!(a, b);
}

#[test]
fn case_insensitive_hash() {
    let a = HeaderName("X-Custom");
    let b = HeaderName("x-custom");

    let hash = |thing: HeaderName<'_>| {
        let mut s = std::collections::hash_map::DefaultHasher::new();
        thing.hash(&mut s);
        s.finish()
    };

    assert_eq!(hash(a), hash(b));
}
