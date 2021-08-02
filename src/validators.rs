use std::fmt::Display;

use thiserror::Error;

#[derive(Error, Debug)]
#[error("Validation error: {0}")]
struct ValidationError(String);

/// A 'validator' to allow validating the value of a field when parsing
pub trait RequireEqual<T> {
    fn require_equal(self, expected: T) -> Result<T, Box<dyn std::error::Error>>;
}

impl<T, E> RequireEqual<T> for Result<T, E>
where
    E: Into<Box<dyn std::error::Error>>,
    T: Eq + Display,
{
    fn require_equal(self, expected: T) -> Result<T, Box<dyn std::error::Error>> {
        match self {
            Err(e) => Err(e.into()),
            Ok(v) => v.require_equal(expected),
        }
    }
}

impl<T> RequireEqual<T> for T
where
    T: Eq + Display,
{
    fn require_equal(self, expected: T) -> Result<T, Box<(dyn std::error::Error + 'static)>> {
        if self == expected {
            Ok(self)
        } else {
            Err(ValidationError(format!("expected {}, but found {}", expected, self)).into())
        }
    }
}
