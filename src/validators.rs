use std::fmt::Display;

use thiserror::Error;

#[derive(Error, Debug)]
#[error("Validation error: {0}")]
struct ValidationError(String);

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
            Ok(v) => {
                if v == expected {
                    Ok(v)
                } else {
                    Err(ValidationError(format!("expected {}, but found {}", expected, v)).into())
                }
            }
        }
    }
}
