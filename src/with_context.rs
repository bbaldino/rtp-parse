use std::error::Error;
use thiserror::Error;

#[derive(Error, Debug)]
#[error("{msg}: {cause}")]
pub struct WrappedError {
    msg: String,
    cause: Box<dyn Error>,
}

pub trait Context<T, E> {
    fn with_context<S: Into<String>>(self, context: S) -> Result<T, Box<dyn Error>>;
}

impl<T, E> Context<T, WrappedError> for Result<T, E>
where
    E: Into<Box<dyn Error>>,
{
    fn with_context<S: Into<String>>(self, context: S) -> Result<T, Box<dyn Error>> {
        match self {
            Ok(v) => Ok(v),
            Err(e) => Err(WrappedError {
                msg: context.into(),
                cause: e.into(),
            }
            .into()),
        }
    }
}

pub fn with_context<T, F: FnOnce() -> Result<T, Box<dyn std::error::Error>>, S: Into<String>>(
    context: S,
    block: F,
) -> Result<T, Box<dyn std::error::Error>> {
    match block() {
        Ok(v) => Ok(v),
        Err(e) => Err(Box::new(WrappedError {
            msg: context.into(),
            cause: e,
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passes() -> Result<u8, Box<dyn std::error::Error>> {
        Ok(42)
    }

    fn fails() -> Result<u8, impl std::error::Error> {
        Err(std::io::Error::new(std::io::ErrorKind::Other, "Boom!"))
    }

    #[derive(Debug)]
    struct MyStruct {
        value: u8,
    }

    fn parse_my_struct() -> Result<MyStruct, Box<dyn std::error::Error>> {
        with_context("MyStruct", || {
            Ok(MyStruct {
                value: fails().with_context("parsing value")?,
            })
        })
    }

    #[test]
    fn foo() {
        let result = parse_my_struct();
        println!("Error: {}", result.unwrap_err());
    }
}
