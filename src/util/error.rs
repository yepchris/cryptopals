use crypto::symmetriccipher::SymmetricCipherError::{self, InvalidLength, InvalidPadding};
use std::{error, fmt, io, net::AddrParseError};

#[derive(Debug, Default)]
pub struct AesError(pub String);

impl fmt::Display for AesError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "error: {}", self.0)
    }
}

impl error::Error for AesError {
    fn description(&self) -> &str {
        "generic error"
    }

    fn cause(&self) -> Option<&error::Error> {
        // Generic error, underlying cause isn't tracked.
        None
    }
}

impl AesError {
    pub fn new<S: Into<String>>(msg: S) -> Self {
        AesError(msg.into())
    }
}

impl From<SymmetricCipherError> for AesError {
    fn from(error: SymmetricCipherError) -> Self {
        match error {
            InvalidLength => AesError::new("invalid AES length"),
            InvalidPadding => AesError::new("invalid AES padding"),
        }
    }
}

impl From<String> for AesError {
    fn from(error: String) -> Self {
        AesError::new(error)
    }
}

/*
impl From<AddrParseError> for Generic {
    fn from(error: AddrParseError) -> Self {
        Generic::new(error.to_string())
    }
}

impl From<io::Error> for Generic {
    fn from(error: io::Error) -> Self {
        Generic::new(error.to_string())
    }
}
*/
/*
impl From<native_tls::Error> for Generic {
    fn from(error: native_tls::Error) -> Self {
        Generic::new(error.description())
    }
}
*/
/*
#[derive(Debug)]
enum ApiError {
    Io(io::Error),
    //Parse(num::ParseIntError),
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            // Both underlying errors already impl `Display`, so we defer to
            // their implementations.
            ApiError::Io(ref err) => write!(f, "IO error: {}", err),
            //CliError::Parse(ref err) => write!(f, "Parse error: {}", err),
        }
    }
}

impl error::Error for ApiError {
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            // N.B. Both of these implicitly cast `err` from their concrete
            // types (either `&io::Error` or `&num::ParseIntError`)
            // to a trait object `&error::Error`. This works because both error types
            // implement `error::Error`.
            ApiError::Io(ref err) => Some(err),
            //CliError::Parse(ref err) => Some(err),
        }
    }
}
*/
