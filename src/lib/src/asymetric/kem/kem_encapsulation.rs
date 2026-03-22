use std::fmt;

use crate::asymetric::kem::{ciphertext::Ciphertext, shared_secret::SharedSecret};

pub struct KemEncapsulation {
    pub ss: SharedSecret,
    pub ct: Ciphertext,
}

impl fmt::Debug for KemEncapsulation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("SS: {:?}\nCT: {:?}", &self.ss, &self.ct))
    }
}
