extern crate anyhow;
use zeroize::{Zeroize, ZeroizeOnDrop};

use self::anyhow::Result;

extern crate core;
use self::core::fmt;

use std::{
    fmt::{Display, Formatter},
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Word(String);
pub struct Dictionnary;

impl Dictionnary {
    pub fn get_random_word(path: &Path) -> Result<Word> {
        let reader = BufReader::new(File::open(path).expect("Cannot open file"));
        let file_length = reader.lines().count();
        let random = rand::random_range(0..file_length);
        let reader = BufReader::new(File::open(path)?);

        let word = reader.lines().nth(random).expect("index is valid")?;

        Ok(Word(word))
    }
}

impl Word {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn from_str(p: &str) -> Self {
        Self(p.to_string())
    }
}

impl Display for Word {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
