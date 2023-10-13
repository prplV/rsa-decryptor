#[path = "decryptor.rs"] mod decryptor;

use crate::decryptor::Decryptor;

fn main() {

    let mut dec: decryptor::MainStructForDecryption = decryptor::Decryptor::new();
    
    dec.read_message(("license").to_string(), ("license").to_string());
    dec.read_private_key(("license_key_private").to_string());
    dec.decrypt_and_save();
}
