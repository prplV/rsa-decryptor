extern crate rand; 
extern crate rsa as rust_crypto;

use std::fs::File;
use std::io::{Write, Read};
use rust_crypto::{Pkcs1v15Encrypt, RsaPrivateKey, Oaep};
use rust_crypto::pkcs1::DecodeRsaPrivateKey;

pub struct MainStructForDecryption{
    private_key: RsaPrivateKey,
    encrypted_message: Vec<u8>,
    decrypted_message: String,
    filename: String,
}

pub trait Decryptor{
    fn new() -> Self;
    fn read_private_key(&mut self, pk_file_name: String);
    fn read_message(&mut self, msg_file_name: String, fname: String);
    fn decrypt_and_save(&self) -> std::io::Result<()>;
}

impl Decryptor for MainStructForDecryption{
    fn new() -> Self{
        let mut temp = rand::thread_rng();
        return MainStructForDecryption{
            private_key: RsaPrivateKey::new(&mut temp, 2048).expect("failed to generate a key"),
            encrypted_message: Vec::new(),
            decrypted_message: String::from("null"),
            filename: String::from("null"),
        }
    }
    // get private key from .pem file
    fn read_private_key(&mut self, pk_file_name: String){
        let private_key_path = pk_file_name + ".pem";

        let mut private_key_data = Vec::new();
        let mut private_key_file = File::open(private_key_path).expect("private key file opening error");
        private_key_file.read_to_end(&mut private_key_data).expect("private key file reading error");

        let str = String::from_utf8(private_key_data).unwrap();
        let pk = RsaPrivateKey::from_pkcs1_pem(&str).expect("error parsing pk");
        self.private_key = pk;

        println!("pk reading was successfully done!");
    }   

    // fn to read an encrypted message from the .bin file 
    fn read_message(&mut self, msg_file_name: String, fname: String){
        let MESSAGE = msg_file_name + &".bin".to_string();
        
        let mut msg_data = Vec::new();
        let mut msg_file  = File::open(MESSAGE).expect("msg file opening error");
        msg_file.read_to_end(&mut msg_data).expect("msg file reading error!");

        self.encrypted_message = msg_data;
        self.filename = fname;
        println!("msg reading was successfully done!");
        
    }
    // magic
    fn decrypt_and_save(&self) -> std::io::Result<()>{
        // decrypting 
        let ini_file: Vec<u8> = self.private_key.decrypt(Pkcs1v15Encrypt, &self.encrypted_message)
            .expect("error with decrypting messasge");

        // creating file and saving
        let owner = self.filename.as_str().to_owned();
        let fname = owner + ".ini";
        
        let mut file = File::create(fname)?;
        file.write_all(&ini_file)?;
        
        println!("\ndecrypted message was successfully written");
        Ok(())
    }
}