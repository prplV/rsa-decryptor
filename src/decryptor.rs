extern crate rand; 
extern crate rsa;

use std::fs::File;
use std::io::{Write, Read, BufReader};
use base64::{encode, decode};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, Oaep, Pss};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::signature::digest::{Digest, DynDigest};
use sha1::Sha1;
use sha2::Sha256;
// use crypto::digest::Digest;

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
    fn test_pkcs_padding(&self, padding: &Pkcs1v15Encrypt) -> bool;
    fn test_oaep_padding(&self, padding: Oaep, index: i8) -> bool;
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
        //println!("{:?}", pk);
        self.private_key = pk;

        println!("pk reading was successfully done!");
    }   

    // fn to read an encrypted message from the .bin file 
    fn read_message(&mut self, msg_file_name: String, fname: String){
        let MESSAGE = msg_file_name + &".bin".to_string();
        
        let mut msg_data = Vec::new();
        let mut msg_file  = File::open(MESSAGE).expect("msg file opening error");
        msg_file.read_to_end(&mut msg_data).expect("msg file reading error!");

        //let msg_base64 = encode(msg_data);

        //println!("{:?}", msg_base64);

        self.encrypted_message = msg_data;
        self.filename = fname;
        //println!("msg reading was successfully done!");
        //panic!("aiusdhpa");
    }
    // magic
    fn decrypt_and_save(&self) -> std::io::Result<()>{
        // decrypting 

        //creating new padding schemes
        let padding_Pkcs1v15Encrypt = Pkcs1v15Encrypt;
        let padding_oaep_sha256 = Oaep::new::<Sha256>();
        let padding_oaep_sha1 = Oaep::new::<Sha1>();
        //let tuple_padding = (padding_Pkcs1v15Encrypt, padding_oaep_sha1, padding_oaep_sha256);
        //let padding_pss = Pss::new::<Sha256>();

        match self.private_key.validate(){
            Ok(_) => {println!("\n\nVerified\n\n")},
            Err(_) => {println!("\n\nUnverified\n\n")}
        }

        //let ini_file: Vec<u8> = self.private_key.decrypt(padding_oaep_sha1, &self.encrypted_message).unwrap();

            //.expect("error with decrypting messasge");

        let mut ini_file: Vec<u8> = Vec::new();


        if self.test_pkcs_padding(&padding_Pkcs1v15Encrypt){
            ini_file = self.private_key.decrypt(padding_oaep_sha1, &self.encrypted_message).unwrap();
        }
        else{
            if self.test_oaep_padding(padding_oaep_sha1, 1){
                let padding_oaep_sha1 = Oaep::new::<Sha1>();
                ini_file = self.private_key.decrypt(padding_oaep_sha1, &self.encrypted_message).unwrap();
            }
            else{
                if self.test_oaep_padding(padding_oaep_sha256, 2){
                    let padding_oaep_sha256 = Oaep::new::<Sha256>();
                    ini_file = self.private_key.decrypt(padding_oaep_sha256, &self.encrypted_message).unwrap();
                }
                else{
                    panic!("There is no padding schemes that satisfy private key in the work directory!\nWork can't be continued");
                }
            }
        }

        
        // creating file and saving
        let owner = self.filename.as_str().to_owned();
        let fname = owner + ".ini";
        
        let mut file = File::create(fname)?;
        file.write_all(&ini_file)?;
        
        println!("\ndecrypted message was successfully written");
        Ok(())
    }
    fn test_pkcs_padding(&self, padding: &Pkcs1v15Encrypt) -> bool {
        return match self.private_key.decrypt(*padding, &self.encrypted_message) {
            Ok(_) => {
                println!("Bin file's padding is Pkcs1v15Encrypt");
                true
            },
            Err(_) => {
                false
            },
        }
    }
    fn test_oaep_padding(&self, padding: Oaep, index: i8) -> bool {
        return match self.private_key.decrypt(padding, &self.encrypted_message) {
            Ok(_) => {
                if index == 1{
                    println!("Bin file's padding is Oaep with Sha-1 hashing");
                }
                else{
                    println!("Bin file's padding is Oaep with Sha-256 hashing");
                }
                true
            },
            Err(_) => {
                false
            },
        }
    }  
}