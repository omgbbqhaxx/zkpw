use aes::Aes256;
use aes::cipher::{generic_array::GenericArray, BlockEncryptMut, BlockDecryptMut, KeyInit};
use hex::{decode, encode};
use sha3::{Digest, Keccak256};
use secp256k1::{Secp256k1, PublicKey}; // secp256k1 crate'i ekle
use std::io::{self, Write};

// Ethereum private key'den şifreleme anahtarı türet
fn derive_key_from_private_key(private_key_hex: &str) -> [u8; 32] {
    let private_key_bytes = decode(private_key_hex).expect("Invalid hex string");

    let mut hasher = Keccak256::new();
    hasher.update(private_key_bytes);
    let result = hasher.finalize();

    let mut key = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    key
}

// Public key'i private key'den türet
fn derive_public_key(private_key_hex: &str) -> PublicKey {
    let secp = Secp256k1::new();
    let private_key = decode(private_key_hex).expect("Invalid hex string");
    let secret_key = secp256k1::SecretKey::from_slice(&private_key).expect("Invalid private key");
    PublicKey::from_secret_key(&secp, &secret_key)
}

// 16 byte blok boyutuna göre padding uygula
fn pad_data(data: &[u8]) -> Vec<u8> {
    let mut padded_data = data.to_vec();
    let pad_length = 16 - (data.len() % 16);
    padded_data.extend(vec![pad_length as u8; pad_length]);
    padded_data
}

// Padding'i kaldır (decrypt sonrası)
fn unpad_data(padded_data: &[u8]) -> Vec<u8> {
    let pad_length = *padded_data.last().unwrap() as usize;
    padded_data[..padded_data.len() - pad_length].to_vec()
}

// 4 haneli PIN'den IV oluştur (hash ile)
fn derive_iv_from_pin(pin: &str) -> [u8; 16] {
    let mut hasher = Keccak256::new();
    hasher.update(pin);
    let result = hasher.finalize();

    let mut iv = [0u8; 16];
    iv.copy_from_slice(&result[..16]);
    iv
}

// Veriyi AES-256 CBC ile şifreleme
fn encrypt_data(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let mut cipher = Aes256::new(GenericArray::from_slice(key));
    let mut blocks = pad_data(data);

    let mut previous_block = iv.to_vec(); // IV'yi önceki bloğa atıyoruz

    for chunk in blocks.chunks_mut(16) {
        let block = GenericArray::from_mut_slice(chunk);
        for (byte, prev_byte) in block.iter_mut().zip(previous_block.iter()) {
            *byte ^= prev_byte; // XOR işlemi
        }
        cipher.encrypt_block_mut(block);
        previous_block.copy_from_slice(chunk); // Şifrelenen bloğu önceki bloğa kaydet
    }

    blocks
}

// AES-256 CBC ile şifreyi çözme
fn decrypt_data(key: &[u8; 32], iv: &[u8; 16], encrypted_data: &[u8]) -> Vec<u8> {
    let mut cipher = Aes256::new(GenericArray::from_slice(key));
    let mut blocks = encrypted_data.to_vec();

    let mut previous_block = iv.to_vec(); // IV'yi önceki blok için başlat

    for chunk in blocks.chunks_mut(16) {
        let block = GenericArray::from_mut_slice(chunk);
        cipher.decrypt_block_mut(block);
        for (byte, prev_byte) in block.iter_mut().zip(previous_block.iter()) {
            *byte ^= prev_byte; // XOR işlemi
        }
        previous_block.copy_from_slice(chunk); // Şifrelenen bloğu önceki bloğa kaydet
    }

    unpad_data(&blocks)
}

fn main() {
    // Kullanıcıdan private key iste
    let mut private_key_input = String::new();
    print!("Please fill private key (without 0x): ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut private_key_input).expect("Failed to read input");
    let private_key = private_key_input.trim();

    // Public key'i private key'den türet
    let public_key = derive_public_key(private_key);
    let public_key_hex = encode(public_key.serialize_uncompressed()); // Public key'i hex formatında al

    // Şifreleme anahtarını private key'den türet
    let key = derive_key_from_private_key(private_key);

    // Kullanıcıdan 4 haneli PIN iste
    let mut pin_input = String::new();
    print!("4 haneli PIN girin: ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut pin_input).expect("Failed to read input");
    let pin = pin_input.trim();
    assert!(pin.len() == 4, "4 digit IV (PIN) necessary");

    // PIN'den IV oluştur (hash ile)
    let iv = derive_iv_from_pin(pin);

    // Kullanıcıdan şifrelenecek veri iste
    let mut data_input = String::new();
    print!("Şifrelenecek veriyi girin: ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut data_input).expect("Failed to read input");
    let data = data_input.trim().as_bytes(); // Kullanıcıdan alınan veriyi byte dizisine çevir

    // Veriyi şifrele
    let encrypted_data = encrypt_data(&key, &iv, data);
    println!("Encrypted data (hex): {}", encode(&encrypted_data));
}
