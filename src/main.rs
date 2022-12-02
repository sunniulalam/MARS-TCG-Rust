use aes::Aes128;
use block_modes::{BlockMode, Ecb, block_padding::Pkcs7};
use hex_literal::hex;
use std::{str};

type Aes128Ecb = Ecb<Aes128, Pkcs7>;

/*use hex_literal::hex;
use std::alloc;
pub use cipher;

use openssl::aes::{AesKey, KeyError, aes_ige};
use openssl::symm::{encrypt, Cipher};
use hex::{FromHex, ToHex};



pub use aes::Aes128;
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyInit};

type Aes128EcbEnc= ecb::Encryptor<aes::Aes128>;
type Aes128EcbDec= ecb::Decryptor<aes::Aes128>;*/

/*pub struct Encryptor<C>;
struct myAllocator;

unsafe impl alloc::GlobalAlloc for MyAllocator {
    unsafe fn alloc(&self, layout: alloc::Layout) -> *mut u8 {
        alloc::System.alloc(layout)
    }
    unsafe fn `dealloc(&self, ptr: *mut u8, layout: alloc::Layout) {
        alloc::System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static GLOBAL: MyAllocator = MyAllocator;*/

fn main() {
    /*let iv= hex!("");
    let mut plaintext= (String::from("Hello world!")).as_bytes();
    let mut key= hex::decode(String::from("000102030405060708090A0B0C0D0E0F")).expect("Decoding failed");

    let cipher= Aes128Ecb::new_from_slices(&key,&iv).unwrap();
    let pos= plaintext.len();
    let mut buffer= [0u8, 128];
    buffer[..pos].copy_from_slice(plaintext);
    let ciphertext= cipher.encrypt(&mut buffer, pos).unwrap();
    println!("\nCiphertext: {:?}",hex::encode(ciphertext));
    
    let mut buf=ciphertext.to_vec();
    let decrypted_ciphertext= cipher.decrypt(&mut buf).unwrap();
    println!("\nDeciphertext: {:?}",str::from_utf8(decrypted_ciphertext).unwrap());
    /*let key= hex!("000102030405060708090a0b0c0d0e0f");
    let nonce= hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let cryptme= b"abc";
    println!("Crypting the text: {:?}", str::from_utf8(cryptme).unwrap());

    let cipher= Aes128Cbc::new_from_slice(key, nonce).unwrap();
    let mut buffer = [0u8, 32];

    let pos= cryptme.len();
    buffer[..pos].copy_from_slice(cryptme);
    let crypted= cipher.encrypt(&mut buffer, pos).unwrap();
    //println!("Crypted text: {:?}", crypted);

    let mut buf= crypted.to_vec();
    let cipher= Aes128Cbc::new_from_slice(&key, &nonce).unwrap();
    let decrypted= cipher.decrypt(&mut buf).unwrap();

    //println!("Decrypted text: {:?}", str::from_ut8(decrypted).unwrap());
    assert_eq!(decrypted, cryptme);*/
    /*let key = [0x42; 16];
    let plaintext = *b"hello world! this is my plaintext.";
    let ciphertext = hex!(
        "0336763e966d92595a567cc9ce537f5e"
    );
    let mut buf = [0u8; 48];
    let pt_len = plaintext.len();
    
    let res = Aes128EcbEnc::new(&key.into())
    .encrypt_padded_vec_mut::<Pkcs7>(&plaintext);
    assert_eq!(res[..], ciphertext[..]);
    let res = Aes128EcbDec::new(&key.into()).decrypt_padded_vec_mut::<Pkcs7>(&res).unwrap();
    assert_eq!(res[..], plaintext[..]);
    buf[..pt_len].copy_from_slice(&plaintext);
    let ct = Aes128EcbEnc::new(&key.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buf, pt_len)
        .unwrap();
    assert_eq!(ct, &ciphertext[..]);

    let pt = Aes128EcbDec::new(&key.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .unwrap();
    assert_eq!(pt, &plaintext);

    // encrypt/decrypt from buffer to buffer
    let mut buf = [0u8; 48];
    let ct = Aes128EcbEnc::new(&key.into())
        .encrypt_padded_b2b_mut::<Pkcs7>(&plaintext, &mut buf)
        .unwrap();
    assert_eq!(ct, &ciphertext[..]);

    let mut buf = [0u8; 48];
    let pt = Aes128EcbDec::new(&key.into())
        .decrypt_padded_b2b_mut::<Pkcs7>(&ct, &mut buf)
        .unwrap();
    assert_eq!(pt, &plaintext);
  /*let ciph= Cipher::aes_128_ecb();
    let mut key = [0u8; 16];
    let iv= [0u8; 16];
    let plaintext = hex::decode((hex!("f34481ec3cc627bacd5dc3fb08f273e6")));
    let ciphertext = hex!("0336763e966d92595a567cc9ce537f5e");
    println!("Expected Cipher text: {}", hex::decode(ciphertext));
    println!("Actual Cipher text: {}", hex::decode(encrypt(ciph, &key, iv, plaintext).unwrap()));
    assert_eq!(ciphertext, encrypt(ciph, &key, iv, plaintext).unwrap()) */
}
/*#[cfg(all(feature = "alloc", feature = "block-padding"))] {
    use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyInit};
    use hex_literal::hex;
    type Aes128EcbEnc = ecb::Encryptor<aes::Aes128>;
    type Aes128EcbDec = ecb::Decryptor<aes::Aes128>;
    let key = [0; 16];
    let plaintext = hex::decode((hex!("f34481ec3cc627bacd5dc3fb08f273e6")));
    let ciphertext = hex!("0336763e966d92595a567cc9ce537f5e");
    let res = Aes128EcbEnc::new(&key.into())
        .encrypt_padded_vec_mut::<Pkcs7>(&plaintext);
    assert_eq!(res[..], ciphertext[..]);
    let res = Aes128EcbDec::new(&key.into())
        .decrypt_padded_vec_mut::<Pkcs7>(&res)
        .unwrap();
    assert_eq!(res[..], plaintext[..]);*/ */ */
}
