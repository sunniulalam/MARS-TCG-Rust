use std::u8;
use ascon_aead::aead::generic_array::{GenericArray, ArrayLength};
use ascon_aead::{Ascon128, Error , Key, Nonce, Ascon128Tag, Ascon128Nonce}; // Or Ascon128a
use ascon_aead::aead::{Aead, KeyInit,AeadInPlace};
use ascon_hash::{AsconHash,Digest, AsconCore}; use digest::consts::{B1, B0};
use digest::core_api::CoreWrapper;
use digest::typenum::{UInt, UTerm};
use hex::FromHex;
use std::io::Write;   //bytes.write(

#[derive(Debug, Default, Clone)]
pub struct ASCON_CTX{
    hasher: CoreWrapper<AsconCore>,
    /*not used in SHA256*/
    total:  usize,
    len:    usize,
    blk:    GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>>,
    h:      GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>>,
    truncate: usize,
}

pub(crate) type profile_shc_t= ASCON_CTX;

impl ASCON_CTX{
    fn ASCON_Init(&mut self){
        self.hasher= AsconHash::new();
    }
    fn ASCON_Update(&mut self, data: &[u8]){
        (self.hasher).update(data);
    }
    fn ASCON_Final(self)-> GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>>{
        return (self.hasher).finalize();
    }
}

//Function returns hexString from bytes
pub fn hexout(data: &[u8]) -> String {
    let mut ret = String::new();

    for d in data {
        let x = format!("{:02x}", d);
        ret.push_str(&x);
    }
    return ret
}

//Padding the label 'Z' with 0s
fn fill_from_str(mut bytes: &mut [u8], s: &str) {
    bytes.write(s.as_bytes()).unwrap();
    //println!("{:?}", bytes);
} 

pub(crate) fn CryptSign(key: &[u8],digest: &[u8]) -> Result<Ascon128Tag,Error> {
    let key = Key::<Ascon128>::from_slice(&key);
    let cipher = Ascon128::new(key);
    let mut bytes: [u8; 16] = [0; 16];
    let mut buffer = Vec::new();
    let s= "Z";

    //set the label to a letter Z padded with 15 0s
    fill_from_str(&mut bytes, "Z");
    let nonce = Nonce::<Ascon128>::from_slice(&bytes);  
    
    print!("{}", "SIGN: key ");
    hexout(&key[..]);
    print!("{} {}", "SIGN: nnc ", hexout(&nonce));
    print!("{}", "SIGN: ad ");
    let hexDigest = hex::encode(&digest);
    println!("{}", hexDigest);
    print!("{}", "SIGN: sig ");

    let tag = cipher.encrypt_in_place_detached(&nonce, &digest , &mut buffer); 
    return tag;
}


pub(crate) fn CryptVerify(key: &[u8],digest: &[u8], tag: Result<Ascon128Tag,Error> )  -> Result<(),Error> {
    let key = Key::<Ascon128>::from_slice(&key);
    let cipher = Ascon128::new(key);
    let mut bytes: [u8; 16] = [0; 16];
    let mut buffer = Vec::new();
    let s= "Z";

    let mut gTag= GenericArray::default(); //gets the generic array only and not the result
    for d in tag {
        gTag = d;
    }

    //set the label to a letter Z padded with 15 0s
    fill_from_str(&mut bytes, "Z");
    let nonce = Nonce::<Ascon128>::from_slice(&bytes);  
    //hexout(&nonce);
    
    let decryptTag = cipher.decrypt_in_place_detached(&nonce, &digest, &mut buffer, &gTag);
    return decryptTag;
}

fn CryptSkdf(key: &[u8],label: String, digest: &[u8]) -> Result<Ascon128Tag,Error> {
    let key = Key::<Ascon128>::from_slice(&key);
    let cipher = Ascon128::new(key);
    let mut bytes: [u8; 16] = [0; 16];
    let mut buffer = Vec::new();
    let s= "Z";

    //set the label to a letter Z padded with 15 0s
    fill_from_str(&mut bytes, &label);
    let nonce = Nonce::<Ascon128>::from_slice(&bytes);  
    //hexout(&nonce);
    
    let tag = cipher.encrypt_in_place_detached(&nonce, &digest , &mut buffer); 
    return tag;
}

pub(crate) fn CryptXkdf(key: &[u8],label: String, digest: &[u8])->Result<Ascon128Tag,Error>{
    return CryptSkdf(key, label, digest);
}

pub(crate) fn CryptHashInit(pctx: &mut profile_shc_t){
    pctx.ASCON_Init();
}

pub(crate) fn  CryptHashUpdate(pctx: &mut profile_shc_t, data: &[u8]){
    pctx.ASCON_Update(data);
}

pub(crate) fn CryptHashFinal(pctx: &mut profile_shc_t)-> GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>>{
    return (pctx).clone().ASCON_Final(); 
}


fn SelfTest(){
     //Init/ Update / Finalize
     let pctx: &mut profile_shc_t= &mut profile_shc_t::default();

     println!("{}","\nCrypt init,update,finalize Function");
     CryptHashInit(pctx);
     CryptHashUpdate(pctx, b"this is a test");
     let final_hash = CryptHashFinal(pctx);
     let string_crypt_hash = hexout(&final_hash);        //Convert vec to hexString
     println!("{}", string_crypt_hash);   
     println!("{}","\n\n");
// -----------------------------------------------------------------------------------------------------------------------------

     //CryptSign
     println!("{}","CryptSign Function");
     let tag = CryptSign(b"A 16 byte secret", &final_hash);
     
     let mut hex_tag_string = String::new(); //Print out the results
     for d in tag {
         let x = format!("{:02x}", d);
         hex_tag_string.push_str(&x);
     }
     println!("{}",hex_tag_string);


// -----------------------------------------------------------------------------------------------------------------------------

     //CryptVerify
     println!("{}","\nCryptVerify Function");
     let decrypt_tag = CryptVerify(b"A 16 byte secret", &final_hash, tag);
     println!("{}",decrypt_tag.is_ok()); //True if match otherwise false

// -----------------------------------------------------------------------------------------------------------------------------

     //CryptSkdf
     println!("{}","\nCryptSkdf Function");
     let label = "ABC";
     let skdf = CryptSkdf(b"A 16 byte secret", label.to_string(), &final_hash);
     
     let mut hexSKDFString = String::new();
     for d in skdf {
         let x = format!("{:02x}", d);
         hexSKDFString.push_str(&x);
     }
     print!("{}","SKDF Result:   ");
     println!("{}",hexSKDFString);
    }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        SelfTest()

    }
}