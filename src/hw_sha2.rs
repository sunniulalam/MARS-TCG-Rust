/*SHA256*/
use sha2::{Sha256VarCore, OidSha256};
pub use sha2::{Digest, Sha256};
use hmac::{Hmac, Mac, digest::{generic_array::GenericArray, typenum::{UInt, B1, UTerm, B0}, core_api::{CtVariableCoreWrapper, CoreWrapper}}};


#[derive(Debug, Default, Clone)]
pub struct SHA256_CTX{
    hasher: CoreWrapper<CtVariableCoreWrapper<Sha256VarCore, UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>, OidSha256>>,
    /*not used in SHA256*/
    total:  usize,
    len:    usize,
    blk:    GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>>,
    h:      GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>>,
    truncate: usize,
}

pub(crate) type profile_shc_t= SHA256_CTX;

impl SHA256_CTX{
    fn SHA256_Init(&mut self){
        self.hasher= Sha256::new();
    }
    fn SHA256_Update(&mut self, data: &[u8]){
        (self.hasher).update(&data);
    }
    fn SHA256_Final(self)-> GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>>{
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
    ret
}
//Crypt Sign Function
pub(crate) fn CryptSign(key: &[u8],digest: &[u8]) -> GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>>  {
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC can take key of any size");
        mac.update(&digest);   //message

        let result = mac.finalize();
        let code_bytes = result.into_bytes();       //Gets the aunthentic code
        // println!("{:?}", code_bytes);

        //let string_code_byte = hexout(&code_bytes);

       return code_bytes;  

}

//CryptVerify Function
pub(crate) fn CryptVerify(key: &[u8],digest: &[u8], sig: GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>>)  -> bool {

     let new_sig = CryptSign(key, digest);

     if new_sig == sig {
        return true;
     }else{
        return false;
     }
}


fn CryptSKDF(key: &[u8],label: &[u8], context: &[u8]) -> GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>> {
  
    // print!("{}", "SKDF: ");

    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC can take key of any size");
    mac.update(&b"\x00\x00\x00\x01"[..]);   
    mac.update(&label[..]);   
    mac.update(&b"\x00"[..]);   
    mac.update(&context[..]);   
    mac.update(&b"\x00\x00\x20\x00"[..]);   

    let result = mac.finalize();
    let code_bytes = result.into_bytes();
    return code_bytes;     
}

pub(crate) fn CryptXkdf(key: &[u8], label: &[u8], context: &[u8])-> GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>>{
    return CryptSKDF(key, label, context);
}

pub(crate) fn CryptHashInit(pctx: &mut profile_shc_t){
    pctx.SHA256_Init();
}

pub(crate) fn  CryptHashUpdate(pctx: &mut profile_shc_t, data: &[u8]){
    pctx.SHA256_Update(data);
}

pub(crate) fn CryptHashFinal(pctx: &mut profile_shc_t)-> GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>>{
    return (pctx).clone().SHA256_Final(); 
}


#[test]
fn SelfTest(){
    //Init/ Update / Finalize
    //Test based on CryptSelfTest from https://github.com/TrustedComputingGroup/MARS/blob/fe892024c80baa50603fca4caea2b67eb43a29dc/emulator/python/hw_sha2.py
    println!("{}","\nCrypt Self Test");
    let hash_test: &mut profile_shc_t = &mut profile_shc_t::default();
    //let mut x = DerefMutExample { value: hash_test };
    
    CryptHashInit(hash_test);
    CryptHashUpdate(hash_test, b"PYTHON");
    let string_crypt_hash = hexout(&CryptHashFinal(hash_test)[..]);        //Convert vec to hexString
    println!("{}", string_crypt_hash);
    let exp = "329b3dcf798a73e8b87f486bcdaa8e2070f6437f1d470fec6e174ef8ec7b1554";
    assert_eq!(string_crypt_hash,exp); 
    
   // println!("{}\n", string_crypt_hash);  
   //let mut x = DerefMut(hash_test); 
} 




#[cfg(test)]
mod tests {   
    use super::*;

    #[test]
    fn abc_test(){
        let hash_test: &mut profile_shc_t = &mut profile_shc_t::default();
        CryptHashInit(hash_test);
        CryptHashUpdate(hash_test, b"this is a test");

       // CryptHashFinal(hash_test);
       // println!("{}", hexout(&CryptHashFinal(hash_test)[..]));
    }

    #[test]
    fn test_sha256_sum() {

//          //CryptSign
//          println!("{}","CryptSign Function");
//          let sig = CryptSign(b"my secret and secure key", b"Hi There");
//          let string_of_sig = hexout(&sig);
//          println!("{}", string_of_sig);   
          
//  // -----------------------------------------------------------------------------------------------------------------------------

//         //CryptVerify
//         println!("{}","\nCryptVerify Function");
//         let bool_check = CryptVerify(b"my secret and secure key", b"Hi There", sig);
//         println!("{}", bool_check);
      
//  // -----------------------------------------------------------------------------------------------------------------------------
//         //CryptSKDF
//         println!("{}","\nCryptSKDF Function");
//         // bytes.fromhex('101112131415161718191a1b1c1d1e1f101112131415161718191a1b1c1d1e1f')
//         let skdf = CryptSKDF(b"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",b"R" , b"");
//         let string_of_skdf = hexout(&skdf);
//         println!("{}", string_of_skdf);   
        

//  // -----------------------------------------------------------------------------------------------------------------------------
//         //Init/ Update / Finalize
//         println!("{}","\nCrypt init,update,finalize Function");
//         let hash_test: profile_shc_t = profile_shc_t::default();
        
//         let init_hash = CryptHashInit(hash_test);
//         let update_hash = CryptHashUpdate(init_hash, b"this is a test");
//         let final_hash = CryptHashFinal(update_hash);
        
//         let string_crypt_hash = hexout(&final_hash);        //Convert vec to hexString
//         println!("{}", string_crypt_hash);   
//         println!("{}","\n\n");

    }
}
/*END OF SHA256*/