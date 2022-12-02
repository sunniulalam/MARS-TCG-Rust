/*SHE*/
use aes::Aes128;
use aes::cipher::{BlockCipher, BlockEncrypt, BlockDecrypt, };
use hex_literal::hex;
use hex::decode_to_slice;
use cmac::{Cmac, Mac, digest::{typenum::{UInt, UTerm, B1, B0}, OutputSizeUser}};
use bytes::{BytesMut, BufMut};
use cipher::generic_array::GenericArray;
use std::{vec, fmt::Write, num::ParseIntError};

//hex!(stringName); //result will be bytes

#[derive(Debug, Default)]
pub struct she_hctx_t{
    total:  usize,
    len:    usize,
    blk:    GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>>,
    h:      GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>>,
    truncate: usize,
}

pub(crate) type profile_shc_t= she_hctx_t;

impl she_hctx_t{
    fn SHEHashInit(&mut self){
        (self.h).fill(0x00);
        (self.total)= 0;
        (self.len)= 0;
        (self.blk)= GenericArray::default();
        (self.truncate)= 16;
    }  
    fn SHEHashUpdate(&mut self, mut msg: &[u8]){
        let mut n: usize= msg.len();
        self.total += n;
        let mut sum = 0;
        if self.len!=0{
            if 16-self.len < n{(self.truncate)= 16-self.len;}else{(self.truncate)=n;}
            for i in 0..(self.truncate){
                self.blk[i]= msg[i];
            }
            self.len += (self.truncate);
            sum= (self.truncate);
            msg= &msg[sum..];
            n -= (self.truncate);
            if self.len == 16{
                self.h = mp_comp(&(self.blk[..self.truncate]), self.h);
                self.len= 0;
            }
        }
        if n!=0{
            self.h= mp_comp(msg, self.h);
            (self.truncate) = n % 16; //n%16
            sum = n - (self.truncate);
            msg = &msg[sum..];
            self.len= (self.truncate);
            for i in 0..(self.truncate){
                self.blk[i]= msg[i];
            }
        }
    }
    fn SHEHashFinal(&mut self)->GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>>{
        println!("{:#?}", &self.blk[..self.truncate]);
        return mp_comp(&pad(&self.blk[..self.truncate], self.total), self.h);
    }
}

fn hexout(var: &[u8]) -> String{    
    let mut new_label = String::new();    
    for d in var {        
        let x = format!("{:02x}", d);        
        new_label.push_str(&x);    
    }   
    //println!("{:?}", new_label);       
    return new_label;
}
fn mp_comp(mut m: &[u8], mut h: GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>>) -> GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>>{
    let (mut j, mut b): (usize, usize) = (0, 1);
    let mut ekm: GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>> = GenericArray::default();
    let mut cipher;  
    while  b <= m.len()>>4 {
        ekm.copy_from_slice(&m[((b-1)*16)..(b*16)]);
        cipher= <Aes128 as cipher::KeyInit>::new(&h);
        cipher.encrypt_block(&mut ekm);
        for j in 0..16{
            h[j] = h[j] ^ (ekm[j] ^ m[j+(16*(b-1))]);
        }
        b+=1;
    }
    return h;
}
fn pad(msg: &[u8], mut total: usize) -> Vec<u8> {
    let n= msg.len();
    if total == usize::MIN {total = n;}
    let r = msg.len() & 0xf;
    let z:usize;
    if r <= 10{z = 10 - r;}else{z = 26 - r;}
    let zero_vec: Vec<u8> = vec![0; z].to_owned();
    let mut vec = Vec::new();
    for iter in msg.to_owned(){vec.push(iter);}
    for iter in *b"\x80"{vec.push(iter);}
    for iter in zero_vec.to_owned(){vec.push(iter);}
    let i = total * 8; 
    for j in (0..5).rev(){vec.push(({i}>>({j}<<3) & 0xff).try_into().unwrap());}
    println!("{:#?}", vec.len());
    return vec;
}
fn cmac1(key: &[u8], msg: &[u8]) -> GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>>{
    let mut mac = Cmac::<Aes128>::new_from_slice(&key).unwrap();
    cmac::Mac::update(&mut mac, &msg);
    let result = cmac::Mac::finalize(mac);
    let tag_bytes = result.into_bytes();
    return tag_bytes;
}

pub(crate) fn CryptHashInit(pctx: &mut profile_shc_t){
    pctx.SHEHashInit();
}
pub(crate) fn CryptHashUpdate(pctx: &mut profile_shc_t, mut msg: &[u8]){
    pctx.SHEHashUpdate(msg);
}
pub(crate) fn CryptHashFinal(pctx: &mut profile_shc_t)->GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>>{
    //pctx.SHEHashFinal(dig);
    return pctx.SHEHashFinal();
}
fn CryptSelfTest(fulltest: bool)->bool{
    let mut i: usize;
    let key: Vec<u8>= vec![];
    let key: Vec<u8>= vec![];

    return true;
}
pub(crate) fn CryptSign(key: &[u8], msg: &[u8]) -> GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>>{
    return cmac1(&key, &msg);
}
pub(crate) fn CryptVerify(key: &[u8],digest: &[u8], sig: GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>>)  -> bool {
    let new_sig = CryptSign(key, digest);
    if new_sig == sig {return true;} return false;
}
pub(crate) fn CryptSkdf(parent: &[u8], label: char, ctx: &[u8])->GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>>{
    let mut hctx: she_hctx_t= she_hctx_t::default();
    hctx.SHEHashInit();
    hctx.SHEHashUpdate(parent);
    hctx.SHEHashUpdate(b"\x01\x01");
    //hctx.SHEHashUpdate(label);
    hctx.SHEHashUpdate(ctx);
    hctx.SHEHashUpdate(b"");
    return hctx.SHEHashFinal();
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn hash_func(){
        
        //let she_hctx_t = she_hctx_t::hctx();

        let  pshctx: &mut profile_shc_t= &mut profile_shc_t::default();
        CryptHashInit(pshctx);
        println!("{:#?}", pshctx.len);

        //bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
        let msg= hex!("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
        println!("This is message: {:#?}", msg);
        CryptHashUpdate(pshctx, &msg[0..4]);
        println!("{:#?} <-[0..4]", pshctx.len);
        CryptHashUpdate(pshctx, &msg[4..21]);
        println!("{:#?} <-[4..21]", pshctx.len);
        CryptHashUpdate(pshctx, &msg[21..32]);
        println!("{:#?} <-[21..32]", pshctx.len);
        println!("{:#?}", hexout(&CryptHashFinal(pshctx)[..]));

        

        //hcontext = CryptHashUpdate(hcontext, b"", n)
    }

    #[test]
    fn try_it(){
        let mut key: &GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>>
            = &GenericArray::clone_from_slice(b"AAAAAAAAAAAAAAAA"); 
        let message= b"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ";
        println!("{:#?}", hexout(&mp_comp(message, *key)[..]));



        println!("{}","\nCryptSign Function");
        //Test Vectors from Autosar SHE 
        let crypt_sign_result = CryptSign(b"+~\x15\x16(\xae\xd2\xa6\xab\xf7\x15\x88\t\xcfO<", b"k\xc1\xbe\xe2.@\x9f\x96\xe9=~\x11s\x93\x17*");
        println!("{}", hexout(&crypt_sign_result));

        println!("{}","\nCryptVerify Function");
        let bool_check = CryptVerify(b"+~\x15\x16(\xae\xd2\xa6\xab\xf7\x15\x88\t\xcfO<", b"k\xc1\xbe\xe2.@\x9f\x96\xe9=~\x11s\x93\x17*", crypt_sign_result);
        println!("{}", bool_check);
        
        //2b7e151628aed2a6abf7158809cf4f3c    = key
        //6bc1bee22e409f96e93d7e117393172a    = msg

        //hex!("2b7e151628aed2a6abf7158809cf4f3c")

        //pad tests  
        // for j in (0..20){     
        let test = &pad(b"\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB", usize::MIN)[..];
        println!("{:?}", hexout(test));

        //let cmaced = cmac1(&<[u8; 16]>::from_hex("2b7e151628aed2a6abf7158809cf4f3c"), &<[u8; 16]>::from_hex("2b7e151628aed2a6abf7158809cf4f3c"));
        println!("{:#?}", hex!("2b7e151628aed2a6abf7158809cf4f3c"));
        //let (hctx, msg): (she_hctx_t, &[u8])= CryptHashUpdate(hctx, msg);
    }
}
/*END OF SHE*/