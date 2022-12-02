/*SHE*/
use aes::Aes128;
use hex_literal::hex;
use cmac::{Cmac, Mac, digest::{generic_array::GenericArray, typenum::{UInt, UTerm, B1, B0}, OutputSizeUser}};
use bytes::{BytesMut, BufMut};
use std::vec::IntoIter;

#[derive(Debug, Default)]
pub struct she_hctx_t{
    total: usize,
    len: usize,
    blk: Vec<u8>,
    h: GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>>,
}

type profile_shc_t= she_hctx_t;


impl she_hctx_t{

    fn SHE_Init(&mut self){
        (self.h).fill(0x0);
        (self.total)= 0;
        (self.len)= 0;
        (self.blk)= vec![0;32];
    }  
    
    fn SHE_Update(&mut self, mut msg: &[u8]){
        let mut pn: usize; 
        let mut n = msg.len();
        self.total += n;
        
        if self.len != 0 {                
            if 16-self.len < n{
                pn = 16-self.len;
            }
            else{
                pn = n;
            }
            
            
            for i in 0..pn{
                self.blk[self.len + i] = msg[i];
            }
            
            self.len += pn;
            msg = &msg[pn..];
            
            n -= pn;
            
            if self.len == 16 { // blk is full, compress it
                self.h= mp_comp(msg.to_vec(), n, self.h);
                self.len= 0;
            }
        }

        if n != 0 {
            self.h= mp_comp(msg.to_vec(), n, self.h);
            
            pn = n & 0xf; //n%16
            let sum = n - pn;
            msg = &msg[sum..];

            self.len= pn;
            for i in 0..pn{
                self.blk[i]= msg[i];
            }
        }

    }

    fn SHE_Final(&mut self) -> GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>>{
        pad(self);
        return mp_comp(self.blk.to_vec(), self.len , self.h)
    }
}

fn hexout(var: &[u8]) -> String{    
    let mut new_label = String::new();    
    for d in var {        
        let x = format!("{:02x}", d);        
        new_label.push_str(&x);    
    }          
    return new_label; //will display 5a}
}

//CMAC to encrypt the message block
fn cmac1(key: &[u8], msg: &[u8]) -> GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>>{
    let mut mac = Cmac::<Aes128>::new_from_slice(&key).unwrap();
    mac.update(&msg);
    let result = mac.finalize();
    let tag_bytes = result.into_bytes();
    return tag_bytes;
}


fn mp_comp(m: Vec<u8>, len: usize, mut h: GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>>) -> GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>>{
    let (mut b, mut m_count): (usize, usize) = (len>>4, 1);
    let mut ekm = GenericArray::default();
    let mut cipher;  
    
    while  b > 0 {
        cipher= <Aes128 as cipher::KeyInit>::new(&h);
        ekm.copy_from_slice(&m[((m_count-1)*16)..(m_count*16)]);
        cipher::BlockEncrypt::encrypt_block(&cipher, &mut ekm);
        for j in 0..16{
            h[j] = h[j] ^ (ekm[j] ^ m[j + (16 * (m_count - 1))]);
        }
        b-=1;
        m_count+=1;
    }
    // println!("{}",h.len());
    return h;
}


fn pad(hctx: &mut she_hctx_t) {
    let n= hctx.len;
    if hctx.total == 0 {
        hctx.total = n;
    }
    let r = n & 0xf;
    let z:usize;
    if r <= 10{
        z = 10 - r;
    }
    else{
        z = 26 - r;
    }
    hctx.blk[hctx.len] = 0x80;
    hctx.len +=1;
    for j in 0..z{
        hctx.blk[hctx.len + j] = 0;
    }
    hctx.len += z;
    let bits = hctx.total << 3;
    for j in 0..5{
        hctx.blk[hctx.len + (4-j)] = ({bits}>>({j}<<3) & 0xff).try_into().unwrap();
    }
    hctx.len += 5;
}

pub (crate) fn CryptSign(key: &[u8], msg: &[u8]) -> GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>>{
    return cmac1(&key, &msg);
}

pub (crate) fn CryptVerify(key: &[u8], digest: &[u8], sig: GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>>)  -> bool {
    let new_sig = CryptSign(key, digest);
    if new_sig == sig {
        return true;
    }
    return false;
}

fn SHE_kdf(parent:&[u8], label:&[u8], ctx:&[u8]) -> Vec<u8> {
    let pctx: &mut profile_shc_t= &mut profile_shc_t::default();
    CryptHashInit(pctx);
    CryptHashUpdate(pctx, parent);
    CryptHashUpdate(pctx, b"\x01\x01");
    CryptHashUpdate(pctx, label);
    CryptHashUpdate(pctx, ctx);
    CryptHashUpdate(pctx, b"\x00");
    return CryptHashFinal(pctx).to_vec()
}

fn CryptSkdf(parent:&[u8], label:&[u8], ctx:&[u8]) -> Vec<u8>{
    SHE_kdf(parent, label, ctx)
}

pub (crate) fn CryptXkdf( parent:&[u8], label:&[u8], ctx:&[u8]) -> Vec<u8>{
    CryptSkdf(parent, label, ctx)
}

pub(crate) fn CryptHashInit(pctx: &mut profile_shc_t){
    pctx.SHE_Init();
}

pub(crate) fn  CryptHashUpdate(pctx: &mut profile_shc_t, data: &[u8]){
    pctx.SHE_Update(data);
}

pub(crate) fn CryptHashFinal(pctx: &mut profile_shc_t)-> GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>>{
    return pctx.SHE_Final(); 
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        // CMAC1 test
        println!("CMAC test");
        let key = hex!(
            "2b7e151628aed2a6abf7158809cf4f3c"
        );
        let msg = hex!(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
        );
        let results = cmac1(&key, &msg);
        hexout(&results);

        //Test Vectors from Autosar SHE 
        //CryptSign
        println!("{}","\nCryptSign Function");
        let crypt_sign_result = CryptSign(b"+~\x15\x16(\xae\xd2\xa6\xab\xf7\x15\x88\t\xcfO<", b"k\xc1\xbe\xe2.@\x9f\x96\xe9=~\x11s\x93\x17*");
        println!("{}", hexout(&crypt_sign_result));
        
        //CryptVerify
        println!("{}","\nCryptVerify Function");
        let bool_check = CryptVerify(b"+~\x15\x16(\xae\xd2\xa6\xab\xf7\x15\x88\t\xcfO<", b"k\xc1\xbe\xe2.@\x9f\x96\xe9=~\x11s\x93\x17*", crypt_sign_result);
        println!("{}", bool_check);

        //Hash Sequence Test
        println!("{}","\nHash Sequence Function");
        let pshctx: &mut profile_shc_t= &mut profile_shc_t::default();
        for i in 0..30{
            CryptHashInit(pshctx);
            let msg= b"Z".repeat(i);
            CryptHashUpdate(pshctx, &msg);
            let dig = CryptHashFinal(pshctx);
            println!("{} {}", i, hexout(&dig));
        }

        //SHE_KDF test taken from https://github.com/TrustedComputingGroup/MARS/blob/fe892024c80baa50603fca4caea2b67eb43a29dc/emulator/python/hw_she.py
        println!("{}","\nSHE_KDF Test");
        let key = hex!("000102030405060708090a0b0c0d0e0f");
        let exp = hex!("118a46447a770d87828a69c222e2d17e");
        let out = CryptSkdf(&key, b"SHE", b"");
        assert_eq!(out,exp);
        println!("SKDF = {}",hexout(&out));

    }
}
/*END OF SHE*/