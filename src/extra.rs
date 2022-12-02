



// use aes::Aes128;
// use aes::cipher::{BlockCipher, BlockEncrypt, BlockDecrypt, KeyInit, };
// use hex_literal::hex;
// use cmac::{Cmac, Mac, digest::{typenum::{UInt, UTerm, B1, B0}, OutputSizeUser}};

// use cipher::generic_array::GenericArray;

// fn mp_comp(mut m: &[u8], mut h: GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>>)-> GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>>{
//     let j: usize;
//     let mut b: usize= m.len() >> 4;
//     //let mut ekm= GenericArray::from([u8; 16]);
//     let mut ekm: GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>> = GenericArray::default();

//     //let mut ekm =  GenericArray<u8, <Aes128 as BlockSizeUser>::BlockSize>;
//     let cipher= Aes128::new(&h);

//     while  b>0 {
//         ekm.copy_from_slice(m);
//         cipher.encrypt_block(&mut ekm);
//         for j in 0..16{
//             h[j] ^= ekm[j] ^ m[j];
//         }
//         b-=1;
//     }

//     return h;
// }



// #[cfg(test)]
// mod tests {
//     use crate::mp_comp;
//     use cmac::{Cmac, Mac, digest::{typenum::{UInt, UTerm, B1, B0}, OutputSizeUser}};
//     use cipher::generic_array::GenericArray;

//     #[test]
//     fn try_it(){
//         let mut h: GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>>= GenericArray::clone_from_slice(b"TCG"); 
//         let mut hey = mp_comp(b"MARS", h);
    
//         let mut hexTagString = String::new();
//         for d in hey {
//             let x = format!("{:02x}", d);
//             hexTagString.push_str(&x);
//         }

//         println!("{}",hexTagString);

    
    
//     }
// }
      /*use std::vec;

    use cipher::typenum::{Len, Length};

    use super::*;


    fn print_2_hex(var: &[u8]) -> String{    
        let mut new_label = String::new();    
        for d in var {        
            let x = format!("{:02x}", d);        
            new_label.push_str(&x);    
        }   
        //println!("{:?}", var);       
        return new_label; //will display 5a}
    }

    fn cmac(key: &[u8], msg: &[u8]) -> GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>>{
        let mut mac = Cmac::<Aes128>::new_from_slice(&key).unwrap();
        mac.update(&msg);
        let result = mac.finalize();
        let tag_bytes = result.into_bytes();
        return tag_bytes;
    }

    //Modify this later
    fn cmac1(key: &[u8], msg: &[u8]) -> GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>>{
        let mut mac = Cmac::<Aes128>::new_from_slice(&key).unwrap();
        mac.update(&msg);
        let result = mac.finalize();
        let tag_bytes = result.into_bytes();
        return tag_bytes;
    }


    fn mp_comp(M: Vec<u8>, n: usize, H: Vec<u8>){
        let mut j = n >> 4;
        let mut b = n >> 4;
        let EkM: Vec<u8> = Vec::with_capacity(16); 
        while j <= b {
            for k in 0..15{
                // let mut H[k] = &EkM[k] ^ &M[k];
            }
            // M += 16;
            // decrement counter
            j -= 1;
        }*/
    
    // fn padc(mut msg: &[u8], mut total: usize) -> usize{

    //     let n= msg.len();
    //     if total==usize::MIN {
    //         total= n;
    //     }

    //     let r: usize= n + 0xf;
    //     let z:usize;
    //     if r <= 10 { z=10-r; } else { z=26-r; }

    //     msg = msg + n as u8;
    //     let mut temp= msg;
    //     temp=temp + 1;

    //     temp= 0x80 as [u8];

    //     msg[0..z].fill(0x0);

    //     msg+= z;
    //     total <<= 3;
    //     for i in 5..0{
    //         temp+=1;
    //         temp= (total as [u8]) >> (i<<3);
    //     }
    //     return n + 1 + z + 5;
    // }
/*
    fn pad(mut msg: &[u8], mut total: usize) -> String{
        let n= msg.len();
        println!("{}", msg.len());
        if total == usize::MIN {
           total = n;
        }
        let r = msg.len() + 0xf;
        println!("{}", r);
        let z:usize;
        if(r <= 10){
            z = 10 - r;
            println!("{}",z);
        }
        else{
            z = 26 - r;
            println!("{}",z);
        }
    
      // let mut _abc = vec![];
       let mut vec = Vec::new();
       let zero_vec = vec![0; z];
       
    
        vec.push(&msg[..]);
        vec.push(&b"\x80"[..]);
        vec.push(&zero_vec[..]);
    
        //let mut function_result:Vec<[usize; 1]> = Vec::new(); 
        let mut function_result: Vec<u8> = Vec::new(); 
        let i = total * 8; 
        for j in (0..4).rev(){     
            function_result.push(({i}>>({j}<<3) & 0xff).try_into().unwrap());
        }
        vec.push(&function_result[..]);

        // println!("{:?}", vec);
        
        //Concatenate the results together in one string to return
        let mut results: String = "".to_owned();
        results.push_str(&(print_2_hex(&msg[..])).to_owned());
        results.push_str(&(print_2_hex(b"\x80")).to_owned());
        results.push_str(&(print_2_hex(&zero_vec[..])).to_owned());
        results.push_str(&(print_2_hex(&function_result[..])).to_owned());

        // let function_result = function_result.to_be_bytes();
        return results.to_string();
    }

    fn CryptSign(key: &[u8],blk:&[u8]){

    }


    #[test]
    fn it_works() {
        // CMAC tests
        let key = hex!(
            "2b7e151628aed2a6abf7158809cf4f3c"
        );
        let msg = hex!(
            "6bc1bee22e409f96e93d7e117393172a"
        );
        let results = cmac(&key, &msg);
        
        let mut newLabel = String::new();
        for d in results {
            let x = format!("{:02x}", d);
            newLabel.push_str(&x);
        }
        println!("{}",newLabel); 

        //Hash tests  
        // for j in (0..20){     
        println!("{}",pad(b"\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB", usize::MIN));
        // }  

    }
}*/















/*use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyInit};
use aes::Aes128;
use anyhow::{Result, Error};
use cipher::generic_array::GenericArray;
use cipher::typenum::bit::{B1, B0};
use cipher::typenum::{UInt, UTerm};
use hex_literal::hex;
use std::vec::Vec;
use std::ops::Deref;

use cmac::{Cmac, Mac};
use substring::Substring;


//static mut BUF = [0u8; 48];

type Aes128EcbEnc = ecb::Encryptor<aes::Aes128>;
type Aes128EcbDec = ecb::Decryptor<aes::Aes128>;

fn encryptAesECB(key: [u8; 16], plaintext: [u8; 16])-> (Vec<u8>, [u8; 48]){
    let mut buf = [0u8; 48];
    let pt_len = plaintext.len();
    buf[..pt_len].copy_from_slice(&plaintext);
    let ct= Aes128EcbEnc::new(&key.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buf, pt_len)
        .unwrap();
    
    println!("{}", "Encrypt AES Function");
    println!("{:?}", ct);

    return (ct.to_vec(), buf);
}

fn decryptAesECB(key: [u8; 16], mut buf: [u8; 48])-> Vec<u8>{
    let mut buf = [0u8; 48];
    let pt = Aes128EcbDec::new(&key.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .unwrap();
    
    println!("{}", "Decrpyt AES Function");
    println!("{:?}", pt);

    return pt.to_vec();
}

/*fn pad(mut msg: u8, n: usize, total: usize) -> usize{
    let (i, r, z): usize;
    if !total{
        total= n;
    }
    r= n & 0xf;
    if r<10 {} else {}
    /*z= (r<10 ? 10: 26) - r;*/
    msg+= n;
    /* *msg++ = 0x80; */
    memset(msg, 0, z);
    msg+= z;
    total <<= 3;
    for i in 5 .. 3{
        /* *msg++ = total >> (i<<3); */
    }
    return n + 1 + z + 5;
    
}*/
// fn pad(mut msg: &[u8], mut total: usize) -> usize{
//     let n = msg.len();
//     if total==usize::MIN {
//         total= n;
//     }

//     let r: usize= n + 0xf;
//     let z:usize;
//if r <= 10 { z=10-r; } else { z=26-r; }

//     msg+= n as &[u8];
//     let mut temp= msg;
//     temp+=1;
//     temp= 0x80 as &[u8];

//     msg[0..z].fill(0x0);
    
//     msg+= z;
//     total <<= 3;
//     for i in 5..0{
//         temp+=1;
//         temp= (total as [u8]) >> (i<<3);
//     }

//     return n + 1 + z + 5;
// }
/* 
fn pad(mut msg: &[u8], mut total: usize) -> usize{

    let msg_convert = read_be_usize(&mut msg);

    let n= msg.len();
    if total==usize::MIN {
        total= n;
    }
    let r: usize= n + 0xf;
    let z:usize;
    if r <= 10 { z=10-r; } else { z=26-r; }

    let new_msg_convert = msg_convert + n;

    let mut temp= new_msg_convert;

    temp += 1;

    temp = 0x80;

    let check = temp as u8;
    let mut temp = [check];
    // for i in z{
    //     //temp[i] = 0; 
    // }

    //this is supposed to be temp
    temp[0..z].fill(0x0);

    //convert temp into usize
    
    temp += z;
    total <<= 3;
    for i in 5..0{
        temp+=1;
        temp= total >> (i<<3);
    }

    return n + 1 + z + 5;
}*/


/*
fn pad(mut msg: &[u8], mut total: usize) -> String{
        let n= msg.len();
        if total == usize::MIN {
           total = n;
        }
        let r = msg.len() + 0xf;

        let z:usize;
        if(r <= 10){
            z = 10 - r;
        }else{
            z = 26 - r;
        }
    
      // let mut _abc = vec![];
       let mut vec = Vec::new();
    
       let new_z = z.to_be_bytes();
    
         vec.push(&msg[..]);
         vec.push(&&b"\x80"[..]);
         vec.push(&new_z[..]);


        let mut function_result: Vec<u8> = Vec::new(); 
        let i = (total as u8) * 8; 
        for j in 0..5.rev(){
           // [i>>(j<<3) & 0xff]
            
             function_result.push(([i>>(j<<3) & 0xff]).as_bytes());
        }
         
     //   let mut function_result:Vec<[usize; 1]> = Vec::new(); 

        return "need to return generic array".to_string();
    }


    let mut function_result:Vec<[usize; 1]> = Vec::new(); 
    let i = total * 8; 
    
    for j in (0..5).rev(){
     //println!("{:?}", [i>>(j<<3) & 0xff]);    
     let maybe = [i>>(j<<3) & 0xff];
     println!("{:?}", maybe);    
      function_result.push([i>>(j<<3) & 0xff]);
 }*/




fn read_be_usize(input: &mut &[u8]) -> usize {
    let (int_bytes, rest) = input.split_at(std::mem::size_of::<usize>());
    *input = rest;
    usize::from_be_bytes(int_bytes.try_into().unwrap())
}



//m is message
//h is key*/
// fn mp_comp(mut m: &[u8], mut h: GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>>){
//     let j: usize;
//     let mut b: usize= m.len() >> 4;
//     let mut ekm: GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>> = GenericArray::default();
//     //let mut ekm =  GenericArray<u8, <Aes128 as BlockSizeUser>::BlockSize>;
//     let cipher= Aes128::new(&h);

//     while  b>0 {
//         ekm.copy_from_slice(m);
//         cipher.encrypt_block(&mut ekm);
//         for j in 0..16{
//             h[j] ^= ekm[j] ^ m[j];
//         }
//         b-=1;
//     }
// }







/*
fn pad(mut msg: &[u8], mut total: usize) -> String{
    let n= msg.len();
    if total == usize::MIN {
       total = n;
    }
    let r = msg.len() + 0xf;
    let z:usize;
    if(r <= 10){
        z = 10 - r;
    }
    else{
        z = 26 - r;
    }

  // let mut _abc = vec![];
   let mut vec = Vec::new();
   let zero_vec = vec![0; z];
   

    vec.push(&msg[..]);
    vec.push(&b"\x80"[..]);
    vec.push(&zero_vec[..]);

    //let mut function_result:Vec<[usize; 1]> = Vec::new(); 
    let mut function_result: Vec<u8> = Vec::new(); 
    let i = total * 8; 
    for j in (0..4).rev(){     
        function_result.push(({i}>>({j}<<3) & 0xff).try_into().unwrap());
    }
    vec.push(&function_result[..]);

    println!("{:?}", vec);
    print_2_hex(&msg[..]); 
    print_2_hex(b"\x80"); 
    print_2_hex(&zero_vec[..]); 
    print_2_hex(&function_result[..]); 


    // let function_result = function_result.to_be_bytes();
    return "need to return generic array".to_string();
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad(){
        let mut message: &[u8];
        let total: usize= 0;
        println!("{}", pad(message, total));

    }

    fn cmac_implement(){
        let plaintext: [u8; 16]= hex!("00112233445566778899aabbccddeeff");

        let key = hex!("000102030405060708090a0b0c0d0e0f");

        let (result_string, mut buf) = encryptAesECB(key, plaintext);
        

        let mut new_label = String::new();
        for d in result_string {
            let x = format!("{:02x}", d);
            new_label.push_str(&x);
        }
        new_label= (&new_label).substring(0, 32).to_string();

        println!("{}", new_label);

        let result_decrypt= decryptAesECB(key, buf);

        let mut newer = String::new();
        for d in result_decrypt {
            let x = format!("{:02x}", d);
            newer.push_str(&x);
        }

        println!("{}", newer);
    }
    /*fn aesTrial() {
 
        let key = hex!(
            "000102030405060708090a0b0c0d0e0f"
        );
        let plaintext = hex!(
            "00112233445566778899aabbccddeeff"
        );
        let ciphertext = hex!(
            "69c4e0d86a7b0430d8cdb78070b4c55a"
        );
        
        // encrypt/decrypt in-place
        // buffer must be big enough for padded plaintext
        let mut buf = [0u8; 48];
        let pt_len = plaintext.len();
        buf[..pt_len].copy_from_slice(&plaintext);
        let ct = Aes128EcbEnc::new(&key.into())
            .encrypt_padded_mut::<Pkcs7>(&mut buf, pt_len)
            .unwrap();
        
        let cut= (*ct).split(9);
        
        let mut newLabel = String::new();
        for d in ct {
            let x = format!("{:02x}", d);
            newLabel.push_str(&x);
        }
        println!("{}",newLabel); //will display 5a
        
        let pt = Aes128EcbDec::new(&key.into())
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .unwrap();
        let mut p= String::new();
        for d in pt {
                let x = format!("{:02x}", d);
                p.push_str(&x);
        }
        println!("{}", p);
    }
    */
    /*fn cmacTrial(){
        let mut mac = Cmac::<Aes128>::new_from_slice(b"very secret key.").unwrap();
        mac.update(b"input message");

        // `result` has type `Output` which is a thin wrapper around array of
        // bytes for providing constant time equality check
        let result = mac.finalize();
        // To get underlying array use the `into_bytes` method, but be careful,
        // since incorrect use of the tag value may permit timing attacks which
        // defeat the security provided by the `Output` wrapper
        let tag_bytes = result.into_bytes();
        let mut mac = Cmac::<Aes128>::new_from_slice(b"very secret key.").unwrap();

        mac.update(b"input message");

        // `verify` will return `Ok(())` if tag is correct, `Err(MacError)` otherwise
        mac.verify(&tag_bytes).unwrap();
    }*/

}






















//use aes::Aes128;
// use aes::cipher::{
//     BlockCipher, BlockEncrypt, BlockDecrypt, KeyInit,
//     generic_array::GenericArray,
// };


// pub fn hex_to_string(data: &[u8]) -> String {
//     let mut ret = String::new();

//     for d in data {
//         let x = format!("{:02x}", d);
//         ret.push_str(&x);
//     }

//     ret
// }



// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn sheAes(){
//         let key = GenericArray::from([0u8; 16]);
//         let mut block = GenericArray::from([42u8; 16]);
//         // Initialize cipher
//     let cipher = Aes128::new(&key);

//     let block_copy = block.clone();

//     // Encrypt block in-place
//     cipher.encrypt_block(&mut block);

//     // And decrypt it back
//     cipher.decrypt_block(&mut block);

//     let newString =  hex_to_string(&block);
//     println!("{:?}", block);
//     println!("{:?}", newString);
//     }
// }



*/
// use aes::Aes128;
// use hex_literal::hex;
// use cmac::{Cmac, Mac, digest::{generic_array::GenericArray, typenum::{UInt, UTerm, B1, B0}, OutputSizeUser}};
// use bytes::{BytesMut, BufMut};

// #[cfg(test)]
// mod tests {

//     use std::vec;

//     use cipher::typenum::{Len, Length};

//     use super::*;


//     fn convert_2_hex(var: &[u8]) -> String{    
//         let mut new_label = String::new();    
//         for d in var {        
//             let x = format!("{:02x}", d);        
//             new_label.push_str(&x);    
//         }   
//         //println!("{:?}", var);       
//         return new_label; //will display 5a}
//     }

//     fn cmac(key: &[u8], msg: &[u8]) -> GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>>{
//         let mut mac = Cmac::<Aes128>::new_from_slice(&key).unwrap();
//         mac.update(&msg);
//         let result = mac.finalize();
//         let tag_bytes = result.into_bytes();
//         return tag_bytes;
//     }

//     //Modify this later
//     fn cmac1(key: &[u8], msg: &[u8]) -> GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>>{
//         let mut mac = Cmac::<Aes128>::new_from_slice(&key).unwrap();
//         mac.update(&msg);
//         let result = mac.finalize();
//         let tag_bytes = result.into_bytes();
//         return tag_bytes;
//     }


//     fn mp_comp(h: &mut[u8], msg: &[u8]){
//         let j: usize;
//         let mut b: usize= msg.len() >> 4;
//         //let mut ekm= GenericArray::from([u8; 16]);
//         let ekm: GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>> = GenericArray::default();
    
//         //let mut ekm =  GenericArray<u8, <Aes128 as BlockSizeUser>::BlockSize>;
        
//         while  b>0 {
//             println!("Before: {},  {:#?}", b, msg);
//             cmac1(&h, &msg);
//             println!("After: {},  {:#?}", b, msg);
//             for j in 0..16{
//                 h[j] ^= ekm[j] ^ msg[j];
//                 println!("Inside For Loop {},  {:#?}", j, h[j]);
//             }
//             b-=1;
//         }
//         let mut new_label = String::new();    
//         for d in h {        
//             let x = format!("{:02x}", d);        
//             new_label.push_str(&x);    
//         }   
//         println!("{:?}", new_label);   
//     }
//     #[test]
//     fn it_works() {
//         //mpcomp tests (not finished)
//         let mut key = BytesMut::with_capacity(64);
//         key.put(&b"AAAAAAAAAAAAAAAA"[..]);
//         let msg: &[u8]= b"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ";
//         println!("{:#?}", key);
//         mp_comp(&mut key, msg);
//     }
// }
