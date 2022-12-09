/*SHE import*/
//mod hw_she;
//use hw_she::{profile_shc_t, CryptHashInit, CryptHashUpdate, CryptHashFinal};

/*SHA2 import*/
mod hw_sha2;
use hw_sha2::{profile_shc_t, CryptHashInit, CryptHashUpdate, CryptHashFinal, CryptSign, CryptVerify, CryptXkdf, CryptSelfTest};

/*Ascon import*/
//mod hw_ascon;
//use hw_ascon::{profile_shc_t, CryptHashInit, CryptHashUpdate, CryptHashFinal, CryptSign, CryptVerify, CryptXkdf};


use aes::Aes128;
use aes::cipher::{BlockCipher, BlockEncrypt, BlockDecrypt, };
use hex_literal::hex;
//use hex::decode_to_slice;
//use cmac::{Cmac, Mac, digest::{typenum::{UInt, UTerm, B1, B0}, OutputSizeUser}};
use bytes::{BytesMut, BufMut};


//use cipher::generic_array::GenericArray;
use std::{vec, fmt::Write, num::ParseIntError};
use sha2::{Sha256VarCore, OidSha256};
pub use sha2::{Digest, Sha256};
use hmac::{Hmac, Mac, digest::{generic_array::GenericArray, typenum::{UInt, B1, UTerm, B0}, core_api::{CtVariableCoreWrapper, CoreWrapper}}};

const MARS_PT_PCR:          u16= 1;
const MARS_PT_TSR:          u16= 2;
const MARS_PT_LEN_DIGEST:   u16= 3;
const MARS_PT_LEN_SIGN:     u16= 4;
const MARS_PT_LEN_KSYM:     u16= 5;
const MARS_PT_LEN_KPUB:     u16= 6;
const MARS_PT_LEN_KPRV:     u16= 7;
const MARS_PT_ALG_HASH:     u16= 8;
const MARS_PT_ALG_SIGN:     u16= 9;
const MARS_PT_ALG_SKDF:     u16= 10;
const MARS_PT_ALG_AKDF:     u16= 11;

type MARS_RC = u16;

const MARS_RC_SUCCESS:  MARS_RC= 0;
const MARS_RC_IO:       MARS_RC= 1;
const MARS_RC_FAILURE:  MARS_RC= 2;
//reserved                       3
const MARS_RC_BUFFER:   MARS_RC= 4;
const MARS_RC_COMMAND:  MARS_RC= 5;
const MARS_RC_VALUE:    MARS_RC= 6;
const MARS_RC_REG:      MARS_RC= 7;
const MARS_RC_SEQ:      MARS_RC= 8;


//IMPORTED VALUES      DO NOT KEEP
//ADD IN HARDWARE CRYPT ALGORITHMS
const PROFILE_COUNT_PCR:  usize= 4;
const PROFILE_COUNT_TSR:  usize= 0;
const PROFILE_LEN_DIGEST: usize= 32;
const PROFILE_COUNT_REG:  usize= (PROFILE_COUNT_PCR as usize)+ (PROFILE_COUNT_TSR as usize); //?????
const PROFILE_LEN_XKDF:   usize= 7;
const PROFILE_LEN_SIGN:   usize= PROFILE_LEN_DIGEST;
const PROFILE_LEN_KPUB:   usize= 0;
const PROFILE_LEN_KPRV:   usize= 0;
const PROFILE_ALG_HASH:   usize= 11;
const PROFILE_ALG_SIGN:   usize= 5;
const PROFILE_ALG_SKDF:   usize= 34;
const PROFILE_ALG_AKDF:   usize= 0;





const PROFILE_LEN_KSYM:   usize= PROFILE_LEN_DIGEST;

//#define PROFILE_LEN_KSYM   PROFILE_LEN_DIGEST
//#define PROFILE_LEN_SIGN   PROFILE_LEN_DIGEST

const MARS_LX:             [u8; 1]= *b"X";
const MARS_LD:             [u8; 1]= *b"D";
const MARS_LU:             [u8; 1]= *b"U";
const MARS_LR:             [u8; 1]= *b"R";



#[derive(Default)]
pub struct MARS{
    debug: bool,
    failure: bool,
    REG: [Vec<u8>; PROFILE_COUNT_PCR as usize],
    DP: Vec<u8>,
    PS: Vec<u8>,
    RC_CODE: MARS_RC,
    pctx: profile_shc_t,
}
impl MARS{
    fn MARS_init(&mut self, 
        debug: bool){
        self.debug= debug;
        self.failure= false;
        //self.REG= [; PROFILE_COUNT_PCR as usize];
        self.RC_CODE= 0;
        if PROFILE_LEN_KSYM==16{
            //self.PS= *b"A 16-byte secret";
        }else{
            self.PS= (b"Here are thirty two secret bytes").to_vec();
        }
        let mut temp: GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>>= GenericArray::default();
        if debug{
            temp= CryptXkdf(&self.PS, &MARS_LD[..], b"dbg");
            for i in 0..PROFILE_LEN_KSYM{   
                self.DP[i]= temp[i];    
            }

        }else{
            temp= CryptXkdf(&self.PS, &MARS_LD[..], b"prd");
            for i in 0..PROFILE_LEN_KSYM{   
                self.DP[i]= temp[i];    
            } 
        }
    }
    
    fn MARS_dump(&mut self){
        println!("--------------------------");
        println!("MARS PRIVATE CONFIGURATION");
        println!("{}", hexout(&self.PS));
        println!("{}", hexout(&self.DP));
        for i in &self.REG{
            println!("{}", hexout(&i));
        }
        println!("--------------------------");
    }
    fn MARS_SelfTest(&mut self,
            fullTest: bool
        ) -> MARS_RC{
        self.failure= self.failure || !CryptSelfTest(fullTest);
        if self.failure{
            return MARS_RC_FAILURE;
        }else{
            return MARS_RC_SUCCESS;
        }
    }
    
    fn MARS_CapabilityGet(
        &mut self,
        pt: u16,
        cap: &mut u16
        )-> MARS_RC{
        *cap = match pt{
            MARS_PT_PCR         =>PROFILE_COUNT_PCR as u16,
            MARS_PT_TSR         =>PROFILE_COUNT_TSR as u16,
            MARS_PT_LEN_DIGEST  =>PROFILE_LEN_DIGEST as u16,
            MARS_PT_LEN_SIGN    =>PROFILE_LEN_SIGN as u16,
            MARS_PT_LEN_KSYM    =>PROFILE_LEN_KSYM as u16,
            MARS_PT_LEN_KPUB    =>PROFILE_LEN_KPUB as u16,
            MARS_PT_LEN_KPRV    =>PROFILE_LEN_KPRV as u16,
            MARS_PT_ALG_HASH    =>PROFILE_ALG_HASH as u16,
            MARS_PT_ALG_SIGN    =>PROFILE_ALG_SIGN as u16,
            MARS_PT_ALG_SKDF    =>PROFILE_ALG_SKDF as u16,
            MARS_PT_ALG_AKDF    =>PROFILE_ALG_AKDF as u16,
            _=>return MARS_RC_VALUE,
        };
        return MARS_RC_SUCCESS;
    }

    fn MARS_SequenceHash(&mut self) -> MARS_RC{
        if self.failure {
            return MARS_RC_FAILURE;
        }
        CryptHashInit(&mut self.pctx);
        return MARS_RC_SUCCESS;
    }

    fn MARS_SequenceUpdate(&mut self, inVal: &[u8], out: &[u8]) -> MARS_RC{
        if self.failure {
            return MARS_RC_FAILURE;
        }
        if inVal.len()==0 || out.len() == 0 {
            return MARS_RC_BUFFER;
        }
        CryptHashUpdate(&mut self.pctx, inVal);
        return MARS_RC_SUCCESS;
    }
    
    fn MARS_SequenceComplete(&mut self, out: &mut Vec<u8>) -> MARS_RC{
        if self.failure {
            return MARS_RC_FAILURE;
        }
        if (out.len()==0 || (&out.len() < &PROFILE_LEN_DIGEST)){
            return MARS_RC_BUFFER;
        }
        *out= CryptHashFinal(&mut self.pctx).to_vec();
        return MARS_RC_SUCCESS;
    }

    fn MARS_Derive(&mut self, 
        regSelect: u32, 
        ctx: &[u8], 
        out: &mut Vec<u8>
        ) -> MARS_RC{

        if self.failure{
            return MARS_RC_FAILURE;
        }
        if regSelect>>PROFILE_COUNT_REG==0{
            return MARS_RC_REG;
        }
        if out.len()==0 || ctx.len()==0{
            return MARS_RC_BUFFER;
        }
        let snapshot= self.CryptSnapshot(regSelect, ctx);
        *out= CryptXkdf(&self.DP, &MARS_LX, &snapshot).to_vec();
        return MARS_RC_SUCCESS;
    }
    fn MARS_DpDerive(&mut self,
        regSelect: u32,
        ctx: &[u8],
        ) -> MARS_RC{
            if self.failure{
                return MARS_RC_FAILURE;
            }
            if regSelect>>PROFILE_COUNT_REG==0{
                return MARS_RC_REG;
            }
            if ctx.len()==0{
                return MARS_RC_BUFFER;
            }
            if ctx.len()!=0{
                let snapshot= self.CryptSnapshot(regSelect, ctx);
                let temp= CryptXkdf(&self.DP, &MARS_LD, &snapshot);
                for i in 0..PROFILE_LEN_KSYM{   
                    self.DP[i]= temp[i];    
                }
            }
                

            return MARS_RC_SUCCESS;
    }
    fn CryptSnapshot(&mut self, 
        regSelect: u32, 
        ctx: &[u8]
        ) -> Vec<u8>{
        
        let pctx: &mut profile_shc_t= &mut profile_shc_t::default();
        
        CryptHashInit(pctx);
        CryptHashUpdate(pctx, &regSelect.to_be_bytes());
        for i in 0..PROFILE_COUNT_REG{
            if (regSelect & (1<<i)) !=0{
               CryptHashUpdate(pctx, &self.REG[i]);
            }
        }
        CryptHashUpdate(pctx, ctx);
        return CryptHashFinal(pctx).to_vec();
    }
    
    fn MARS_PcrExtend(&mut self, 
        pcrIndex: u16, 
        dig: &[u8]
        ) -> MARS_RC{
        if self.failure {
            return MARS_RC_FAILURE; //0
        }  
        if pcrIndex >= PROFILE_COUNT_PCR as u16{
            return MARS_RC_REG; //7
        }
        if dig.len()==0{
            return MARS_RC_BUFFER; //4
        }
        let pctx: &mut profile_shc_t= &mut profile_shc_t::default();
        CryptHashInit(pctx);                                                                                         
        CryptHashUpdate(pctx, &self.REG[pcrIndex as usize][..]);
        CryptHashUpdate(pctx, dig);
        self.REG[pcrIndex as usize].copy_from_slice(&CryptHashFinal(pctx)[..]);
        return MARS_RC_SUCCESS; //0
    }
    
    fn MARS_Quote(&mut self, 
        regSelect: u32, 
        nonce: &[u8], 
        ctx: &[u8], 
        sig: &mut GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>>
        ) -> MARS_RC{
        if self.failure{
            return MARS_RC_FAILURE;
        }
        if (regSelect>>PROFILE_COUNT_REG)!=0{
            return MARS_RC_REG;
        }
        if (nonce.len()==0) || ctx.len()==0 || sig.len()==0{
            return MARS_RC_BUFFER;
        }
        let snapshot= self.CryptSnapshot(regSelect, nonce);
        let AK= CryptXkdf(&self.DP, &MARS_LR, ctx);
        println!("Snapshot {}", hexout(&snapshot));
        println!("AK {}", hexout(&AK));
        *sig= CryptSign(&AK, &snapshot);
        return MARS_RC_SUCCESS;
    }
    
    fn MARS_RegRead(&mut self, regIndex: usize, 
        dig: &mut GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>>
        ) -> MARS_RC{
        if self.failure {  return MARS_RC_FAILURE; }
        if regIndex >= PROFILE_COUNT_REG { return MARS_RC_REG; }
        if dig.len()==0 {   return MARS_RC_BUFFER;   }
        let mut i=0;
        for j in &self.REG[regIndex]{
            dig[i]= *j;
            i+=1;
        }
        return MARS_RC_SUCCESS;
    }
    
    fn MARS_Sign(&mut self, 
            ctx: &[u8], 
            dig: &[u8], 
            sig: &mut GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>>
        ) -> MARS_RC{    
                  
        if self.failure{ 
            return MARS_RC_FAILURE;  
        }
        if !(dig.len()!=0 || sig.len()!=0) || (ctx.len()==0){
            return MARS_RC_BUFFER;
        }
        let key= CryptXkdf(&self.DP, &MARS_LU, ctx);
        *sig = CryptSign(&key,dig);
        return MARS_RC_SUCCESS;
    }

    fn MARS_SignatureVerify(&mut self, 
            restricted: bool,
            ctx: &[u8], 
            dig: &[u8], 
            sig: GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>>, 
            result: &mut bool
        ) -> MARS_RC{
                
        if(self.failure){
            return MARS_RC_FAILURE;       
        }
        if !(dig.len()!=0 ||sig.len()!=0 || *result) || !(ctx.len()!=0){
            return MARS_RC_BUFFER;
        }
        let mut label= MARS_LU;
        if restricted{ 
            label= MARS_LR;
        }
        let key= CryptXkdf(&self.DP, &label, ctx);
        *result= CryptVerify(&key, dig, sig);
        return MARS_RC_SUCCESS;
    }
}






// //SHA2.H file initialized variables
//PROFILE_COUNT_REG  = (PROFILE_COUNT_PCR + PROFILE_COUNT_TSR)
//PROFILE_COUNT_PCR  = 4
//PROFILE_COUNT_TSR  = 0
//PROFILE_LEN_DIGEST = SHA256_DIGEST_LENGTH
//static REG: u8 = [4][6];      //6 because "PYTHON" 6 letters

  /****************************/
 //static REG: [[u8; PROFILE_COUNT_PCR]; PROFILE_LEN_DIGEST];
/***************************/
pub fn hexout(data: &[u8]) -> String {
    let mut ret = String::new();

    for d in data {
        let x = format!("{:02x}", d);
        ret.push_str(&x);
    }
    return ret
}



#[cfg(test)]
mod testing {
    use super::*;

    #[test]
    fn mars_test(){
        let digest: &mut GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>>= &mut GenericArray::default();
        let debug= true;
        let mut MARS_RUNNER: MARS = MARS::default();
        MARS_RUNNER.MARS_init(debug);

        for i in 0..PROFILE_COUNT_PCR+1{
            MARS_RUNNER.RC_CODE= MARS_RUNNER.MARS_PcrExtend(0, b"trusted computing"); 
            MARS_RUNNER.RC_CODE= MARS_RUNNER.MARS_RegRead(0, digest);
            //println!("MARS_RC: {}\t REG[{}]: {:#?}", RC_CODE, 0, hexout(&REG[0]));
            println!("MARS_RC: {}\t REG[{}]: {:#?}", MARS_RUNNER.RC_CODE, 0, hexout(&digest));
        }
    }
    
    #[test]
    fn mars_snapshot(){
        let mut MARS_RUNNER: MARS = MARS::default();
        let debug=true;
        MARS_RUNNER.MARS_init(debug);

        //let str1 = MARS_RUNNER.CryptSnapshot(0b101, b"");
        let mut dig: GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>>= GenericArray::default();
        //println!("{}",hexout(&str1));
        let mut sig: &mut GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>>= &mut GenericArray::default(); 
        MARS_RUNNER.RC_CODE= MARS_RUNNER.MARS_Quote(0,b"N", b"Maryland", &mut sig);
        println!("{}", hexout(&sig[..]));
        
        println!("{}", hexout(&dig));
    }
    #[test]
    fn mars_sig_and_verify(){
        let mut MARS_RUN: MARS= MARS::default();
        let debug= true;
        MARS_RUN.MARS_init(debug);
        let mut sign: &mut GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>>= &mut GenericArray::default(); 
        let mut result: &mut bool= &mut false;
        let restricted= false;
        MARS_RUN.RC_CODE= MARS_RUN.MARS_Sign(b"Hello" ,b"DIGEST" , &mut sign);  
        println!("{} {}", MARS_RUN.RC_CODE, hexout(&sign));
        MARS_RUN.RC_CODE= MARS_RUN.MARS_SignatureVerify(restricted, b"Hello" ,b"DIGEST" , *sign, &mut result);
        println!("{} {}", MARS_RUN.RC_CODE, result);
    }




}
/*END OF MARS*/
