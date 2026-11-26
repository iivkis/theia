//! Passive UDP classification. No integrity-field or encrypted-payload mutation.
use super::quic;
const COOKIE:[u8;4]=[0x21,0x12,0xa4,0x42];
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(crate) struct Stun { method:u16,class:u8,transaction:[u8;12] }
pub(crate) fn stun(data:&[u8])->Option<Stun>{
    let header=data.get(..20)?;
    let kind=u16::from_be_bytes([header[0],header[1]]);
    let len=usize::from(u16::from_be_bytes([header[2],header[3]]));
    if kind&0xc000!=0 || len%4!=0 || len+20!=data.len() || header[4..8]!=COOKIE {return None;}
    let mut rest=&data[20..];let mut count=0;
    while !rest.is_empty(){
        let h=rest.get(..4)?;let len=usize::from(u16::from_be_bytes([h[2],h[3]]));
        rest=rest.get(4+((len+3)&!3)..)?;
        count+=1;if count>256{return None;}
    }
    Some(Stun { method:(kind&0xf)|((kind>>1)&0x70)|((kind>>2)&0xf80),class:(((kind>>4)&1)|((kind>>7)&2)) as u8,transaction:header[8..20].try_into().ok()? })
}
impl Stun {
    pub(crate) fn matches_response(self,response:Self)->bool{
        self.class==0 && matches!(response.class,2|3) && self.method==response.method && self.transaction==response.transaction
    }
}
#[derive(Default)]
pub(crate) struct Observer { quic:quic::Observer, done:bool, request:Option<Stun> }
impl Observer {
    pub(crate) fn outgoing(&mut self,data:&[u8]){
        if self.done {return;}
        if let Some(message)=stun(data){
            self.request=Some(message);self.done=true;crate::traffic::udp_stun_flow();
        } else {
            match self.quic.observe(data) {
                quic::Result::Pending=>{},
                quic::Result::Hello=>{self.done=true;crate::traffic::udp_quic_flow();},
                quic::Result::Unsupported=>self.done=true,
            }
        }
    }
    pub(crate) fn incoming(&mut self,data:&[u8]){
        if self.request.is_some_and(|request|stun(data).is_some_and(|response|request.matches_response(response))){
            self.request=None;crate::traffic::udp_stun_response();
        }
    }
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn stun_lengths_padding_and_transaction(){
        let mut req=vec![0,1,0,0];req.extend(COOKIE);req.extend([7;12]);
        let mut res=req.clone();res[0]=1;
        assert!(stun(&req).unwrap().matches_response(stun(&res).unwrap()));
        res[19]^=1;assert!(!stun(&req).unwrap().matches_response(stun(&res).unwrap()));
        let mut attr=req.clone();attr[3]=8;attr.extend([0x80,0x22,0,1,b'x',0,0,0]);
        assert!(stun(&attr).is_some());attr[23]=9;assert!(stun(&attr).is_none());
        for n in 0..req.len(){assert!(stun(&req[..n]).is_none());}
        let mut observer=Observer::default();observer.outgoing(&req);res[19]^=1;observer.incoming(&res);assert!(observer.request.is_none());
    }
}
