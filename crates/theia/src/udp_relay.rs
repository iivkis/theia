//! SOCKS5 datagrams and bounded per-destination relay. All socket I/O is
//! ordinary Tokio UDP; no raw packet access. One pinned target per flow.
use crate::{client::ClientError,protocol::{self,Address,ErrorCode,Frame}};
use std::{io,net::{IpAddr,SocketAddr},sync::Mutex,time::Duration};
use tokio::{net::UdpSocket,sync::mpsc,time::{Instant,timeout,sleep_until}};

pub(crate) const MAX_FLOWS:usize=8;
pub(crate) const QUEUE:usize=8;
const IDLE:Duration=Duration::from_secs(30);
const LIFETIME:Duration=Duration::from_secs(600);
pub(crate) struct Activity { last:Mutex<Instant>, end:Instant }
impl Activity {
    pub(crate) fn new()->Self { let now=Instant::now(); Self { last:Mutex::new(now),end:now+LIFETIME } }
    pub(crate) fn touch(&self){ *self.last.lock().unwrap_or_else(|e|e.into_inner())=Instant::now(); }
    fn deadline(&self)->Instant { (*self.last.lock().unwrap_or_else(|e|e.into_inner())+IDLE).min(self.end) }
    pub(crate) async fn expire(&self){ loop { sleep_until(self.deadline()).await; if Instant::now()>=self.deadline(){return;} } }
}
pub(crate) enum Target { Tcp(tokio::net::TcpStream), Udp(UdpSocket) }
pub(crate) async fn connect(address:SocketAddr)->io::Result<UdpSocket>{
    let bind=if address.is_ipv4() {"0.0.0.0:0"} else {"[::]:0"};
    let socket=UdpSocket::bind(bind).await?;
    socket.connect(address).await?;
    if socket.peer_addr()?!=address {return Err(io::Error::other("UDP peer mismatch"));}
    Ok(socket)
}
pub(crate) async fn send_datagram(socket:&UdpSocket,data:&[u8])->io::Result<()>{
    if data.len()>protocol::MAX_DATAGRAM || socket.send(data).await?!=data.len(){return Err(io::Error::from(io::ErrorKind::InvalidData));}
    Ok(())
}
pub(crate) async fn direct(address:Address,port:u16,pinned:Option<Vec<IpAddr>>)->Result<UdpSocket,ClientError>{
    if port==0{return Err(ClientError::Protocol);}
    timeout(Duration::from_secs(15),async {
        let candidates:Vec<SocketAddr>=if let Some(ips)=pinned {ips.into_iter().map(|ip|SocketAddr::new(ip,port)).collect()} else {
            match address {
                Address::V4(ip)=>vec![SocketAddr::from((ip,port))],
                Address::V6(ip)=>vec![SocketAddr::from((ip,port))],
                Address::Dns(name)=>tokio::net::lookup_host((name.as_str(),port)).await.map_err(|_|ClientError::Open(ErrorCode::DialFailed))?.take(65).collect(),
            }
        };
        if candidates.len()>64 {return Err(ClientError::Open(ErrorCode::ResourceLimit));}
        for addr in candidates {
            if addr.ip().is_unspecified() || addr.ip().is_multicast() || addr.ip()==IpAddr::V4(std::net::Ipv4Addr::BROADCAST) {continue;}
            if let Ok(socket)=connect(addr).await{return Ok(socket);}
        }
        Err(ClientError::Open(ErrorCode::DialFailed))
    }).await.map_err(|_|ClientError::Open(ErrorCode::DialTimeout))?
}
pub(crate) enum Tunnel { Direct(UdpSocket), H2(Box<crate::client::Tunnel>), H3(Box<crate::h3_client::H3Tunnel>) }
impl Tunnel {
    pub(crate) async fn relay(self,mut upload:mpsc::Receiver<Vec<u8>>,download:mpsc::Sender<Vec<u8>>)->Result<(),ClientError>{
        match self {
            Self::H2(t)=>t.relay_udp(upload,download).await,
            Self::H3(t)=>t.relay_udp(upload,download).await,
            Self::Direct(socket)=>{
                let traffic=crate::traffic::enter_udp(crate::Role::Client,false,true);
                let activity=Activity::new();
                let send=async {
                    while let Some(data)=upload.recv().await {
                        send_datagram(&socket,&data).await.map_err(|_|ClientError::Io)?;
                        traffic.upload(data.len());
                        activity.touch();
                    }
                    Ok::<(),ClientError>(())
                };
                let receive=async {
                    let mut buf=vec![0;protocol::MAX_DATAGRAM+1];
                    loop {
                        let n=socket.recv(&mut buf).await.map_err(|_|ClientError::Io)?;
                        if n>protocol::MAX_DATAGRAM {continue;}
                        download.send(buf[..n].to_vec()).await.map_err(|_|ClientError::Io)?;
                        traffic.download(n);
                        activity.touch();
                    }
                    #[allow(unreachable_code)]
                    Ok::<(),ClientError>(())
                };
                tokio::select! { result=send=>result, result=receive=>result, ()=activity.expire()=>Ok(()) }
            }
        }
    }
}
pub(crate) fn valid_associate(address:&Address,peer:IpAddr)->bool {
    let ip:IpAddr=match address {Address::V4(ip)=>(*ip).into(),Address::V6(ip)=>(*ip).into(),Address::Dns(_)=>return false};
    ip.is_unspecified() || ip==peer
}
fn encode_address(out:&mut Vec<u8>,address:&Address,port:u16){
    match address { Address::V4(ip)=>{out.push(1);out.extend(ip)}, Address::V6(ip)=>{out.push(4);out.extend(ip)}, Address::Dns(name)=>{out.push(3);out.push(name.len() as u8);out.extend(name.as_bytes())} }
    out.extend(port.to_be_bytes());
}
pub(crate) fn associate_reply(bound:SocketAddr)->Vec<u8> {
    let mut out=vec![5,0,0];
    let addr=match bound.ip(){IpAddr::V4(ip)=>Address::V4(ip.octets()),IpAddr::V6(ip)=>Address::V6(ip.octets())};
    encode_address(&mut out,&addr,bound.port());out
}
pub(crate) fn parse_socks(bytes:&[u8])->Option<(Address,u16,&[u8])>{
    if bytes.get(..3)?!=[0,0,0]{return None;} // RFC 1928 FRAG unsupported
    let (address,end)=match *bytes.get(3)? {
        1=>(Address::V4(bytes.get(4..8)?.try_into().ok()?),8),
        4=>(Address::V6(bytes.get(4..20)?.try_into().ok()?),20),
        3=>{let n=usize::from(*bytes.get(4)?);let name=std::str::from_utf8(bytes.get(5..5+n)?).ok()?; (Address::Dns(name.to_ascii_lowercase()),5+n)},
        _=>return None
    };
    let port=u16::from_be_bytes(bytes.get(end..end+2)?.try_into().ok()?);
    let data=bytes.get(end+2..)?;
    if data.len()>protocol::MAX_DATAGRAM || protocol::encode(&Frame::OpenUdp{address:address.clone(),port}).is_err(){return None;}
    Some((address,port,data))
}
pub(crate) fn encode_socks(address:&Address,port:u16,data:&[u8])->Option<Vec<u8>>{
    protocol::encode(&Frame::OpenUdp{address:address.clone(),port}).ok()?;
    let mut out=vec![0,0,0];
    encode_address(&mut out,address,port);
    if out.len()+data.len()>protocol::MAX_DATAGRAM {return None;}
    out.extend(data);Some(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn socks_datagrams_exact_and_fragment_rejected() {
        for address in [Address::V4([127,0,0,1]),Address::V6([0;16]),Address::Dns("example.org".into())] {
            let mut encoded=encode_socks(&address,443,b"data").unwrap();
            assert_eq!(parse_socks(&encoded),Some((address,443,b"data".as_slice())));
            encoded[2]=1;assert!(parse_socks(&encoded).is_none());
        }
        assert!(encode_socks(&Address::Dns("bad/name".into()),443,b"").is_none());
        assert!(valid_associate(&Address::V4([0;4]),"127.0.0.1".parse().unwrap()));
        assert!(!valid_associate(&Address::V4([8,8,8,8]),"127.0.0.1".parse().unwrap()));
    }
    #[tokio::test]
    async fn connected_udp_preserves_boundaries_and_empty_datagrams() {
        let origin=UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client=connect(origin.local_addr().unwrap()).await.unwrap();
        for data in [b"first".as_slice(),b"".as_slice(),b"second".as_slice()] {
            send_datagram(&client,data).await.unwrap();
            let mut buf=[0;32];
            let (n,peer)=timeout(Duration::from_secs(1),origin.recv_from(&mut buf)).await.unwrap().unwrap();
            assert_eq!(&buf[..n],data);
            assert_eq!(origin.send_to(data,peer).await.unwrap(),n);
            let n=timeout(Duration::from_secs(1),client.recv(&mut buf)).await.unwrap().unwrap();
            assert_eq!(&buf[..n],data);
        }
    }
}
