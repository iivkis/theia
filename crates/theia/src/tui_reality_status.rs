//! Guarded server identity controls plus separate saved/runtime status.
use crate::{reality_bootstrap::Error,reality_config::{self,RotationReview,TrustReview,ExpiryReview},reference_health,tui_editor::Editor,Role};
use crossterm::event::{KeyCode,KeyEvent};
use std::{path::PathBuf,sync::mpsc::{self,Receiver,TryRecvError}};

enum Update { Report(String), Review(RotationReview), Trust(TrustReview), Expiry(ExpiryReview) }
struct ClientRun{
    stop:Option<tokio::sync::oneshot::Sender<()>>,
    done:Receiver<Result<(),crate::client::ClientError>>,
    report:std::sync::Arc<std::sync::Mutex<String>>,
}
impl Drop for ClientRun{
    fn drop(&mut self){if let Some(stop)=self.stop.take(){let _=stop.send(());}}
}
pub(crate) struct StatusPanel {
    path:PathBuf,digest:[u8;32],id:String,server:bool,
    pending:Option<Receiver<Result<Update,Error>>>,
    review:Option<RotationReview>,
    committing:bool,
    report:String,
    client_active:bool,
    client_confirm:Option<bool>,
    client_run:Option<ClientRun>,
    trust_input:Option<(bool,String)>,
    trust_review:Option<TrustReview>,
    expiry_review:Option<ExpiryReview>,
}
impl StatusPanel{
    pub(crate) fn open(editor:&Editor)->Self{
        let mut panel=Self{path:editor.saved_path().to_owned(),digest:editor.saved_sha256(),
            id:editor.selected_record_id().to_owned(),server:editor.role()==Role::Server,
            pending:None,review:None,committing:false,report:String::new(),
            client_active:editor.selected_record_is_active(),client_confirm:None,client_run:None,trust_input:None,trust_review:None,expiry_review:None};
        panel.start(None);
        panel
    }
    fn start(&mut self,rotation:Option<bool>){
        if self.pending.is_some(){return;}
        let path=self.path.clone();let digest=self.digest;let id=self.id.clone();let server=self.server;
        let (tx,rx)=mpsc::channel();self.pending=Some(rx);
        let _worker=std::thread::spawn(move||{
            let result=(||{
                let path=std::path::absolute(path).map_err(|_|Error::Storage)?;
                let now=reference_health::unix_now().map_err(|_|Error::Clock)?;
                if let Some(retire)=rotation{return RotationReview::prepare(&path,digest,&id,retire,now).map(Update::Review);}
                let mut report=reality_config::status_expected(&path,digest,&id,now)?;
                if server{
                    use crate::management::StatusReply;
                    let command=reality_config::runtime_status_command(&path,digest,&id)?;
                    let response=tokio::runtime::Builder::new_current_thread().enable_all().build()
                        .ok().and_then(|rt|rt.block_on(crate::management::query_environment(command)).ok());
                    let live=match response{
                        Some(StatusReply::RealityRunning{generation,revision,health_revision,active_reference,overlap})=>
                            format!("Runtime: принимает подключения\ngeneration={generation} revision={revision} health_revision={health_revision}\nreference_index={active_reference} overlap={overlap}"),
                        Some(StatusReply::RealitySuspended)=>"Runtime: новые подключения приостановлены; действующие туннели не отозваны.".into(),
                        _=>"Runtime: нет подтверждённого IPC статуса этого bundle.".into(),
                    };
                    report.push_str("\n\n");report.push_str(&live);
                }
                Ok(Update::Report(report))
            })();
            let _=tx.send(result);
        });
    }
    fn apply(&mut self,review:RotationReview){
        let path=self.path.clone();let digest=self.digest;let id=self.id.clone();
        let (tx,rx)=mpsc::channel();self.pending=Some(rx);self.committing=true;
        let _worker=std::thread::spawn(move||{
            let result=std::path::absolute(path).map_err(|_|Error::Storage)
                .and_then(|path|reference_health::unix_now().map_err(|_|Error::Clock)
                    .and_then(|now|review.apply(&path,digest,&id,now))).map(Update::Report);
            let _=tx.send(result);
        });
    }
    pub(crate) fn paste(&mut self,text:&str){
        if let Some((_,field))=&mut self.trust_input{
            let text=text.trim_end_matches(['\r','\n']);
            if !text.chars().any(char::is_control)&&field.len()+text.len()<=1024{field.push_str(text);}
        }
    }
    fn start_trust(&mut self,promote:bool,source:PathBuf){
        let path=self.path.clone();let digest=self.digest;let id=self.id.clone();
        let (tx,rx)=mpsc::channel();self.pending=Some(rx);
        let _worker=std::thread::spawn(move||{
            let result=std::path::absolute(path).map_err(|_|Error::Storage)
                .and_then(|path|reference_health::unix_now().map_err(|_|Error::Clock)
                    .and_then(|now|TrustReview::prepare(&path,digest,&id,&source,promote,now))).map(Update::Trust);
            let _=tx.send(result);
        });
    }
    fn apply_trust(&mut self,review:TrustReview){
        let path=self.path.clone();let digest=self.digest;let id=self.id.clone();
        let (tx,rx)=mpsc::channel();self.pending=Some(rx);self.committing=true;
        let _worker=std::thread::spawn(move||{
            let result=std::path::absolute(path).map_err(|_|Error::Storage)
                .and_then(|path|reference_health::unix_now().map_err(|_|Error::Clock)
                    .and_then(|now|review.apply(&path,digest,&id,now))).map(Update::Report);
            let _=tx.send(result);
        });
    }
    fn start_expiry(&mut self){
        let path=self.path.clone();let digest=self.digest;let id=self.id.clone();
        let (tx,rx)=mpsc::channel();self.pending=Some(rx);
        let _worker=std::thread::spawn(move||{
            let result=std::path::absolute(path).map_err(|_|Error::Storage)
                .and_then(|path|reference_health::unix_now().map_err(|_|Error::Clock)
                    .and_then(|now|ExpiryReview::prepare(&path,digest,&id,now))).map(Update::Expiry);
            let _=tx.send(result);
        });
    }
    fn apply_expiry(&mut self,review:ExpiryReview){
        let path=self.path.clone();let digest=self.digest;let id=self.id.clone();
        let (tx,rx)=mpsc::channel();self.pending=Some(rx);self.committing=true;
        let _worker=std::thread::spawn(move||{
            let result=std::path::absolute(path).map_err(|_|Error::Storage)
                .and_then(|path|reference_health::unix_now().map_err(|_|Error::Clock)
                    .and_then(|now|review.apply(&path,digest,&id,now))).map(Update::Report);
            let _=tx.send(result);
        });
    }
    fn start_client(&mut self){
        if !self.client_active||self.client_run.is_some(){return;}
        let path=self.path.clone();let digest=self.digest;let id=self.id.clone();
        let (stop,rx)=tokio::sync::oneshot::channel();
        let (tx,done)=mpsc::channel();
        let report=std::sync::Arc::new(std::sync::Mutex::new("Проверка trust, credentials и двух loopback bind...".into()));
        let monitor=report.clone();
        self.client_run=Some(ClientRun{stop:Some(stop),done,report});
        let _worker=std::thread::spawn(move||{
            use crate::{client::ClientError,local_proxy::PreparedLocalProxy};
            let result=tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|_|ClientError::Io)
                .and_then(|runtime|runtime.block_on(async move{
                    let mut rx=rx;
                    let prepared=tokio::select!{
                        result=PreparedLocalProxy::start_reality(&path,digest,&id)=>result?,
                        _=&mut rx=>return Ok(()),
                    };
                    prepared.serve_reality_observed(rx,monitor).await
                }));
            let _=tx.send(result);
        });
    }
    pub(crate) fn key(&mut self,key:KeyEvent)->bool{
        if !self.server{
            if self.trust_review.is_some(){
                match key.code{
                    KeyCode::Char('y')=>{if let Some(review)=self.trust_review.take(){self.apply_trust(review);}},
                    KeyCode::Char('n')|KeyCode::Esc=>self.trust_review=None,
                    _=>{},
                }
                return false;
            }
            if let Some((promote,field))=self.trust_input.as_mut(){
                match key.code{
                    KeyCode::Esc=>self.trust_input=None,
                    KeyCode::Enter=>{
                        let promote=*promote;let source=PathBuf::from(field.as_str());
                        self.trust_input=None;self.start_trust(promote,source);
                    }
                    KeyCode::Backspace=>{field.pop();}
                    KeyCode::Char(ch) if !ch.is_control()&&field.len()+ch.len_utf8()<=1024
                        && (key.modifiers.is_empty()||key.modifiers==crossterm::event::KeyModifiers::SHIFT)=>field.push(ch),
                    _=>{},
                }
                return false;
            }
            if let Some(start)=self.client_confirm{
                match key.code{
                    KeyCode::Char('y')=>{self.client_confirm=None;if start{self.start_client();}else if let Some(run)=self.client_run.as_mut(){if let Some(stop)=run.stop.take(){let _=stop.send(());}}},
                    KeyCode::Char('n')|KeyCode::Esc=>self.client_confirm=None,
                    _=>{},
                }
                return false;
            }
            if self.client_run.is_some(){
                if key.code==KeyCode::Char('x'){self.client_confirm=Some(false);}
                return false;
            }
            if self.pending.is_none()&&!self.committing&&matches!(key.code,KeyCode::Char('o'|'k')){
                self.trust_input=Some((key.code==KeyCode::Char('k'),String::new()));return false;
            }
            if self.pending.is_none()&&self.client_active&&key.code==KeyCode::Char('s'){
                self.client_confirm=Some(true);return false;
            }
        }
        if self.committing{return false;}
        if self.pending.is_some(){return key.code==KeyCode::Esc;}
        if self.expiry_review.is_some(){
            match key.code{
                KeyCode::Char('y')=>{if let Some(review)=self.expiry_review.take(){self.apply_expiry(review);}},
                KeyCode::Char('n')|KeyCode::Esc=>self.expiry_review=None,
                _=>{},
            }
            return false;
        }
        if self.review.is_some(){
            match key.code{
                KeyCode::Char('y')=>{if let Some(review)=self.review.take(){self.apply(review);}false}
                KeyCode::Char('n')|KeyCode::Esc=>{self.review=None;false}
                _=>false,
            }
        }else{
            match key.code{
                KeyCode::Esc=>true,
                KeyCode::Char('r')=>{self.start(None);false}
                KeyCode::Char('e') if self.server=>{self.start_expiry();false}
                KeyCode::Char('t') if self.server=>{self.start(Some(false));false}
                KeyCode::Char('p') if self.server=>{self.start(Some(true));false}
                _=>false,
            }
        }
    }
    pub(crate) fn poll(&mut self){
        if let Some(run)=&self.client_run{
            let result=match run.done.try_recv(){Ok(result)=>Some(result),Err(TryRecvError::Disconnected)=>Some(Err(crate::client::ClientError::Io)),Err(TryRecvError::Empty)=>None};
            if let Some(result)=result{self.client_run=None;self.client_confirm=None;self.report=match result{Ok(())=>"Локальный runtime остановлен; OS proxy не изменён.".into(),Err(_)=>"Локальный runtime завершился с ошибкой; слушатели закрыты. Проверьте сохранённый профиль.".into()};}
        }
        let Some(rx)=self.pending.as_ref() else{return;};
        let result=match rx.try_recv(){
            Ok(value)=>value,Err(TryRecvError::Empty)=>return,Err(TryRecvError::Disconnected)=>Err(Error::Storage),
        };
        self.pending=None;self.committing=false;
        match result{
            Ok(Update::Report(report))=>self.report=report,
            Ok(Update::Review(review))=>self.review=Some(review),
            Ok(Update::Trust(review))=>self.trust_review=Some(review),
            Ok(Update::Expiry(review))=>self.expiry_review=Some(review),
            Err(error)=>self.report=format!("Операция не подтверждена: {error}\nПри неопределённой записи сначала перечитайте сохранённый и runtime статус. Не повторяйте вслепую."),
        }
    }
    pub(crate) fn body(&self)->String{
        if let Some((promote,field))=&self.trust_input{return format!("{}\nАбсолютный путь к подписанному descriptor: [скрыто, {} bytes]\nEnter: предпросмотр | Esc: отменить",
            if *promote{"Плановый переход identity"}else{"Offline recovery"},field.len());}
        if let Some(review)=&self.trust_review{return format!("{}\n\ny: подтвердить | n/Esc: отменить",review.report());}
        if let Some(start)=self.client_confirm{return if start{"Запустить сохранённый активный REALITY-профиль с двумя loopback listeners? OS proxy не изменяется.\ny: подтвердить | n/Esc: отменить".into()}else{"Остановить локальный runtime? Открытые туннели будут закрыты.\ny: подтвердить | n/Esc: отменить".into()};}
        if let Some(run)=&self.client_run{
            if run.stop.is_none(){return "Остановка локального runtime...".into();}
            let status=run.report.lock().map(|s|s.clone()).unwrap_or_else(|_|"Статус недоступен".into());
            return format!("{status}\n\nx: остановить (подтверждение). Esc не закрывает работающий runtime.");
        }
        if self.committing{return "Подтверждённая запись публикации выполняется. Не закрывайте экран.".into();}
        if self.pending.is_some(){return "Проверка сохранённых материалов/локального IPC. Ничего не применяется.\nEsc: закрыть.".into();}
        if let Some(review)=&self.expiry_review{return format!("{}\n\ny: подтвердить | n/Esc: отменить",review.report());}
        if let Some(review)=&self.review{return format!("{}\n\ny: подтвердить запись | n/Esc: отменить",review.report());}
        format!("{}\n\nr: перечитать | {}Esc: закрыть",self.report,
            if self.server{"t: начать ротацию | p: отозвать старый ключ после overlap | e: восстановить истёкший descriptor | "}else if self.client_active{"s: запустить локальный runtime | o: recovery | k: promotion | "}else{"o: recovery | k: promotion | для запуска выберите активный профиль | "})
    }
}

#[cfg(test)]
mod tests{
    use super::*;
    use crossterm::event::KeyModifiers;
    fn key(code:KeyCode)->KeyEvent{KeyEvent::new(code,KeyModifiers::NONE)}
    fn panel(active:bool)->StatusPanel{
        StatusPanel{path:PathBuf::new(),digest:[1;32],id:"test".into(),server:false,
            pending:None,review:None,committing:false,report:String::new(),
            client_active:active,client_confirm:None,client_run:None,trust_input:None,trust_review:None,expiry_review:None}
    }
    #[test]
    fn runtime_and_trust_inputs_never_implicitly_apply(){
        let mut p=panel(true);
        assert!(!p.key(key(KeyCode::Char('s'))));
        assert_eq!(p.client_confirm,Some(true));
        assert!(p.client_run.is_none());
        assert!(!p.key(key(KeyCode::Char('n'))));
        assert!(p.client_confirm.is_none());
        assert!(!p.key(key(KeyCode::Char('o'))));
        p.paste("/secret/location");
        assert!(!p.body().contains("/secret/location"));
        assert!(!p.key(key(KeyCode::Esc)));
        assert!(p.trust_input.is_none());
        let mut inactive=panel(false);
        inactive.key(key(KeyCode::Char('s')));
        assert!(inactive.client_confirm.is_none()&&inactive.client_run.is_none());
    }
}
