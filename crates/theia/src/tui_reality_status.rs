//! Guarded server identity controls plus separate saved/runtime status.
use crate::{reality_bootstrap::Error,reality_config::{self,RotationReview},reference_health,tui_editor::Editor,Role};
use crossterm::event::{KeyCode,KeyEvent};
use std::{path::PathBuf,sync::mpsc::{self,Receiver,TryRecvError}};

enum Update { Report(String), Review(RotationReview) }
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
}
impl StatusPanel{
    pub(crate) fn open(editor:&Editor)->Self{
        let mut panel=Self{path:editor.saved_path().to_owned(),digest:editor.saved_sha256(),
            id:editor.selected_record_id().to_owned(),server:editor.role()==Role::Server,
            pending:None,review:None,committing:false,report:String::new(),
            client_active:editor.selected_record_is_active(),client_confirm:None,client_run:None};
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
            if self.pending.is_none()&&self.client_active&&key.code==KeyCode::Char('s'){
                self.client_confirm=Some(true);return false;
            }
        }
        if self.committing{return false;}
        if self.pending.is_some(){return key.code==KeyCode::Esc;}
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
            Err(error)=>self.report=format!("Операция не подтверждена: {error}\nПри неопределённой записи сначала перечитайте сохранённый и runtime статус. Не повторяйте вслепую."),
        }
    }
    pub(crate) fn body(&self)->String{
        if let Some(start)=self.client_confirm{return if start{"Запустить сохранённый активный REALITY-профиль с двумя loopback listeners? OS proxy не изменяется.\ny: подтвердить | n/Esc: отменить".into()}else{"Остановить локальный runtime? Открытые туннели будут закрыты.\ny: подтвердить | n/Esc: отменить".into()};}
        if let Some(run)=&self.client_run{
            if run.stop.is_none(){return "Остановка локального runtime...".into();}
            let status=run.report.lock().map(|s|s.clone()).unwrap_or_else(|_|"Статус недоступен".into());
            return format!("{status}\n\nx: остановить (подтверждение). Esc не закрывает работающий runtime.");
        }
        if self.committing{return "Подтверждённая запись публикации выполняется. Не закрывайте экран.".into();}
        if self.pending.is_some(){return "Проверка сохранённых материалов/локального IPC. Ничего не применяется.\nEsc: закрыть.".into();}
        if let Some(review)=&self.review{return format!("{}\n\ny: подтвердить запись | n/Esc: отменить",review.report());}
        format!("{}\n\nr: перечитать | {}Esc: закрыть",self.report,
            if self.server{"t: начать ротацию | p: отозвать старый ключ после overlap | "}else if self.client_active{"s: запустить локальный runtime | "}else{"сначала выберите профиль активным и сохраните TOML | "})
    }
}
