//! Guarded server identity controls plus separate saved/runtime status.
use crate::{reality_bootstrap::Error,reality_config::{self,RotationReview},reference_health,tui_editor::Editor,Role};
use crossterm::event::{KeyCode,KeyEvent};
use std::{path::PathBuf,sync::mpsc::{self,Receiver,TryRecvError}};

enum Update { Report(String), Review(RotationReview) }
pub(crate) struct StatusPanel {
    path:PathBuf,digest:[u8;32],id:String,server:bool,
    pending:Option<Receiver<Result<Update,Error>>>,
    review:Option<RotationReview>,
    committing:bool,
    report:String,
}
impl StatusPanel{
    pub(crate) fn open(editor:&Editor)->Self{
        let mut panel=Self{path:editor.saved_path().to_owned(),digest:editor.saved_sha256(),
            id:editor.selected_record_id().to_owned(),server:editor.role()==Role::Server,
            pending:None,review:None,committing:false,report:String::new()};
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
    pub(crate) fn key(&mut self,key:KeyEvent)->bool{
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
        if self.committing{return "Подтверждённая запись публикации выполняется. Не закрывайте экран.".into();}
        if self.pending.is_some(){return "Проверка сохранённых материалов/локального IPC. Ничего не применяется.\nEsc: закрыть.".into();}
        if let Some(review)=&self.review{return format!("{}\n\ny: подтвердить запись | n/Esc: отменить",review.report());}
        format!("{}\n\nr: перечитать | {}Esc: закрыть",self.report,
            if self.server{"t: начать ротацию | p: отозвать старый ключ после overlap | "}else{""})
    }
}
