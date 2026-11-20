package sip

// Local SBC Console integration. Keeps a private sidecar; it does not change SIPREC signaling.
import (
 "encoding/json"
 "os"
 "path/filepath"
 "time"
 "siprec-server/pkg/security"
)
func (s *CustomSIPServer) saveConsoleRecording(callID string, state *CallState, status string, paths []string) {
 if s.handler==nil || s.handler.Config==nil || s.handler.Config.MediaConfig==nil { return }
 directory:=s.handler.Config.MediaConfig.RecordingDir
 if directory=="" || state==nil { return }
 base:=security.SanitizeCallUUID(callID)
 if base=="" { return }
 files:=[]string{}
 seen:=map[string]bool{}
 for _,path:=range append([]string{filepath.Join(directory,base+".wav")},paths...) {
  if filepath.Clean(filepath.Dir(path))!=filepath.Clean(directory) { continue }
  name:=filepath.Base(path)
  if info,err:=os.Lstat(path);err==nil && info.Mode().IsRegular() && !seen[name] { files=append(files,name);seen[name]=true }
 }
 payload:=map[string]interface{}{"callId":callID,"status":status,"createdAt":state.CreatedAt.UTC().Format(time.RFC3339Nano),"updatedAt":time.Now().UTC().Format(time.RFC3339Nano),"files":files,"metadata":state.RecordingSession}
 data,err:=json.MarshalIndent(payload,"","  ");if err!=nil{return}
 destination:=filepath.Join(directory,base+".recording.json")
 temporary,err:=os.CreateTemp(directory,".metadata-*");if err!=nil{return}
 name:=temporary.Name();defer os.Remove(name)
 if err=temporary.Chmod(0600);err==nil { _,err=temporary.Write(data) }
 closeErr:=temporary.Close()
 if err==nil && closeErr==nil { _=os.Rename(name,destination) }
}
