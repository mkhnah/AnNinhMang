import { useId, useRef, useState } from 'react';
import { UploadCloud, FileCheck2, X } from 'lucide-react';
interface Props {label:string; accept?:string; file?:File|null; disabled?:boolean; onChange:(file?:File)=>void;}
export function FilePicker({label,accept,file,disabled,onChange}:Props) {
  const id=useId(); const input=useRef<HTMLInputElement>(null); const [dragging,setDragging]=useState(false);
  return <div className={`file-picker ${file?'has-file':''} ${dragging?'is-dragging':''} ${disabled?'is-disabled':''}`}
    onDragOver={e=>{e.preventDefault();if(!disabled)setDragging(true);}} onDragLeave={()=>setDragging(false)}
    onDrop={e=>{e.preventDefault();setDragging(false);const dropped=e.dataTransfer.files[0];if(!disabled&&dropped)onChange(dropped);}}>
    <input ref={input} id={id} className="sr-only" tabIndex={-1} type="file" accept={accept} aria-label={label} disabled={disabled} onChange={e=>{onChange(e.target.files?.[0]);e.target.value='';}}/>
    <button type="button" disabled={disabled} className="file-picker-target" onClick={()=>input.current?.click()} aria-label={file?`Đổi ${label}`:`Mở ${label}`}>
      <span className="file-picker-icon">{file?<FileCheck2 size={24}/>:<UploadCloud size={24}/>}</span>
      <span className="file-picker-text"><span>{file?.name||label}</span>{file&&<span className="file-picker-size">{file.size<1048576?`${Math.ceil(file.size/1024)} KB`:`${(file.size/1048576).toFixed(1)} MB`}</span>}</span>
      <span className="file-picker-action">{file?'Đổi tệp':'Chọn tệp'}</span>
    </button>
    {file&&<button type="button" disabled={disabled} aria-label={`Bỏ ${label}`} className="icon-button file-picker-remove" onClick={()=>onChange(undefined)}><X size={17}/></button>}
  </div>;
}
