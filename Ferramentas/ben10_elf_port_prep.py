#!/usr/bin/env python3
"""Read-only PS3 PPU ELF analysis and static-recompilation preparation.
Produces JSON manifests without altering the original ELF.
Compatible with Python 3.13, no dependencies.
"""
import argparse,collections,hashlib,json,struct,pathlib

def hx(n):return f'0x{n:x}'
def u16(b,off):return struct.unpack_from('>H',b,off)[0]
def u32(b,off):return struct.unpack_from('>I',b,off)[0]
def u64(b,off):return struct.unpack_from('>Q',b,off)[0]

def run(source,out):
 b=pathlib.Path(source).read_bytes()
 if len(b)<64 or b[:4]!=b'\x7fELF' or b[4:6]!=b'\x02\x02':raise ValueError('Expected big-endian ELF64 (decrypted PPU ELF)')
 if u16(b,18)!=21:raise ValueError('Expected PowerPC64 ELF (e_machine 21)')
 e_entry=u64(b,24); po=u64(b,32); so=u64(b,40); phnum=u16(b,56);shnum=u16(b,60);shstr=u16(b,62)
 phentsz=u16(b,54);shentsz=u16(b,58)
 if po+phnum*phentsz>len(b) or so+shnum*shentsz>len(b):raise ValueError('ELF header tables out of file')
 segments=[]
 for i in range(phnum):
  off=po+i*phentsz
  typ,flags,fo,va,pa,fs,ms,al=struct.unpack_from('>IIQQQQQQ',b,off)
  if fo+fs>len(b):raise ValueError('Segment extends beyond ELF')
  segments.append(dict(type=typ,flags=flags,file_offset=fo,vaddr=va,filesz=fs,memsz=ms,align=al))
 sections=[]
 for i in range(shnum):
  off=so+i*shentsz
  name,typ,flags,addr,fo,sz,link,info,align,es=struct.unpack_from('>IIQQQQIIQQ',b,off)
  sections.append(dict(index=i,name_offset=name,type=typ,flags=flags,addr=addr,offset=fo,size=sz,align=align))
 def read(va,size):
  for s in segments:
   if s['type']==1 and s['vaddr']<=va and va+size<=s['vaddr']+s['filesz']:
    p=s['file_offset']+va-s['vaddr'];return b[p:p+size]
  return None
 ranges=[(s['vaddr'],s['vaddr']+s['filesz']) for s in segments if s['type']==1 and (s['flags']&1)]
 in_exec=lambda x:any(lo<=x<hi for lo,hi in ranges)
 opdsec=min((s for s in sections if s['size'] and s['addr']<=e_entry<s['addr']+s['size']),key=lambda x:x['size'],default=None)
 if not opdsec:raise ValueError('No section contains e_entry (OPD resolution unavailable)')
 opd=[]
 for a in range(opdsec['addr'],opdsec['addr']+opdsec['size']-7,8):
  raw=read(a,8)
  if raw is None:continue
  func,toc=struct.unpack('>II',raw)
  if in_exec(func):opd.append({'opd':hx(a),'func':hx(func),'toc':hx(toc)})
 entry_raw=read(e_entry,8)
 entry_func,entry_toc=struct.unpack('>II',entry_raw) if entry_raw else (0,0)
 if not in_exec(entry_func):raise ValueError('Entry descriptor does not point into executable segment')
 func_addrs=sorted({int(e['func'],16) for e in opd})
 first={int(e['func'],16):e for e in opd}
 funcs=[]
 for i,a in enumerate(func_addrs):
  bound=next((hi for lo,hi in ranges if lo<=a<hi),a)
  end=min(bound,func_addrs[i+1]) if i+1<len(func_addrs) else bound
  funcs.append(dict(start=hx(a),end=hx(end),toc=first[a]['toc'],opd=first[a]['opd']))
 def get32(a):
  raw=read(a,4);return struct.unpack('>I',raw)[0] if raw else None
 def getstr(a):
  raw=read(a,256)
  if raw is None:
   raw=b''
   for n in range(256):
    c=read(a+n,1)
    if not c or c==b'\x00':break
    raw+=c
  return raw.split(b'\x00',1)[0].decode('ascii','replace')
 imports=[];issues=[]
 for seg in segments:
  if seg['type']!=0x60000002:continue
  raw=read(seg['vaddr'],32)
  if not raw or u32(raw,4)!=0x1b434cec:continue
  sta,end=u32(raw,24),u32(raw,28)
  va=sta
  while va<end:
   header=read(va,28)
   if not header:issues.append('Unmapped libstub record at '+hx(va));break
   size=header[0]
   if size<28 or va+size>end:issues.append('Invalid libstub size at '+hx(va));break
   count=u16(header,6);nameptr=u32(header,16);nidptr=u32(header,20);stubptr=u32(header,24)
   name=getstr(nameptr)
   for i in range(count):
    nid=get32(nidptr+4*i);stub=get32(stubptr+4*i)
    if nid is None or stub is None:issues.append('Unmapped import '+name+':'+str(i));continue
    imports.append(dict(library=name,nid=hx(nid),stub=hx(stub)))
   va+=size
 out=pathlib.Path(out);out.mkdir(parents=True,exist_ok=True)
 def dump(name,v): (out/name).write_text(json.dumps(v,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
 dump('EBOOT.loader.json',dict(source=pathlib.Path(source).name,sha256=hashlib.sha256(b).hexdigest(),size=len(b),entry_opd=hx(e_entry),entry_code=hx(entry_func),entry_toc=hx(entry_toc),opd_base=hx(opdsec['addr']),opd_size=hx(opdsec['size']),opd_descriptors=len(opd),unique_function_addresses=len(func_addrs),imports=len(imports),issues=issues))
 dump('EBOOT.functions.json',funcs)
 dump('EBOOT.imports.json',imports)
 dump('EBOOT.image.json',[{k:hx(v) if k in ('vaddr','file_offset','filesz','memsz') else v for k,v in s.items()} for s in segments if s['type']==1 and s['memsz']])
 dump('EBOOT.opd.json',opd)
 cnt=collections.Counter(i['library'] for i in imports)
 report=[f'ELF: {source}',f'SHA256: {hashlib.sha256(b).hexdigest()}',f'ELF e_entry (OPD): {hx(e_entry)}',f'Actual entry code: {hx(entry_func)}',f'Entry TOC r2: {hx(entry_toc)}',f'Function descriptors: {len(opd)}',f'Unique function pointers: {len(func_addrs)}',f'Firmware imports: {len(imports)} in {len(cnt)} libraries','', 'Import libraries:']
 report += [f'  {k}: {v}' for k,v in cnt.most_common()]
 report += ['', 'Status: port preparation only. No native execution or translated game functions yet.']
 (out/'README.txt').write_text('\n'.join(report)+'\n',encoding='utf-8')
 print('\n'.join(report))
 return out

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('source');p.add_argument('--out',default='port_prep');a=p.parse_args();run(a.source,a.out)
