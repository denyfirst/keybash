export const ownedRemote = Boolean(document.body.dataset.ownedRemote);
async function json(path, method='GET', body, csrf='') {
  const response=await fetch(path,{method,headers:{'Content-Type':'application/json','X-Keybash-Request':'1','X-Keybash-CSRF':csrf},body:body===undefined?undefined:JSON.stringify(body),credentials:'same-origin',cache:'no-store',redirect:'error',signal:AbortSignal.timeout(15000)});
  if(response.status===503&&response.headers.get('X-Keybash-Capacity')==='full')throw Object.assign(new Error('capacity'),{code:'capacity'});
  if(response.status===429)throw Object.assign(new Error('rate'),{code:'rate'});
  if(!response.ok||response.headers.get('Content-Type')!=='application/json; charset=utf-8')throw new Error('refused');
  const reader=response.body.getReader();let length=0;const parts=[];
  while(true){const {done,value}=await reader.read();if(done)break;length+=value.length;if(length>8192){await reader.cancel();throw new Error('response limit');}parts.push(value);}
  const bytes=new Uint8Array(length);let offset=0;for(const part of parts){bytes.set(part,offset);offset+=part.length;}
  return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
}
export function remoteErrorMessage(error){if(error?.code==='capacity')return 'Hazırda bağlantı tutumu doludur. Açıq sessiyanı bağla və ya bir qədər sonra yenidən cəhd et.';if(error?.code==='rate')return 'Qoşulma cəhdləri çoxdur. Bir qədər gözlə və yenidən cəhd et.';return 'Qoşulma rədd edildi. Sessiya bitibsə yenidən daxil ol.';}
export async function remoteProof(){
 const record=document.body.dataset.connection;if(!/^[a-f0-9]{32}$/.test(record??''))throw new Error('invalid connection');
 const session=await json('/api/session');if(session.stage!=='ready'||!/^[A-Za-z0-9_-]{43}$/.test(session.csrf??''))throw new Error('session refused');
 const data=await json('/api/remote/open','POST',{connection:record},session.csrf);if(!/^[A-Za-z0-9_-]{43}$/.test(data.lease??''))throw new Error('lease refused');
 return {csrf:session.csrf,lease:data.lease};
}
