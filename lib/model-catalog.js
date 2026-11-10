/**
 * Optional DSH model catalog. Only lists models registered with the current
 * DSH host. Never handles QQ credentials or changes the official QQ SDK.
 */
export const MODELS_PATH = '/qqbot/q-mobile/models';

const valid=(value,max)=>typeof value==='string'&&value.length>0&&
  value.length<=max&&!/[\u0000-\u001f<>]/u.test(value);

export async function discoverModels(llm) {
  if(typeof llm?.listProviders!=='function'||typeof llm?.listModels!=='function')return [];
  const providers=await llm.listProviders();
  if(!Array.isArray(providers))return [];
  const items=[];
  const seen=new Set();
  for(const item of providers.slice(0,20)) {
    const provider=typeof item==='string'?item:item?.id;
    if(!valid(provider,96))continue;
    let models;
    try{models=await llm.listModels(provider)}catch{continue}
    if(!Array.isArray(models))continue;
    for(const entry of models.slice(0,35)) {
      const id=typeof entry==='string'?entry:entry?.id;
      const name=typeof entry==='string'?entry:entry?.name;
      if(!valid(id,200)||seen.has(provider+'\u0001'+id))continue;
      seen.add(provider+'\u0001'+id);
      items.push({provider,id,name:valid(name,160)?name:id});
      if(items.length>=120)return items;
    }
  }
  return items;
}
function respond(res,status,value) {
  res.writeHead(status,{
    'content-type':'application/json; charset=utf-8',
    'cache-control':'no-store',
    'x-content-type-options':'nosniff'
  });
  res.end(JSON.stringify(value));
}
function sameOrigin(req) {
  if(!req?.headers?.origin)return true; // Host-authenticated DSH desktop bridge strips Origin
  try{return new URL(req.headers.origin).host===req.headers.host}
  catch{return false}
}
export async function catalogHandler(req,res,llm) {
  if(req.method!=='GET')return respond(res,405,{error:'method_not_allowed'});
  if(!sameOrigin(req))return respond(res,403,{error:'origin_rejected'});
  try{
    const models=await discoverModels(llm);
    return respond(res,200,{models,available:models.length>0});
  }catch{
    return respond(res,200,{models:[],available:false});
  }
}
export function installModelCatalog(ctx) {
  if(typeof ctx?.inject!=='function')return false;
  try {
    // Deferred scoped services do not become dependencies of the QQ plugin.
    ctx.inject(['webServer','llm'],scope=>{
      if(typeof scope.effect!=='function'||typeof scope.webServer?.register!=='function'
          ||!scope.llm)return;
      scope.effect(()=>scope.webServer.register({
        kind:'exact',path:MODELS_PATH,
        handler:(req,res)=>catalogHandler(req,res,scope.llm)
      }));
    });
    return true;
  }catch{return false}
}
