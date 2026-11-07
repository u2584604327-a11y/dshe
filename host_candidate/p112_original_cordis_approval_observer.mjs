/**
 * P112 advisory view into a REAL original Cordis approval/request event.
 *
 * Only original in-process live SessionStore object identity and original
 * waterfall scope are inspected. This module NEVER answers an approval,
 * never exports a Binder transport, never executes a tool, and never writes
 * a session/tool/result event. Untrusted native claims remain DENIED.
 *
 * Based on publicly documented pht88888888/DSHAPP MIT approval/request
 * usage. Original notice is preserved in THIRD_PARTY_LICENSES/DSHAPP-MIT.txt.
 */

const DENIED=Object.freeze({observed:false,reason:'NO_ORIGINAL_LIVE_CALL_PROOF'});
const MAX_ID_LENGTH=128;
const validId=value=>typeof value==='string'&&value.length>0&&
  value.length<=MAX_ID_LENGTH&&/^[A-Za-z0-9_-]+$/.test(value);

function getSessions(ctx){
  if(!ctx||typeof ctx!=='object')return null;
  try {
    const service=typeof ctx.get==='function'?ctx.get('sessions'):null;
    return service&&typeof service.get==='function'?service:null;
  }catch{return null;}
}

/**
 * @param {object} request The original scoped waterfall request, NOT JSON.
 * @param {object} ctx Original Cordis context; ctx.get('sessions') must work.
 * @param {function} scopeKeyOf Official @deepseek-ai/dsh-scope carrierKeyOf.
 * @param {object} carrier Actual Cordis waterfall 'this', not request fields.
 *
 * Return is ADVISORY only. The Android host must NOT use this return to
 * set OriginalCallVerifier=true. No exact pending ToolRuntime state
 * is independently proven here.
 */
export function inspectOriginalApproval({request,ctx,scopeKeyOf,carrier}={}){
  if(!request||typeof request!=='object'||Array.isArray(request)||
     !request.agent||typeof request.agent!=='object'||
     typeof scopeKeyOf!=='function'||!carrier)return DENIED;
  const session=request.agent.session;
  if(!session||typeof session!=='object'||!validId(session.id)||
     !validId(request.callId))return DENIED;
  if(request.signal?.aborted===true)return DENIED;
  const sessions=getSessions(ctx);
  if(!sessions)return DENIED;
  let officialScope;
  let current;
  try {
    officialScope=scopeKeyOf(carrier);
    current=sessions.get(session.id);
  }catch{return DENIED;}
  if(officialScope!==session.id||current!==session)return DENIED;
  // The real session must be alive and identified by ORIGINAL object identity
  // (not a matching serialized ID). This still does NOT prove ToolRuntime
  // has this call pending or authorize the native P102 isolated executor.
  return Object.freeze({
    observed:true,sessionId:session.id,callId:request.callId,
    proofLevel:'ORIGINAL_NODE_LIVE_SESSION_SCOPE_ONLY',
    nativeAuthorization:false,
    exactPendingToolRuntimeCall:false
  });
}

/**
 * Install an original Cordis **observer**, not an answerer. ALWAYS invoke the
 * original waterfall next() exactly once with original this/args; fail safe
 * if diagnostics throw. No handler can return allowed-once on its own.
 */
export function installAdvisoryApprovalObserver({ctx,scopeKeyOf,onObserve}={}){
  if(!ctx||typeof ctx.on!=='function'||typeof scopeKeyOf!=='function')
    throw Error('P112_ORIGINAL_CORDIS_CONTEXT_REQUIRED');
  return ctx.on('approval/request',async function(request,next){
    if(typeof next!=='function')throw Error('P112_NO_ORIGINAL_WATERFALL_NEXT');
    try {
      const candidate=inspectOriginalApproval({
        request,ctx,scopeKeyOf,carrier:this
      });
      // Only call the diagnostic with a separate sanitized view; its return
      // value is never interpreted as approval, and exceptions are ignored.
      if(candidate.observed&&typeof onObserve==='function'){
        try{onObserve(candidate);}catch{}
      }
    }catch{}
    return next(); // NEVER intercept/answer/allow.
  });
}
