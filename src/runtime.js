/* Guardrail OS — local tool boundary + security controls. No network calls. */
(function(){
  const MAX_PAYLOAD = 8192;
  const MAX_AGENT_LENGTH = 120;
  const MAX_STRING = 240;
  const DENY_KEYS=new Set(['__proto__','prototype','constructor']);
  const ALLOWED_TOOLS=new Set(['refund.create','database.export','transaction.delete','email.send','customer.lookup','invoice.fetch','pod.restart']);

  const clone=value=>JSON.parse(JSON.stringify(value??{}));
  const cleanString=value=>String(value??'').trim().slice(0,MAX_STRING);

  function parseObject(value,label){
    if(value===undefined||value===null) return {};
    if(typeof value!=='object'||Array.isArray(value)) throw new Error(`${label} must be an object`);
    return value;
  }

  function validateAction(action){
    if(!action||typeof action!=='object'||Array.isArray(action)) throw new Error('Invalid action payload');
    const rawAgent=String(action.agent??'').trim();
    if(!rawAgent||rawAgent.length>MAX_AGENT_LENGTH) throw new Error('Invalid agent');
    if(!ALLOWED_TOOLS.has(action.tool)) throw new Error('Unknown tool');
    const params=parseObject(action.parameters,'Parameters');
    for(const key of Object.keys(params)) if(DENY_KEYS.has(key)) throw new Error('Unsafe parameter key');
    const serialized=JSON.stringify(params);
    if(serialized.length>MAX_PAYLOAD) throw new Error('Payload exceeds 8 KB limit');

    if(action.tool==='refund.create'){
      const amount=Number(params.amount);
      if(!Number.isFinite(amount)||amount<0) throw new Error('Invalid refund amount');
      if(params.target!==undefined && cleanString(params.target).length>MAX_STRING) throw new Error('Invalid refund target');
    }
    if(action.tool==='email.send'){
      const volume=Number(params.volume);
      if(!Number.isInteger(volume)||volume<1||volume>10000) throw new Error('Invalid email volume');
    }
    if(['customer.lookup','invoice.fetch','pod.restart'].includes(action.tool) && !cleanString(params.target))
      throw new Error('Target is required');

    return {agent:rawAgent,tool:action.tool,parameters:clone(params),context:action.context&&typeof action.context==='object'&&!Array.isArray(action.context)?clone(action.context):{}};
  }

  function redact(value){
    if(typeof value==='string'){
      return value
        .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/ig,'[REDACTED_EMAIL]')
        .replace(/\b(?:\+?91[-\s]?)?[6-9]\d{9}\b/g,'[REDACTED_PHONE]')
        .replace(/\b(?:\d[ -]*?){13,19}\b/g,'[REDACTED_CARD]');
    }
    if(Array.isArray(value)) return value.map(redact);
    if(value&&typeof value==='object') return Object.fromEntries(Object.entries(value).map(([k,v])=>{
      if(/(?:password|secret|token|api[_-]?key|authorization|cookie)/i.test(k)) return [k,'[REDACTED_SECRET]'];
      if(/(?:email|phone|mobile|card(?:number)?)/i.test(k)) return [k,'[REDACTED_PII]'];
      return [k,redact(v)];
    }));
    return value;
  }

  const tools={
    'refund.create':{category:'Payments',execute(p){
      const amount=Number(p.amount); if(!Number.isFinite(amount)||amount<0) throw new Error('Invalid refund amount');
      return {status:200,transactionId:'rf-'+cryptoRandomId(),amount,state:'refunded'};
    }},
    'database.export':{category:'Database',execute(){return {status:200,rows:0,state:'exported'};}},
    'transaction.delete':{category:'Database',execute(){return {status:200,deleted:false,state:'simulated-delete'};}},
    'email.send':{category:'Communication',execute(p){
      const volume=Number(p.volume); if(!Number.isInteger(volume)||volume<1||volume>10000) throw new Error('Invalid email volume');
      return {status:202,accepted:volume,messageId:'mail-'+cryptoRandomId()};
    }},
    'customer.lookup':{category:'Customer data',execute(p){return {status:200,customerRef:cleanString(p.target),scope:'read-only'};}},
    'invoice.fetch':{category:'Finance',execute(p){return {status:200,invoiceRef:cleanString(p.target),state:'verified'};}},
    'pod.restart':{category:'Infrastructure',execute(p){return {status:202,service:cleanString(p.target),state:'restart-requested'};}}
  };

  function cryptoRandomId(){
    if(window.crypto?.getRandomValues){const a=new Uint8Array(4);window.crypto.getRandomValues(a);return [...a].map(b=>b.toString(16).padStart(2,'0')).join('');}
    return Math.random().toString(16).slice(2,10);
  }

  async function digest(input){
    if(window.crypto?.subtle){
      const bytes=new TextEncoder().encode(input);const hash=await window.crypto.subtle.digest('SHA-256',bytes);
      return [...new Uint8Array(hash)].map(b=>b.toString(16).padStart(2,'0')).join('');
    }
    let h=2166136261;for(let i=0;i<input.length;i++){h^=input.charCodeAt(i);h=Math.imul(h,16777619)}return ('00000000'+(h>>>0).toString(16)).slice(-8);
  }

  function readAudit(){
    try{const parsed=JSON.parse(localStorage.getItem('guardrail-os-audit-v1')||'[]');return Array.isArray(parsed)?parsed:[];}
    catch{return []}
  }

  async function recordAudit(event){
    const current=readAudit();
    const previous=current.length?current[current.length-1].hash:'GENESIS';
    const safe=redact(clone(event));
    const hash=await digest(JSON.stringify({previous,event:safe}));
    current.push({sequence:current.length+1,previous,hash,event:safe});
    localStorage.setItem('guardrail-os-audit-v1',JSON.stringify(current));
    return hash;
  }

  async function verifyAudit(){
    const entries=readAudit();let previous='GENESIS';
    for(let i=0;i<entries.length;i++){
      const e=entries[i];
      if(!e||e.sequence!==i+1||e.previous!==previous) return {valid:false,brokenAt:e?.sequence||i+1};
      const hash=await digest(JSON.stringify({previous:e.previous,event:e.event}));
      if(hash!==e.hash) return {valid:false,brokenAt:e.sequence};
      previous=e.hash;
    }
    return {valid:true,count:entries.length};
  }

  function execute(action){
    let safe;try{safe=validateAction(action);}catch(error){return {ok:false,state:'blocked',error:cleanString(error.message||'Validation failed')};}
    const adapter=tools[safe.tool];if(!adapter) return {ok:false,state:'blocked',error:'Tool adapter unavailable'};
    const started=performance.now();
    try{const result=adapter.execute(safe.parameters);return {ok:true,tool:safe.tool,latencyMs:Number((performance.now()-started).toFixed(2)),result:redact(result)};}
    catch(error){return {ok:false,tool:safe.tool,latencyMs:Number((performance.now()-started).toFixed(2)),error:cleanString(error.message||'Tool execution failed')};}
  }

  function intercept(action,rules){
    let safe;try{safe=validateAction(action);}catch(error){return {decision:'BLOCK',policy:'input-validation',reason:error.message,risk:'high',execution:{ok:false,state:'blocked',error:error.message}};}
    let result;try{result=window.GuardrailEngine.evaluate(safe,rules);}catch(error){return {decision:'BLOCK',policy:'engine-fail-closed',reason:'Policy evaluation failed; execution denied',risk:'critical',execution:{ok:false,state:'blocked',error:error.message}};}
    if(result.decision==='ALLOW') result.execution=execute(safe);
    else result.execution={ok:false,state:result.decision==='APPROVE'?'awaiting-approval':'blocked'};
    return {...result,action:safe};
  }

  window.GuardrailRuntime={tools,redact,validateAction,intercept,execute,recordAudit,verifyAudit};
})();
