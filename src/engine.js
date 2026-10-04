/* Guardrail OS — deterministic policy engine. No network calls. */
(function(){
  const DEFAULT_RULES = [
    {id:'refund-limit', name:'Refund amount limit', enabled:true, evaluate(a){
      if(a.tool!=='refund.create') return null;
      const raw=a.parameters?.amount;
      const amount=Number(raw);
      if(raw===undefined || raw===null || !Number.isFinite(amount) || amount<0)
        return {decision:'BLOCK', policy:this.id, reason:'Invalid refund amount; execution denied', risk:'critical'};
      if(amount>100000) return {decision:'BLOCK', policy:this.id, reason:'Refund exceeds hard block limit of ₹100,000', risk:'critical'};
      if(amount>10000) return {decision:'APPROVE', policy:this.id, reason:'Amount exceeds ₹10,000 approval threshold', risk:'high'};
      return {decision:'ALLOW', policy:this.id, reason:'Within auto-credit threshold', risk:'low'};
    }},
    {id:'pii-export', name:'Customer PII export', enabled:true, evaluate(a){
      if(a.tool!=='database.export') return null;
      return {decision:'BLOCK', policy:this.id, reason:'Export contains customer PII', risk:'critical'};
    }},
    {id:'destructive', name:'Destructive database actions', enabled:true, evaluate(a){
      if(a.tool==='transaction.delete' || ['delete','drop','truncate'].includes(String(a.parameters?.operation||'').toLowerCase()))
        return {decision:'BLOCK', policy:this.id, reason:'Destructive database action prohibited', risk:'critical'};
      return null;
    }},
    {id:'safe-operations', name:'Safe read and remediation actions', enabled:true, evaluate(a){
      if(['customer.lookup','invoice.fetch','pod.restart'].includes(a.tool))
        return {decision:'ALLOW', policy:this.id, reason:'Tool is within the approved non-destructive action set', risk:a.tool==='pod.restart'?'medium':'low'};
      return null;
    }},
    {id:'rate-limit', name:'Tool call rate limit', enabled:true, evaluate(a){
      const calls=Number(a.context?.callsLastMinute);
      if(Number.isFinite(calls) && calls>=20)
        return {decision:'BLOCK', policy:this.id, reason:'Agent exceeded 20 tool calls in the last minute', risk:'high'};
      if(a.tool!=='email.send') return null;
      const volume=Number(a.parameters?.volume);
      if(!Number.isFinite(volume) || volume<1)
        return {decision:'BLOCK', policy:this.id, reason:'Invalid email volume; execution denied', risk:'high'};
      if(volume>20) return {decision:'APPROVE', policy:this.id, reason:'Bulk communication exceeds 20 messages; review required', risk:'medium'};
      return {decision:'ALLOW', policy:this.id, reason:'Within communication rate limit', risk:'low'};
    }}
  ];

  function cloneRules(rules){ return (rules||DEFAULT_RULES).map(r=>({...r})); }
  function evaluate(action, rules){
    if(!action || typeof action!=='object' || typeof action.tool!=='string')
      return {decision:'BLOCK',policy:'input-validation',reason:'Invalid action payload',risk:'critical',evaluatedAt:new Date().toISOString()};
    const active=(rules||DEFAULT_RULES).filter(r=>r.enabled!==false);
    for(const rule of active){
      const result=rule.evaluate(action);
      if(result) return {...result,evaluatedAt:new Date().toISOString()};
    }
    return {decision:'BLOCK',policy:'default-deny',reason:'No active policy permits this tool action',risk:'high',evaluatedAt:new Date().toISOString()};
  }
  window.GuardrailEngine={evaluate,cloneRules,DEFAULT_RULES};
})();
