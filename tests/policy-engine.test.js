// Zero-dependency smoke tests for the deterministic policy rules.
const fs=require('fs'), vm=require('vm');
const code=fs.readFileSync('src/engine.js','utf8');
const ctx={window:{},console}; vm.createContext(ctx); vm.runInContext(code,ctx);
const E=ctx.window.GuardrailEngine;
const rules=E.cloneRules();
function t(name,action,expected){const r=E.evaluate(action,rules);if(r.decision!==expected)throw new Error(`${name}: expected ${expected}, got ${r.decision}`);console.log('✓',name)}
t('small refund',{tool:'refund.create',parameters:{amount:850}},'ALLOW');
t('review refund',{tool:'refund.create',parameters:{amount:15000}},'APPROVE');
t('hard refund block',{tool:'refund.create',parameters:{amount:500000}},'BLOCK');
t('PII export',{tool:'database.export',parameters:{}},'BLOCK');
t('destructive delete',{tool:'transaction.delete',parameters:{}},'BLOCK');
t('normal email',{tool:'email.send',parameters:{volume:5}},'ALLOW');
t('customer lookup',{tool:'customer.lookup',parameters:{target:'c-1'}},'ALLOW');
t('invoice fetch',{tool:'invoice.fetch',parameters:{target:'inv-1'}},'ALLOW');
t('pod restart',{tool:'pod.restart',parameters:{target:'auth-cluster'}},'ALLOW');
t('bulk email review',{tool:'email.send',parameters:{volume:25}},'APPROVE');
const disabled=E.cloneRules().map(r=>r.id==='refund-limit'?{...r,enabled:false}:r);
const denied=E.evaluate({tool:'refund.create',parameters:{amount:850}},disabled); if(denied.decision!=='BLOCK') throw new Error('disabled refund policy should fall back to default deny'); console.log('✓ default deny when policy disabled');
console.log('Policy engine smoke tests passed.');
