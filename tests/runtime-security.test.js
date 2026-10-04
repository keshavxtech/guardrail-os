const assert=require('assert');
const fs=require('fs');
const vm=require('vm');
const {webcrypto}=require('crypto');

const storage=new Map();
const localStorage={
  getItem:k=>storage.has(k)?storage.get(k):null,
  setItem:(k,v)=>storage.set(k,String(v)),
  removeItem:k=>storage.delete(k)
};
const ctx={window:{crypto:webcrypto},console,TextEncoder,Uint8Array,performance:{now:()=>1},localStorage};
vm.createContext(ctx);
vm.runInContext(fs.readFileSync('src/engine.js','utf8'),ctx);
vm.runInContext(fs.readFileSync('src/runtime.js','utf8'),ctx);
const R=ctx.window.GuardrailRuntime;
const E=ctx.window.GuardrailEngine;
const rules=E.cloneRules();

assert.strictEqual(R.intercept({agent:'refund-ops-01',tool:'refund.create',parameters:{amount:850}},rules).decision,'ALLOW');
assert.strictEqual(R.intercept({agent:'refund-ops-01',tool:'refund.create',parameters:{amount:-1}},rules).decision,'BLOCK');
assert.strictEqual(R.intercept({agent:'refund-ops-01',tool:'refund.create',parameters:{amount:'nope'}},rules).policy,'input-validation');
assert.strictEqual(R.intercept({agent:'refund-ops-01',tool:'unknown.tool',parameters:{}},rules).decision,'BLOCK');
assert.strictEqual(R.intercept({agent:'refund-ops-01',tool:'email.send',parameters:{volume:25}},rules).decision,'APPROVE');
assert.strictEqual(R.intercept({agent:'refund-ops-01',tool:'email.send',parameters:{volume:5},context:{callsLastMinute:20}},rules).decision,'BLOCK');
assert.strictEqual(R.intercept({agent:'refund-ops-01',tool:'customer.lookup',parameters:{target:'c-1'}},rules).execution.ok,true);
assert.strictEqual(R.intercept({agent:'refund-ops-01',tool:'customer.lookup',parameters:{}},rules).policy,'input-validation');
assert.strictEqual(R.intercept({agent:'refund-ops-01',tool:'refund.create',parameters:{amount:850,constructor:'x'}},rules).policy,'input-validation');
assert.strictEqual(R.redact({email:'user@example.com',phone:'9876543210',token:'secret'}).email,'[REDACTED_PII]');
assert.strictEqual(R.redact({email:'user@example.com',phone:'9876543210',token:'secret'}).token,'[REDACTED_SECRET]');

(async()=>{
  await R.recordAudit({type:'test',parameters:{email:'user@example.com',token:'abc'}});
  await R.recordAudit({type:'test-2',parameters:{value:'safe'}});
  let verified=await R.verifyAudit();
  assert.strictEqual(verified.valid,true);
  const entries=JSON.parse(localStorage.getItem('guardrail-os-audit-v1'));
  assert.strictEqual(entries[0].event.parameters.email,'[REDACTED_PII]');
  entries[0].event.parameters.value='tampered';
  localStorage.setItem('guardrail-os-audit-v1',JSON.stringify(entries));
  verified=await R.verifyAudit();
  assert.strictEqual(verified.valid,false);
  console.log('Runtime/security tests passed.');
})().catch(err=>{console.error(err);process.exit(1)});
