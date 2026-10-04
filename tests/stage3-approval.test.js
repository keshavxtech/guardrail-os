// Stage 3 contract tests for approval-producing policy decisions.
const fs=require('fs'), vm=require('vm');
const code=fs.readFileSync('src/engine.js','utf8');
const ctx={window:{},console}; vm.createContext(ctx); vm.runInContext(code,ctx);
const E=ctx.window.GuardrailEngine;
const rules=E.cloneRules();
const review=E.evaluate({agent:'refund-ops-01',tool:'refund.create',parameters:{amount:15000,target:'user: c-4812'}},rules);
if(review.decision!=='APPROVE') throw new Error('Stage 3 approval request must be created for a review-level refund');
if(review.policy!=='refund-limit') throw new Error('Approval must retain the triggering policy');
if(review.risk!=='high') throw new Error('Approval must retain risk classification');
const allowed=E.evaluate({agent:'refund-ops-01',tool:'refund.create',parameters:{amount:850}},rules);
if(allowed.decision!=='ALLOW') throw new Error('Low-risk refund should not enter approval queue');
const blocked=E.evaluate({agent:'refund-ops-01',tool:'refund.create',parameters:{amount:500000}},rules);
if(blocked.decision!=='BLOCK') throw new Error('Hard-limit refund must bypass approval and block');
console.log('Stage 3 approval contract tests passed.');
