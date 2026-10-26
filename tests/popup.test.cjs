const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../browser-extension/clientsideeye-bridge/popup.js'), 'utf8');
function context(fetch) {
  const element={addEventListener(){},value:'',disabled:false};
  return vm.createContext({document:{addEventListener(){},getElementById:()=>element},
    chrome:{},fetch,AbortController,URL,TextDecoder,setTimeout,clearTimeout,console});
}
function response(product, protocol=1) {
  return {ok:true,headers:new Headers({'content-type':'application/json'}),
    body:new Response(JSON.stringify({product,protocol})).body};
}

test('discovery skips unrelated and wrong-session listeners and revalidates cached sessions', async()=>{
  const calls=[];
  let round=0;
  const sandbox=context(async(url, options)=>{
    calls.push({url,options});
    const port=Number(new URL(url).port);
    if(url.endsWith('/api/health')) return response(port===17373?'OtherProduct':'ClientSideEye');
    if(port===17374 || round===1 && port===17375) return {ok:false,status:401};
    return response('ClientSideEye');
  });
  vm.runInContext(source,sandbox);
  assert.equal(await vm.runInContext("resolveBridgeBase('synthetic-token')",sandbox),'http://127.0.0.1:17375');
  assert.ok(calls.filter(call=>call.url.endsWith('/api/health')).every(call=>!call.options.headers));
  assert.ok(!calls.some(call=>call.url.includes(':17373/api/session')));
  round=1;
  assert.equal(await vm.runInContext("resolveBridgeBase('synthetic-token')",sandbox),'http://127.0.0.1:17376');
});

test('bridge response decoding has a byte budget', async()=>{
  const sandbox=context(()=>{});
  sandbox.response={body:new Response('x'.repeat(5000)).body};
  vm.runInContext(source,sandbox);
  await assert.rejects(vm.runInContext('readBridgeJson(response)',sandbox),/budget/);
});
