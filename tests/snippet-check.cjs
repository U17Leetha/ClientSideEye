const assert = require('node:assert/strict');
const vm = require('node:vm');
let json='';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk=>json+=chunk);
process.stdin.on('end',()=>{
  const {snippet, mode}=JSON.parse(json);
  const nodes=[];
  const element = text => ({
    textContent: text, innerText: text, value:'', tagName:'BUTTON', nodeType:1, disabled:true,
    parentElement:null, hidden:false, style:{setProperty(){}}, dataset:{},
    classList:{[Symbol.iterator]:function*(){},remove(){}},
    getAttribute(){return null;}, removeAttribute(){}, scrollIntoView(){}, focus(){}
  });
  if(mode==='exact') nodes.push(element('Delete User'),element('Other Action'));
  if(mode==='ambiguous') nodes.push(element('Delete User'),element('Delete User'));
  const document={createTreeWalker:()=>({nextNode:()=>null}),querySelectorAll:()=>nodes};
  const context={document,console,getComputedStyle:()=>({}),setTimeout:()=>0};
  vm.runInNewContext(snippet,context,{timeout:1000});
  assert.equal(context.reviewPwned,undefined);
  if(mode==='exact'){assert.equal(nodes[0].disabled,false);assert.equal(nodes[1].disabled,true);}
  if(mode==='ambiguous') assert.ok(nodes.every(node=>node.disabled));
});
