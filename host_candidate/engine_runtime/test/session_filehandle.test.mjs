// Run the same operations against native Node and the bounded owner adapter.
// Only fresh test data. This is not full JSONL/native-flock acceptance.
async function exerciseFileHandles(root){
  const file=root+'/session.jsonl',result={};
  await fs.promises.writeFile(file,'{"header":1}\n{"seq":0}\ncrash-tail');
  const handle=await fs.promises.open(file,'r+');
  try{
    const buffer=Buffer.alloc(32,0x2e);
    let read=await handle.read(buffer,2,5,null);
    result.first=[read.bytesRead,read.buffer===buffer,buffer.toString('utf8',0,9)];
    read=await handle.read(buffer,0,4,13);
    result.explicit=[read.bytesRead,buffer.toString('utf8',0,4)];
    read=await handle.read(buffer,0,4,null);
    result.cursor=[read.bytesRead,buffer.toString('utf8',0,4)];
    const view=new DataView(new ArrayBuffer(6));
    read=await handle.read(view,1,3,0);
    result.view=[read.bytesRead,read.buffer===view,[...new Uint8Array(view.buffer)]];
    read=await handle.read(buffer,0,3,1000000);result.pastEnd=read.bytesRead;
    // Truncate does not move the descriptor's shared read/write offset.
    await handle.truncate(4);await handle.writeFile('X');
    result.hole=(await fs.promises.readFile(file)).toString('hex');
    await handle.truncate(2);await handle.truncate(7);await handle.sync();
    result.zeroExtension=(await fs.promises.readFile(file)).toString('hex');
    result.afterTruncateRead=(await handle.read(buffer,0,4,null)).bytesRead;
    await handle.truncate(-1);await handle.datasync();result.negativeSize=(await handle.stat()).size;
  }finally{await handle.close();}
  try{await handle.read(Buffer.alloc(1),0,1,null);}catch(error){result.closed=error.code;}
  await fs.promises.writeFile(file,'old');
  const append=await fs.promises.open(file,'a');
  try{await append.writeFile('new');await append.truncate(5);await append.sync();}finally{await append.close();}
  result.append=(await fs.promises.readFile(file)).toString();
  await fs.promises.truncate(file,2);result.pathTruncate=(await fs.promises.readFile(file)).toString();
  const reader=await fs.promises.open(file,'r');
  try{
    try{await reader.truncate(1);}catch(error){result.readOnlyTruncate=error.code;}
    try{await reader.read(Buffer.alloc(2),2,1,null);}catch(error){result.invalidRange=error.code;}
    const empty=Buffer.alloc(0);result.emptyRead=(await reader.read(empty,0,0,null)).bytesRead;
  }finally{await reader.close();}
  return result;
}
