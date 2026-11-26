package com.dsh.android.engine;
import java.io.*;import java.net.*;import java.nio.charset.StandardCharsets;import java.security.*;import java.util.*;
/** Original-main HTTP/RPC/WS acceptance client. TEST ONLY; no authority,
 * process creation, arbitrary destination or READY result. All methods stay
 * package-private and connect only to the owned loopback port. */
final class OriginalMainHttpChecks {
 static void yes(boolean value,String code)throws IOException{if(!value)throw new IOException(code);}
 static String line(InputStream in)throws Exception{ByteArrayOutputStream b=new ByteArrayOutputStream();int c;while((c=in.read())!=-1&&c!='\n'){if(b.size()>=8192)throw new IOException("CONTROL_LINE_BOUND");if(c!='\r')b.write(c);}if(c==-1&&b.size()==0)return null;return b.toString("UTF-8");}
 static byte[] read(InputStream in,int max)throws Exception{try(InputStream owned=in){ByteArrayOutputStream bytes=new ByteArrayOutputStream();byte[] block=new byte[4096];int n;while((n=owned.read(block))!=-1){if(n>max-bytes.size())throw new IOException("CONTROL_RESPONSE_BOUND");bytes.write(block,0,n);}return bytes.toByteArray();}}
 static final class Reply{int status;String cookie;byte[] body;}
 static Reply request(int port,String target,String cookie,String json)throws Exception{
  HttpURLConnection c=(HttpURLConnection)new URL("http://127.0.0.1:"+port+target).openConnection(java.net.Proxy.NO_PROXY);c.setInstanceFollowRedirects(false);c.setConnectTimeout(5000);c.setReadTimeout(8000);if(cookie!=null)c.setRequestProperty("Cookie",cookie);
  try{if(json!=null){c.setRequestMethod("POST");c.setDoOutput(true);c.setRequestProperty("Content-Type","application/json");try(OutputStream out=c.getOutputStream()){out.write(json.getBytes(StandardCharsets.UTF_8));}}
   Reply r=new Reply();r.status=c.getResponseCode();r.cookie=c.getHeaderField("Set-Cookie");InputStream body=r.status>=400?c.getErrorStream():c.getInputStream();r.body=body==null?new byte[0]:read(body,2*1024*1024);return r;
  }finally{c.disconnect();}
 }
 static void verifyDefaultWorkspace(int port,String cookie)throws Exception{
  String json="{\"type\":\"client-request\",\"rpcId\":\"default-workspace\",\"method\":\"workspace/initializeDefault\",\"payload\":{\"args\":{}}}";
  Reply reply=request(port,"/api/workspace/initializeDefault",cookie,json);
  String value=new String(reply.body,StandardCharsets.UTF_8).replaceAll("\\s+","");
  yes(reply.status==200&&value.contains("\"ok\":true")&&
      value.contains("/dsh-workspace/deepseek-harness/default-workspace"),"ORIGINAL_WORKSPACE_PATCH_DEFAULT_RPC");
 }
 static void sendWs(OutputStream out,int opcode,byte[] data)throws Exception{
  if(data.length>65535)throw new IOException("CONTROL_WS_BOUND");byte[] mask=new byte[4];new SecureRandom().nextBytes(mask);out.write(0x80|opcode);if(data.length<126)out.write(0x80|data.length);else{out.write(0xfe);out.write(data.length>>>8);out.write(data.length&255);}out.write(mask);for(int i=0;i<data.length;i++)out.write(data[i]^mask[i%4]);out.flush();
 }
 static void workspaceStream(int port,String cookie)throws Exception{
  try(Socket socket=new Socket("127.0.0.1",port)){
   socket.setSoTimeout(8000);OutputStream out=socket.getOutputStream();InputStream in=socket.getInputStream();String key=Base64.getEncoder().encodeToString(new byte[16]);
   out.write(("GET /api/remote.mux HTTP/1.1\r\nHost: 127.0.0.1:"+port+"\r\nOrigin: http://127.0.0.1:"+port+"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: "+key+"\r\nCookie: "+cookie+"\r\n\r\n").getBytes(StandardCharsets.US_ASCII));out.flush();
   yes("HTTP/1.1 101 Switching Protocols".equals(line(in)),"actual_original_websocket_upgrade");Map<String,String> headers=new TreeMap<>(String.CASE_INSENSITIVE_ORDER);String row;while(!(row=line(in)).isEmpty()){int colon=row.indexOf(':');if(colon>0)headers.put(row.substring(0,colon),row.substring(colon+1).trim());}
   String expected=Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-1").digest((key+"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").getBytes(StandardCharsets.US_ASCII)));yes(expected.equals(headers.get("Sec-WebSocket-Accept")),"original_ws_accept_proof");
   sendWs(out,1,"{\"type\":\"open\",\"streamId\":\"one\",\"endpoint\":\"workspace/follow\",\"payload\":{\"args\":{}}}".getBytes(StandardCharsets.UTF_8));
   for(int frames=0;frames<5;frames++){
    DataInputStream data=new DataInputStream(in);int flags=data.readUnsignedByte(),length=data.readUnsignedByte();yes((flags&0x80)!=0&&(length&0x80)==0,"bounded_unmasked_complete_server_frame");int size=length&127;if(size==126)size=data.readUnsignedShort();else if(size==127)throw new AssertionError("control_ws_large_frame");byte[] bytes=new byte[size];data.readFully(bytes);
    if((flags&15)==9){sendWs(out,10,bytes);continue;}yes((flags&15)==1,"original_workspace_stream_text");String message=new String(bytes,StandardCharsets.UTF_8);
    yes(message.contains("\"type\":\"item\"")&&message.contains("\"type\":\"baseline\"")&&message.contains("/dsh-workspace"),"real_original_workspace_stream_baseline");
    sendWs(out,1,"{\"type\":\"cancel\",\"streamId\":\"one\"}".getBytes(StandardCharsets.UTF_8));return;
   }throw new AssertionError("original_workspace_stream_no_baseline");
  }
 }
 static void hostFence(int port,String cookie)throws Exception{
  try(Socket socket=new Socket("127.0.0.1",port)){
   socket.setSoTimeout(5000);socket.getOutputStream().write(("GET /api HTTP/1.1\r\nHost: evil.invalid\r\nCookie: "+cookie+"\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
   String status=line(socket.getInputStream());yes(status!=null&&status.startsWith("HTTP/1.1 403 "),"original_main_host_fence");
  }
  try(Socket socket=new Socket("127.0.0.1",port)){
   socket.setSoTimeout(5000);socket.getOutputStream().write(("GET /api/remote.mux HTTP/1.1\r\nHost: 127.0.0.1:"+port+"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
   String status=line(socket.getInputStream());yes(status!=null&&status.startsWith("HTTP/1.1 401 "),"original_main_unauthenticated_ws_rejected");
  }
 }
}
