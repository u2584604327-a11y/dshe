// One host-owned IPv4 loopback listener over authenticated, bounded Process
// pipes. No TCP bind/connect in the isolated runtime. Original HTTP parsing,
// routes, authentication, frontend and SSE stay in the original http.Server.
import http from 'node:http';
import https from 'node:https';
import { Duplex, Readable, Writable } from 'node:stream';
import { createHmac, timingSafeEqual } from 'node:crypto';

const CHUNK = 16384, WINDOW = 65536, MAX_CONNECTIONS = 16;
const H = { OPEN: 1, DATA: 2, END: 3, CLOSE: 4, ACK: 5, APP_DATA: 6, APP_END: 7, LOG_ACK: 8, SHUTDOWN: 9, LOG_CLOSE: 10 };
const N = { LISTEN: 16, DATA: 17, END: 18, CLOSE: 19, ACK: 20, LOG: 21, STOP: 22, APP_ACK: 24 };
const empty = Buffer.alloc(0);
function error(code) { return Object.assign(new Error(code), {code}); }
function int(value) { const bytes = Buffer.alloc(4); bytes.writeUInt32BE(value); return bytes; }
class Source {
  constructor(input) { this.iterator = input[Symbol.asyncIterator](); this.remaining = empty; }
  async take(length) {
    const result = Buffer.alloc(length); let copied = 0;
    while (copied < length) {
      if (this.remaining.length === 0) {
        const next = await this.iterator.next();
        if (next.done) throw error('E_DSH_IPC_EOF');
        this.remaining = next.value;
      }
      const n = Math.min(length - copied, this.remaining.length);
      this.remaining.copy(result, copied, 0, n); copied += n;
      this.remaining = this.remaining.subarray(n);
    }
    return result;
  }
}

/** Install before importing the original WebServer, using only the pipes
 * delivered by the verified isolated supervisor. This function grants no
 * authority to obtain those descriptors or to enable the production gate.
 */
export async function installHttpTransport({input = process.stdin, output = process.stdout} = {}) {
  const source = new Source(input);
  let hello;
  try { hello = await source.take(88); }
  catch (cause) { input.destroy(); throw cause; }
  if (hello.subarray(0, 8).toString('ascii') !== 'DSHHTTP1') {
    hello.fill(0); input.destroy(); throw error('E_DSH_IPC_HELLO');
  }
  const key = Buffer.from(hello.subarray(8, 40)), session = Buffer.from(hello.subarray(40, 72));
  const epoch = Buffer.from(hello.subarray(72, 80));
  const requestedPort = hello.readUInt32BE(80), port = hello.readUInt32BE(84);
  if (epoch.readBigUInt64BE() === 0n || epoch.readBigUInt64BE() > 0x7fffffffffffffffn ||
      requestedPort > 65535 || port < 1 || port > 65535 || (requestedPort !== 0 && requestedPort !== port)) {
    key.fill(0);hello.fill(0);input.destroy();throw error('E_DSH_IPC_LISTENER');
  }
  hello.fill(0); // retain only the independent key/session/epoch copies
  let sending = 0n, received = 0n, pending = 0, lastId = 0;
  let closed = false, listener = null, listening = false, normalStop = false;
  let writeTail = Promise.resolve();
  const sockets = new Map();
  const originalListen = http.Server.prototype.listen;
  const originalStdout = process.stdout, originalStderr = process.stderr;
  const originalStdinDescriptor = Object.getOwnPropertyDescriptor(process, 'stdin');
  const originalOutDescriptor = Object.getOwnPropertyDescriptor(process, 'stdout');
  const originalErrDescriptor = Object.getOwnPropertyDescriptor(process, 'stderr');
  const tag = (direction, header, payload) => createHmac('sha256', key).update(direction)
    .update(session).update(epoch).update(header).update(payload).digest();
  function send(type, id, payload = empty) {
    if (closed || payload.length > CHUNK || pending + payload.length + 53 > 2 * 1024 * 1024 ||
        sending === 0x7fffffffffffffffn) return Promise.reject(error('E_DSH_IPC_OUTPUT_BOUND'));
    const header = Buffer.alloc(21);
    header.write('DHF1', 0, 'ascii'); header[4] = type; header.writeBigUInt64BE(++sending, 5);
    header.writeUInt32BE(id, 13); header.writeUInt32BE(payload.length, 17);
    const frame = Buffer.concat([header, tag('N', header, payload), payload]);
    pending += frame.length;
    const writing = writeTail.then(() => new Promise((resolve, reject) => {
      if (closed) return reject(error('E_DSH_IPC_CLOSED'));
      output.write(frame, cause => cause ? reject(cause) : resolve());
    })).finally(() => { pending -= frame.length; });
    // Keep the queue's rejection contained even when a caller concurrently
    // closes. The initiating operation still receives its own rejection.
    writeTail = writing.catch(() => {});
    return writing;
  }
  const control = (type, id, payload) => { send(type, id, payload).catch(fail); };
  function fail(cause) {
    if (closed) return;
    closed = true; key.fill(0);
    for (const socket of sockets.values()) socket.destroy(error('E_DSH_IPC_REVOKED'));
    sockets.clear(); applicationInput.destroy();
    for (const stream of logStreams) stream.destroy(error('E_DSH_IPC_REVOKED'));
    input.destroy();
    // Fixed diagnostic only: no credentials, request payload, URL or raw error.
    const code=typeof cause?.code==='string'&&/^[A-Z0-9_]{1,64}$/.test(cause.code)?cause.code:'E_DSH_IPC_INTERNAL';
    originalStderr.write('DSH_RUNTIME_TRANSPORT_DENY='+code+'\n');
    process.exitCode = 125;
  }
  class VirtualInput extends Readable {
    pendingAck = 0; ended = false;
    constructor(ack) { super({highWaterMark: CHUNK}); this.ack = ack; }
    _read() { if (this.pendingAck) { const n = this.pendingAck; this.pendingAck = 0; this.ack(n); } }
    accept(data) {
      if (this.ended || data.length === 0 || data.length + this.readableLength > WINDOW + CHUNK) throw error('E_DSH_IPC_INPUT_BOUND');
      if (this.push(data)) this.ack(data.length); else this.pendingAck += data.length;
    }
    endInput() { if (this.ended) throw error('E_DSH_IPC_DUPLICATE_EOF'); this.ended = true; this.push(null); }
  }
  class CreditWriter extends Writable {
    inFlight = 0; work = null;
    constructor(type, id) { super({highWaterMark: WINDOW}); this.type = type; this.id = id; }
    _write(bytes, encoding, callback) {
      this.work = {bytes, offset: 0, callback}; this.flushWindow();
    }
    flushWindow() {
      const work = this.work; if (!work) return;
      while (work.offset < work.bytes.length && this.inFlight < WINDOW) {
        const n = Math.min(CHUNK, WINDOW - this.inFlight, work.bytes.length - work.offset);
        const data = work.bytes.subarray(work.offset, work.offset + n);
        work.offset += n; this.inFlight += n;
        send(this.type, this.id, data).catch(cause => this.destroy(cause));
      }
      if (work.offset === work.bytes.length && this.inFlight === 0) { this.work = null; work.callback(); }
    }
    acknowledge(bytes) {
      if (bytes.length !== 4) throw error('E_DSH_IPC_CREDIT');
      const amount = bytes.readUInt32BE();
      if (amount === 0 || amount > this.inFlight) throw error('E_DSH_IPC_CREDIT');
      this.inFlight -= amount; this.flushWindow();
    }
    _destroy(cause, callback) {
      const work = this.work; this.work = null;
      if (work) work.callback(cause ?? error('E_DSH_IPC_CLOSED'));
      callback(cause);
    }
  }
  class VirtualSocket extends Duplex {
    inFlight = 0; work = null; pendingAck = 0; inputEnded = false; timer = null; idleMs = 0;
    constructor(id, address, remotePort) {
      super({allowHalfOpen: true, readableHighWaterMark: CHUNK, writableHighWaterMark: WINDOW});
      this.id = id; this.remoteAddress = address; this.remotePort = remotePort; this.remoteFamily = 'IPv4';
      this.localAddress = '127.0.0.1'; this.localPort = port; this.connecting = false;
      this.on('error', () => {}); // HTTP emits its own contained client error; no unhandled revoke
    }
    _read() { if (this.pendingAck) { const n = this.pendingAck; this.pendingAck = 0; control(N.ACK, this.id, int(n)); } }
    accept(data) {
      if (this.inputEnded || !data.length || this.readableLength + data.length > WINDOW + CHUNK) throw error('E_DSH_IPC_REQUEST_BOUND');
      this.touch(); if (this.push(data)) control(N.ACK, this.id, int(data.length)); else this.pendingAck += data.length;
    }
    endInput() { if (this.inputEnded) throw error('E_DSH_IPC_DUPLICATE_EOF'); this.inputEnded = true; this.push(null); }
    _write(bytes, encoding, callback) { this.work = {bytes, offset: 0, callback}; this.flushWindow(); }
    flushWindow = CreditWriter.prototype.flushWindow;
    acknowledge = CreditWriter.prototype.acknowledge;
    type = N.DATA;
    _final(callback) { send(N.END, this.id).then(() => callback(), callback); }
    _destroy(cause, callback) {
      clearTimeout(this.timer); sockets.delete(this.id);
      const work = this.work; this.work = null;
      if (work) work.callback(cause ?? error('E_DSH_IPC_CLOSED'));
      if (!closed) control(N.CLOSE, this.id);
      if (listener && !listening && sockets.size === 0) queueMicrotask(() => listener.emit('close'));
      callback(cause);
    }
    address() { return {address: this.localAddress, family: 'IPv4', port}; }
    setNoDelay() { return this; }
    setKeepAlive() { return this; }
    ref() { return this; }
    unref() { return this; }
    setTimeout(ms, callback) { this.idleMs = ms; if (callback) this.once('timeout', callback); this.touch(); return this; }
    touch() {
      clearTimeout(this.timer);
      if (this.idleMs > 0) { this.timer = setTimeout(() => this.emit('timeout'), this.idleMs); this.timer.unref(); }
    }
  }
  const applicationInput = new VirtualInput(n => control(N.APP_ACK, 0, int(n)));
  const logStreams = [new CreditWriter(N.LOG, 0), new CreditWriter(N.LOG, 1)];
  for (const stream of logStreams) { stream.isTTY = false; stream.on('error', cause => { if (!(stream.appClosed && cause?.code === 'EPIPE')) fail(cause); }); }
  applicationInput.on('error', fail);
  Object.defineProperty(process, 'stdin', {configurable: true, value: applicationInput});
  Object.defineProperty(process, 'stdout', {configurable: true, value: logStreams[0]});
  Object.defineProperty(process, 'stderr', {configurable: true, value: logStreams[1]});
  http.Server.prototype.listen = function(...args) {
    let requested, host, callback;
    if (typeof args[0] === 'object' && args[0] !== null) {
      if (Object.keys(args[0]).some(key => !['host', 'port'].includes(key))) throw error('E_DSH_IPC_LISTEN_OPTIONS');
      ({port: requested, host} = args[0]); callback = args[1];
    } else { [requested, host, callback] = args; if (args.length > 3) throw error('E_DSH_IPC_LISTEN_OPTIONS'); }
    if (closed || listener || this instanceof https.Server || requested !== requestedPort ||
        host !== '127.0.0.1' || (callback !== undefined && typeof callback !== 'function')) {
      throw error('E_DSH_IPC_LISTEN_DENIED');
    }
    listener = this; listening = true;
    this.address = () => listening ? {address: '127.0.0.1', family: 'IPv4', port} : null;
    Object.defineProperty(this, 'listening', {configurable: true, get: () => listening});
    this.getConnections = callback => queueMicrotask(() => callback(null, sockets.size));
    this.closeAllConnections = () => { for (const socket of sockets.values()) socket.destroy(); };
    this.close = callback => {
      if (!listening) { if (callback) queueMicrotask(() => callback(error('ERR_SERVER_NOT_RUNNING'))); return this; }
      listening = false; if (callback) this.once('close', callback);
      control(N.STOP, 0);
      if (sockets.size === 0) queueMicrotask(() => this.emit('close'));
      return this;
    };
    if (callback) this.once('listening', callback);
    send(N.LISTEN, 0, int(port)).then(() => this.emit('listening'), fail);
    return this;
  };
  const reading = (async () => {
    for (;;) {
      const envelope = await source.take(53), header = envelope.subarray(0, 21);
      if (header.subarray(0, 4).toString('ascii') !== 'DHF1') throw error('E_DSH_IPC_FRAME');
      const type = header[4], seq = header.readBigUInt64BE(5), id = header.readUInt32BE(13), length = header.readUInt32BE(17);
      if (seq !== received + 1n || seq > 0x7fffffffffffffffn || length > CHUNK || id > 0x7fffffff) throw error('E_DSH_IPC_FRAME');
      const data = await source.take(length);
      if (!timingSafeEqual(envelope.subarray(21), tag('H', header, data))) throw error('E_DSH_IPC_AUTH');
      received = seq;
      if (type === H.APP_DATA) { if (id) throw error('E_DSH_IPC_APP_ID'); applicationInput.accept(data); continue; }
      if (type === H.APP_END) { if (id || length) throw error('E_DSH_IPC_APP_EOF'); applicationInput.endInput(); continue; }
      if (type === H.LOG_ACK) { if (id > 1) throw error('E_DSH_IPC_LOG_ID'); logStreams[id].acknowledge(data); continue; }
      if (type === H.LOG_CLOSE) {
        if (id > 1 || length) throw error('E_DSH_IPC_LOG_CLOSE');
        logStreams[id].appClosed = true; logStreams[id].destroy(error('EPIPE')); continue;
      }
      if (type === H.SHUTDOWN) { if (id || length) throw error('E_DSH_IPC_STOP'); process.kill(process.pid, 'SIGTERM'); continue; }
      if (type === H.OPEN) {
        if (!listening || id !== lastId + 1 || !id || length !== 8 || data[0] !== 127 ||
            data.readUInt32BE(4) < 1 || data.readUInt32BE(4) > 65535 || sockets.size >= MAX_CONNECTIONS) throw error('E_DSH_IPC_OPEN');
        lastId = id;
        const socket = new VirtualSocket(id, [...data.subarray(0, 4)].join('.'), data.readUInt32BE(4));
        sockets.set(id, socket); listener.emit('connection', socket); continue;
      }
      if (![H.DATA, H.END, H.CLOSE, H.ACK].includes(type) || !id || id > lastId) throw error('E_DSH_IPC_CONNECTION');
      const socket = sockets.get(id); if (!socket) continue; // never reused ids, safe late-frame discard
      if (type === H.DATA) socket.accept(data);
      else if (type === H.ACK) socket.acknowledge(data);
      else { if (length) throw error('E_DSH_IPC_TERMINAL'); if (type === H.END) socket.endInput(); else socket.destroy(); }
    }
  })().catch(cause => { if (!normalStop) fail(cause); });
  return {
    port, requestedPort, reading,
    // The owner disposes its original services before ending the transport.
    async close() {
      if (closed) return; normalStop = true;
      for (const socket of sockets.values()) socket.destroy();
      await Promise.all(logStreams.map(stream => stream.destroyed ? Promise.resolve() : new Promise((resolve, reject) => stream.end(cause => cause ? reject(cause) : resolve()))));
      await send(N.STOP, 0); await writeTail;
      closed = true; key.fill(0); input.destroy(); applicationInput.destroy();
      http.Server.prototype.listen = originalListen;
      Object.defineProperty(process, 'stdin', originalStdinDescriptor);
      Object.defineProperty(process, 'stdout', originalOutDescriptor);
      Object.defineProperty(process, 'stderr', originalErrDescriptor);
    },
  };
}
