// A real Node HTTP parser with no routes; used only for malformed-host frames.
import http from 'node:http';
import {pathToFileURL} from 'node:url';
const {installHttpTransport}=await import(pathToFileURL(process.argv[2]));
await installHttpTransport();http.createServer().listen(0,'127.0.0.1');
