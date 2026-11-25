// A real Node HTTP parser with no routes; used only for malformed-host frames.
import http from 'node:http';
import {pathToFileURL} from 'node:url';
const {installHttpTransport}=await import(pathToFileURL(process.argv[2]));
const transport=await installHttpTransport();
if(process.argv[3]==='early-exit'){process.stderr.write('ORIGINAL_STARTUP_EXIT_BEFORE_LISTEN\n');process.exitCode=7;await transport.close();}
else http.createServer().listen(0,'127.0.0.1');
