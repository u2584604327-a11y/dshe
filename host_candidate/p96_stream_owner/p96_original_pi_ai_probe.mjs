/**
 * The real DSH provider imports openAICompletionsApi from this lazy
 * pi-ai submodule. Introspect the exact original contract, never fabricate.
 */
import * as pi from '@earendil-works/pi-ai';
import * as completions from '@earendil-works/pi-ai/api/openai-completions.lazy';

if(!Object.keys(pi).length) {
  process.stdout.write('P96_ORIGINAL_PI_AI_ROOT_IMPORT=FAIL\n');
  process.exitCode=2;
} else process.stdout.write('P96_ORIGINAL_PI_AI_ROOT_IMPORT=PASS\n');

const api=completions.openAICompletionsApi;
const apiType=typeof api;
const descriptors=api==null ? [] : Object.getOwnPropertyNames(api)
  .filter(n=>/api|load|stream|create|value|get/i.test(n));
process.stdout.write('P96_ORIGINAL_COMPLETIONS_EXPORTS='+JSON.stringify(Object.keys(completions))+'\n');
process.stdout.write('P96_ORIGINAL_COMPLETIONS_ADAPTER_TYPE='+apiType+'\n');
process.stdout.write('P96_ORIGINAL_COMPLETIONS_ADAPTER_KEYS='+JSON.stringify(descriptors)+'\n');
if(api==null || !['object','function'].includes(apiType)){
  process.stdout.write('P96_ORIGINAL_COMPLETIONS_ADAPTER=UNAVAILABLE\n');
  process.exitCode=2;
} else process.stdout.write('P96_ORIGINAL_COMPLETIONS_ADAPTER_IMPORTED=PASS\n');
// No stream or tool-result claim until a valid, real callable transport is observed.
process.stdout.write('P96_ORIGINAL_COMPLETIONS_STREAM_E2E=NOT_TESTED\n');
