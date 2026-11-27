#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
python3 -m py_compile patch_original_browser.py test_patch_contract.py kotlin_syntax_smoke.py p190_fullscreen_kotlin_smoke.py
python3 test_patch_contract.py
mkdir -p .p189-tests-java .p189-tests-kotlin .p190-tests-fullscreen
javac --release 8 -Xlint:-options -d .p189-tests-java BrowserOperationLease.java BrowserOperationLeaseTest.java
java -cp .p189-tests-java com.dsh.android.browser.BrowserOperationLeaseTest
python3 kotlin_syntax_smoke.py
kotlinc -nowarn -classpath .p189-tests-java -d .p189-tests-kotlin \
  P189BridgeKotlinCompileStub.kt P189CookieStub.kt P191KotlinLifecycleTest.kt
kotlin -classpath .p189-tests-java:.p189-tests-kotlin \
  com.dsh.android.browser.P191KotlinLifecycleTestKt
python3 p190_fullscreen_kotlin_smoke.py
kotlinc -nowarn -d .p190-tests-fullscreen P190ExactFullscreenKotlinStub.kt
kotlin -classpath .p190-tests-fullscreen com.dsh.android.browser.P190ExactFullscreenKotlinStubKt
printf '%s\n' P191_LOCAL_JAVA_AND_KOTLIN_SMOKE=PASS
