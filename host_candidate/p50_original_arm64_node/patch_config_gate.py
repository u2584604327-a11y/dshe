#!/usr/bin/env python3
"""Disposable config-only handoff. Repository P47 remains fail-closed."""
from pathlib import Path
import os
import sys

OLD='''  public static Process configOrDeny(ProcessBuilder builder) throws IOException {
    return secondaryDeny(builder,2);
  }'''
NEW='''  public static Process configOrDeny(ProcessBuilder builder) throws IOException {
    categorize(builder);
    validateOriginalStreams(builder,2);
    P149OriginalBuilderWitness.observeWithoutLaunch(builder,2);
    return com.dsh.android.p50.P50OriginalEngineConfig.claim(builder);
  }'''


def transform(source):
    if source.count(OLD) != 1:
        raise RuntimeError('ORIGINAL_CONFIG_GATE_ANCHOR_CHANGED')
    candidate = source.replace(OLD, NEW)
    if candidate.replace(NEW, OLD) != source:
        raise RuntimeError('ORIGINAL_CONFIG_GATE_SCOPE_CHANGED')
    return candidate


if __name__ == '__main__':
    if any(os.environ.get(key) != value for key, value in {
        'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': 'u2584604327-a11y/dshe',
        'GITHUB_EVENT_NAME': 'pull_request', 'P51_SIDE_BY_SIDE': '1',
        'P47_NO_HOST_FALLBACK': '1', 'P50_FRESH_CONFIG_SIDECAR': '1',
        'P181_THREE_ORIGINAL_START_DENY': '1',
    }.items()):
        raise RuntimeError('ORIGINAL_CONFIG_GATE_DISPOSABLE_SIDECAR_ONLY')
    source, destination = map(Path, sys.argv[1:])
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(transform(source.read_text()))
    print('ORIGINAL_CONFIG_GATE_CONFIG_ONLY_AUTHENTICATED_HANDOFF=STATIC_NOT_RUNTIME')
