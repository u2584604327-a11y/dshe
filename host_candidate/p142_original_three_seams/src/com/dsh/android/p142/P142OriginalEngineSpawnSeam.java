// Unofficial scoped integration to pht88888888/DSHAPP (MIT).
package com.dsh.android.p142;

import java.io.IOException;
import com.dsh.android.p149.P149OriginalBuilderWitness;
import java.lang.ProcessBuilder;
import java.util.List;

/**
 * P142: three independently named original EngineManager ProcessBuilder seams.
 *
 * Only scoped, pinned production bundle+identity+FD+Binder broker can replace
 * DENY in a future separately reviewed change. This class intentionally
 * launches NOTHING and never uses host ProcessBuilder.start().
 *
 * Do not log or export command values, private paths, token, or environment.
 */
public final class P142OriginalEngineSpawnSeam {
  private static final String UNAVAILABLE =
      "P142_ISOLATED_PRODUCTION_BROKER_UNAVAILABLE_NO_HOST_FALLBACK";
  private P142OriginalEngineSpawnSeam() {}

  /** Diagnostic shape only; sensitive original argv/env values remain private. */
  private static void verify(ProcessBuilder builder, int kind)
      throws IOException {
    if (builder == null || builder.directory() == null ||
        builder.command() == null)
      throw new IOException("P142_MISSING_ORIGINAL_BUILDER");
    List<String> c = builder.command();
    if (c.size() < 5 || c.size() > 128 ||
        c.get(0) == null || !c.get(0).endsWith("/bin/node") ||
        c.get(1) == null ||
        !c.get(1).endsWith("/node_modules/@deepseek-ai/dsh/lib/bin.js") ||
        !"--profile".equals(c.get(2)) ||
        (!"web".equals(c.get(3)) && !"rescue".equals(c.get(3))) ||
        builder.redirectErrorStream() != (kind != 2))
      throw new IOException("P142_ORIGINAL_LAUNCH_SHAPE_DRIFT");
    if (kind == 2) {
      if (c.size() != 5 || !"web".equals(c.get(3)) ||
          !"--dump-config".equals(c.get(4)))
        throw new IOException("P142_CONFIG_PROBE_SHAPE_DRIFT");
      return;
    }
    int index = 4;
    int patches = 0;
    while (index + 1 < c.size() && "--patch".equals(c.get(index))) {
      String entry = c.get(index+1);
      if (entry == null || !entry.startsWith("/") ||
          entry.indexOf('\u0000') >= 0 || ++patches > 48)
        throw new IOException("P142_PATCH_PATH_SHAPE_DRIFT");
      index += 2;
    }
    if (kind == 1) {
      if (index + 2 >= c.size() ||
          !"--port".equals(c.get(index)) ||
          !"0".equals(c.get(index+1)))
        throw new IOException("P142_PROBE_EPHEMERAL_PORT_REQUIRED");
      index += 2;
    } else if (index + 2 < c.size()) {
      if (!"--port".equals(c.get(index)) ||
          !"0".equals(c.get(index+1)))
        throw new IOException("P142_MAIN_DYNAMIC_PORT_SHAPE_DRIFT");
      index += 2;
    }
    if (index != c.size() - 1 || !"--no-open".equals(c.get(index)))
      throw new IOException("P142_UNKNOWN_ORIGINAL_ENGINE_ARGUMENT");
  }

  public static Process probeOrDeny(ProcessBuilder original)
      throws IOException {
    verify(original,1);
    P149OriginalBuilderWitness.observeWithoutLaunch(original,1);
    throw new IOException(UNAVAILABLE);
  }
  public static Process configOrDeny(ProcessBuilder original)
      throws IOException {
    verify(original,2);
    P149OriginalBuilderWitness.observeWithoutLaunch(original,2);
    throw new IOException(UNAVAILABLE);
  }
  public static Process primaryOrDeny(ProcessBuilder original)
      throws IOException {
    verify(original,3);
    P149OriginalBuilderWitness.observeWithoutLaunch(original,3);
    throw new IOException(UNAVAILABLE);
  }
}
