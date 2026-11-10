/**
 * Standalone optional QQ settings model-picker source.
 *
 * Injected as a separate React component, not as hooks inside ConfigPanel.
 * No automatic network I/O, no QQ SDK hooks, no credential read.
 * If this component cannot load its catalog, the official form stays intact.
 */
export const PICKER_SOURCE = String.raw`
function QMobilePicker({ form, patch }) {
  const [qmModels, qmSetModels] = (0, react.useState)([]);
  const [qmBusy, qmSetBusy] = (0, react.useState)(false);
  const [qmStatus, qmSetStatus] = (0, react.useState)("点击读取可用模型，或者继续使用下方手动输入。");
  const qmAbort = (0, react.useRef)(null);
  (0, react.useEffect)(() => () => {
    try { qmAbort.current?.abort(); } catch (_) {}
  }, []);
  const qmLoad = () => {
    if (qmBusy) return;
    let controller;
    try { controller = new AbortController(); }
    catch (_) { qmSetStatus("无法使用当前浏览器网络接口，可在 QQ 中发送 /model 选择。"); return; }
    qmAbort.current?.abort();
    qmAbort.current = controller;
    qmSetBusy(true);
    qmSetStatus("正在读取 DSH 已注册模型…");
    const timer = setTimeout(() => controller.abort(), 7000);
    Promise.resolve().then(() => globalThis.fetch("/qqbot/q-mobile/models", {
      method: "GET", cache: "no-store", credentials: "same-origin",
      signal: controller.signal
    })).then(response => {
      if (!response || !response.ok) throw Error("MODEL_CATALOG_UNAVAILABLE");
      return response.json();
    }).then(data => {
      if (controller.signal.aborted) return;
      const models = Array.isArray(data?.models) ? data.models.filter(m =>
        m && typeof m.provider === "string" && typeof m.id === "string" &&
        m.provider.length > 0 && m.provider.length <= 96 &&
        m.id.length > 0 && m.id.length <= 200 &&
        !/[<>]/.test(m.provider + m.id)).slice(0, 120) : [];
      qmSetModels(models);
      qmSetStatus(models.length
        ? "选择后点击底部保存；仅更改 QQ 插件默认模型。"
        : "宿主尚未提供模型目录，请在 QQ 内发送 /model 查看官方列表，或使用下方手动输入。");
    }).catch(() => {
      if (!controller.signal.aborted) qmSetStatus("模型列表读取失败，官方 Provider/Model 输入框仍可使用，也可在 QQ 中发送 /model。");
    }).finally(() => {
      clearTimeout(timer);
      if (qmAbort.current === controller) {
        qmAbort.current = null;
        qmSetBusy(false);
      }
    });
  };
  const selected = form?.provider && form?.model
    ? JSON.stringify([form.provider, form.model]) : "inherit";
  const known = qmModels.some(m => m.provider === form?.provider && m.id === form?.model);
  const qmSelect = event => {
    try {
      const value = event.target.value;
      if (value === "inherit") {
        patch("provider", "");
        patch("model", "");
        return;
      }
      const entry = JSON.parse(value);
      if (!Array.isArray(entry) || entry.length !== 2 ||
          typeof entry[0] !== "string" || typeof entry[1] !== "string") return;
      const allowed = qmModels.some(m => m.provider === entry[0] && m.id === entry[1]);
      if (!allowed) return;
      patch("provider", entry[0]);
      patch("model", entry[1]);
    } catch (_) { /* Invalid user-supplied option never crashes settings */ }
  };
  try {
    return (0, react.createElement)("div", {
      className: "imqb2-field", "data-q-mobile-model-picker": "0.1.9"
    },
      (0, react.createElement)("label", {
        className: "imqb2-label", htmlFor: "qm-safe-model-select"
      }, "模型快速选择"),
      (0, react.createElement)("select", {
        id: "qm-safe-model-select", value: selected, onChange: qmSelect,
        style: {width:"100%", minHeight:44, padding:"8px", color:"inherit",
          background:"var(--dsw-alias-bg-layer-3, #242424)",
          border:"1px solid var(--dsw-alias-border-l2, #777)", borderRadius:8}
      },
        (0, react.createElement)("option", {value:"inherit"}, "跟随 DSH 默认"),
        !known && selected !== "inherit"
          ? (0, react.createElement)("option", {value:selected}, "当前配置：" + form.provider + "/" + form.model)
          : null,
        ...qmModels.map(m => (0, react.createElement)("option", {
          key:m.provider + "/" + m.id, value:JSON.stringify([m.provider,m.id])
        }, (m.name || m.id) + " · " + m.provider + "/" + m.id))
      ),
      (0, react.createElement)("button", {
        type:"button", disabled:qmBusy, onClick:qmLoad,
        style:{alignSelf:"flex-start", padding:"7px 10px", minHeight:36,
          borderRadius:8, color:"inherit", border:"1px solid var(--dsw-alias-border-l2, #777)",
          background:"transparent"}
      }, qmBusy ? "读取中…" : "读取可用模型"),
      (0, react.createElement)("p", {className:"imqb2-hint", role:"status"}, qmStatus),
      (0, react.createElement)("p", {className:"imqb2-hint"},
        "仅修改官方配置草稿；保存后可能重启 QQ 插件。单个会话的模型切换请使用 QQ /model。")
    );
  } catch (error) {
    console.warn("[Q Mobile] Optional model picker unavailable:", error?.message || error);
    return null;
  }
}
`;
