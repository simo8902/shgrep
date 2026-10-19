#pragma once
#include <string>

namespace shgrep {
// CONTRACT: every failure the user must hear about (a language server, the reranker, the session health check)
//   reaches the model as one line "[<KIND> - tell the user about this in your next message, before continuing:
//   <detail>. <fallback>]". .claude/hooks/lsp-failure-notify.py matches that shape to show it to the user directly,
//   so keep it stable. fallback says what the output below it is, or that there is none.
inline std::string failure_banner(const std::string& kind, const std::string& detail, const std::string& fallback) {
    return "[" + kind + " - tell the user about this in your next message, before continuing: " + detail + ". " + fallback + "]\n";
}
}
