#pragma once
#include "files.hpp"

#include <functional>
#include <memory>

namespace shgrep {
// MSBuild evaluation supplies actual Compile and ProjectReference items, including imports and conditions.
// The pool is used only while its language server's session mutex is held.
class DotnetProjects {
public:
    using Clock = std::chrono::steady_clock;
    using Check = std::function<void()>;
    using Evaluate = std::function<Json(const std::filesystem::path&, const std::string&)>;
    struct Plan {
        std::vector<std::filesystem::path> projects;
        std::string fingerprint;
        bool partial = false;
        bool syntax_only = false;
        std::vector<std::string> blockers;  // why the plan is partial: up to 5 projects and reasons
    };
    DotnetProjects();
    ~DotnetProjects();
    Plan prepare(const SearchContext& context, const SourceText* source, bool reverse, bool whole_workspace,
                 const Evaluate& evaluate, const std::function<bool(const SourceText&)>& in_profile,
                 const Check& check, const std::shared_ptr<std::atomic_bool>& cancelled,
                 std::chrono::milliseconds idle_timeout, size_t project_budget, Clock::time_point deadline,
                 bool touch_owners = true);
    bool contains_source(const std::filesystem::path& path) const;
    std::vector<std::string> sources() const;
    bool expire_idle(Clock::time_point now, std::chrono::milliseconds idle_timeout);
    void unloaded();
    Json status() const;
    size_t unevaluated() const;
    const std::vector<std::filesystem::path>& requested() const;

private:
    struct State;
    std::unique_ptr<State> state_;
};

}
