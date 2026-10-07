# Making `shgrep` Faster Than ripgrep on Windows Without a Content Index

## Bottom line

Your data does **not** support one single “10–25 ms per-file/I/O gap” diagnosis. There are three different problems:

| Workload | shgrep | rg 15.1 | shgrep gap | Wall-equivalent gap / 6,920 files | Diagnosis |
|---|---:|---:|---:|---:|---|
| 1 literal, no match | 103 ms | 107 ms | **−4 ms** | −0.58 µs/file | You already win; don't disturb this path |
| 1 regex, no match | 98 | 70 | **+28 ms** | 4.05 µs/file | regex fast-path / per-file matcher overhead |
| 100 literals | 83 | 71 | **+12 ms** | 1.73 µs/file | literal-set engine |
| 1000 literals | 97 | 73 | **+24 ms** | 3.47 µs/file | literal-set engine, not primarily I/O |
| 100 regexes | 166 | 69 | **+97 ms** | 14.02 µs/file | overwhelmingly regex-engine architecture |
| common literal, `-l` | 74 | 81 | **−7 ms** | — | you already win |
| common regex, `-l` | 74 | 83 | **−9 ms** | — | you already win |
| backreference | 667 | 116 | **+551 ms** | 79.62 µs/file | fallback engine is the emergency |

Those figures are from your measurements; the “µs/file” column is only a wall-time normalization, not literal CPU time per file. With twelve active workers, a 28 ms wall gap can represent roughly 0.34 CPU-seconds of aggregate work, or about 49 µs/file if all workers were saturated.

More importantly, your directory-only result is **9 ms versus rg's 25 ms**. Treating that 16 ms walker advantage as approximately additive—not strictly valid, but useful diagnostically—means that shgrep's post-enumeration path is roughly **44 ms worse for one regex, 40 ms worse for 1000 literals, and 113 ms worse for 100 regexes** before it emerges at the wall clock. The fact that the deficit expands by another ~69 ms merely by going from one regex to 100 regexes over exactly the same files proves that Windows `CREATE` cost cannot be the whole explanation.

My main conclusion is therefore:

> **Do not try to make Hyperscan universally faster. Dispatch different pattern classes to different engines.** Keep Hyperscan where it wins, but use an rg-style lazy-DFA/prefilter engine for ordinary regexes, PCRE2 JIT for Perl features, and a dedicated literal-set engine for large fixed-string sets.

That is the highest-probability route to beating ripgrep because you already have the part ripgrep cannot easily copy: a materially faster Windows walker.

My ranked implementation order is:

| Rank | Change | Representative gain on your benchmark | Confidence | Effort | `(gain × confidence)/effort` | Scope |
|---:|---|---:|---:|---:|---:|---|
| 1 | Replace Chimera/PCRE1 fallback with **PCRE2 JIT**, then selectively prefilter | **350–550 ms** | 0.90 | 2 | ~203 | backrefs/lookaround |
| 2 | Add **regex-automata-style lazy-DFA/meta-regex path** for ordinary regex sets | **40–90 ms** | 0.75 | 3 | ~16 | 1/100 regex |
| 3 | Add **mandatory-literal SIMD prefilter + pattern-group DBs** | **10–50 ms** | 0.70 | 3 | ~7 | regex no-match |
| 4 | Add a **dedicated literal-set engine** instead of always using Hyperscan | **8–25 ms** | 0.65 | 3 | ~4 | 100/1000 literals |
| 5 | Fuse classification/prefilter and tighten the **single-read Windows path** | **3–15 ms** | 0.65 | 2 | ~3 | all files |

`hs_scan_vector` batching is worth an experiment only after measuring fixed `hs_scan` cost; I would **not** put it in the top five. Generic cross-file Hyperscan batching is incorrect under your semantics.

## Why ripgrep is still ahead

**Ripgrep's key advantage is not a faster general regex VM. It is avoiding general regex work whenever possible.** The current Rust regex stack automatically builds prefilters when it can, has explicit support for many-pattern regexes, and composes several engines rather than forcing every haystack through one runtime. `regex-automata::meta::Regex` uses engines such as a lazy DFA for high-throughput searching and falls back to more capable machinery as necessary; its automatic prefiltering is enabled by default. The lazy DFA computes transitions on demand and maintains a bounded cache, abandoning it for another engine if cache clearing becomes pathological. citeturn14view3turn15search9

Literal extraction is a deliberate part of that architecture. `regex-syntax` exposes extraction from regex HIR specifically because looking for a literal first can be substantially faster than executing the complete regex. The current extractor works with prefix/suffix literal sequences, while the regex meta-engine automatically chooses usable prefilters. citeturn16search0turn16search15

Ripgrep's searcher is also built around **incremental fixed-size buffering for normal line-oriented searches**, rather than requiring a whole-file allocation before ordinary matching; whole-haystack behavior becomes necessary for multiline modes. Its own searcher documentation warns that memory mapping can lose on workloads involving rapid open/scan/close of many files, which matches your decision not to mmap this workload. citeturn14view4

At the primitive level, the Rust ecosystem's `memchr` routines dispatch to AVX2 on x86-64 when available. That matters because an extracted one-byte or short literal turns a regex search into an extremely cheap vectorized candidate locator. citeturn15search5

For many patterns, the same ecosystem exposes true multi-pattern regex construction (`Regex::new_many`) and an API to determine which patterns matched. It also exposes explicit per-thread `Cache` objects precisely to avoid the internal cache-pool synchronization cost that can become visible when many threads repeatedly search small haystacks—a description strikingly similar to your 6,920-file workload. citeturn15search9

Hyperscan is doing considerably more fixed work at every file boundary. Its `hs_scan()` implementation validates the database and scratch, marks scratch as in use, checks minimum widths, prefetches data, populates core runtime state, clears exhaustion/logical state where needed, handles boundary programs, initializes state and only then dispatches to the actual matching machinery. citeturn19view0turn19view1

That does **not** mean Hyperscan is bad at small inputs. Quite the opposite: Rose has an explicit small-block optimization that replaces separate anchored/floating work with one coalesced HWLM literal scan when possible. For a pure-literal database, Hyperscan has an even shorter path that initializes its scratch state and calls the HWLM matcher directly. citeturn19view1turn19view2 This is why I would not blindly put a second Teddy-like pass in front of your 1000-literal Hyperscan DB: you can easily spend memory bandwidth reproducing filtering Hyperscan already performs internally.

Hyperscan's design comes from a different optimization target. Its decomposition architecture factors regexes into SIMD-friendly string matching plus automata, which is excellent for sustained throughput and large rule sets. citeturn12search0 Your workload, however, has about **11.3 KiB per file on average** (80 MB / 6,920), so thousands of resets between small independent records are unusually important.

The Hyperscan source makes this distinction visible:

```text
file
  -> hs_scan fixed setup
  -> boundary/state initialization
  -> small-block/HWLM or Rose
  -> end-of-data/SOM flushing
  -> tear down per-block state

next file
  -> repeat
```

Whereas the rg family can often reduce a no-match regex file to conceptually:

```text
file buffer
  -> extracted-literal SIMD search
  -> literal absent?
       yes -> done
       no  -> DFA/regex confirmation near candidate
```

Hyperscan itself advises allocating scratch outside the scan path and retaining one scratch per concurrent context, which you should already be doing. It also says block mode should be preferred to streaming when input naturally consists of discrete blocks. citeturn14view0turn14view1

This leads to a fairly sharp interpretation of your benchmarks:

1. **One literal is solved.** You beat rg by 4 ms and win the common-word `-l` test by 7 ms. A fancy new literal scanner that regresses these is a failure.

2. **One regex is a candidate-rejection problem.** The 28 ms wall deficit is consistent with rg frequently converting a regex into a cheap literal-prefilter search while shgrep enters `hs_scan()` on every text file.

3. **The 1000-literal deficit is a literal-set-engine problem.** The input/open path is identical to your one-literal case, yet the result moves from a 4 ms win to a 24 ms loss. That's strong evidence against blaming all of it on `NtCreateFile`.

4. **The 100-regex deficit is definitely an engine-selection problem.** The same 80 MB and same ~6,920 opens suddenly cost another ~69 ms relative to your one-regex result. I/O cannot explain that delta.

5. **The backreference result says “replace the fallback” in 72-point font.** Ripgrep's `-P` path is based on PCRE2; your Chimera stack uses the old PCRE generation. PCRE2's current JIT generates native code for complete matching and has compiler/start-position optimizations such as minimum-length and required-code-unit tests that can reject a subject before full matching begins. citeturn21search0turn21search4turn21search6

There is also a subtle but important implication from your `-l` numbers: when both tools may terminate after the first useful match in each file, **your system is already competitive or better**. That suggests your open/read/walker design is fundamentally good enough. The biggest remaining wins are on exhaustive no-match scans and expensive pattern sets.

## Scanner algorithms to implement

**1. Add a second regular-expression engine and dispatch before Hyperscan.**

The most direct way to inherit the algorithmic advantage behind rg is to statically link a tiny Rust C-ABI library around `regex-automata`, while keeping the rest of shgrep C++20. `regex-automata::meta::Regex::new_many` natively represents multiple patterns, automatically builds prefilters, can use a lazy DFA, and provides explicit per-thread caches. citeturn15search9turn14view3

I would initially use it as a **negative oracle**, not as a wholesale semantics replacement:

```text
compile pattern set
       |
       +-- regex-automata-compatible?
               |
               +-- yes -> build meta::Regex + one Cache/worker
               |
               +-- no  -> existing HS/PCRE path

per file:
    regex_automata::is_match_with(cache, file)
        false -> final "no match"; do NOT call Hyperscan
        true  -> hs_scan(file) for your existing exact reporting semantics
```

That gives you a low-risk deployment path: a false result is final, while positive files still use your proven Hyperscan match reporting. For the 100-regex **no-match** benchmark, this potentially removes Hyperscan entirely and makes your scanner structurally similar to rg's, while retaining your 16 ms walker advantage.

After validating semantic equivalence, let regex-automata become the primary matcher for ordinary regexes whose requested output semantics it can provide directly. Its lower-level search APIs accept a caller-owned cache, avoiding the internal cache pool specifically for small-haystack/high-concurrency workloads. citeturn15search9

Implementation shape:

```cpp
enum class Engine {
    SingleLiteral,
    LiteralSet,
    RustMetaRegex,
    Hyperscan,
    Pcre2
};

struct PatternPlan {
    Engine primary;
    Engine confirmation;
    PatternCapabilities caps;
    CompiledPatternHandle compiled;
};
```

For each worker, allocate regex-automata cache state just as you already allocate Hyperscan scratch. Do **not** acquire a shared regex cache for every file.

Expected effect on your 100-regex/no-match case: **roughly 40–90 ms**, with the upper end achievable if most of the current 97 ms gap is Rose/HWLM/NFA work avoided by the meta engine. The decisive experiment is to run the same 100-pattern set through `meta::Regex::is_match_with` over the buffers you already loaded, with all filesystem work disabled.

The compile-time objection is weak here. The reason you originally paid ~85 ms for 100 Hyperscan regexes is no longer relevant after your disk DB cache; and for MCP, compiled state lives in memory anyway. Also, compiled matcher state is explicitly allowed by your caching rule.

**2. Build a conservative required-literal plan and make it a file-level gate.**

Do not extract a “likely literal.” Extract a literal that is **logically necessary for every possible match**. Any uncertainty means “unfilterable.”

A conservative HIR analysis is straightforward:

```text
literal "abc"         -> required {"abc"}

A concatenated with B -> any requirement known to occur in A
                         and any requirement known to occur in B
                         remain mandatory

A | B                 -> only requirements guaranteed by both branches

A? or A{0,n}          -> none from A

A+ or A{1,n}          -> mandatory requirements from A

singleton class [x]   -> "x"

general class         -> none unless expanded safely

assertion             -> consumes nothing; no new required literal
```

For alternations, don't require literal equality if you are willing to represent a required **set**: `(foobar|foobaz)` can be filtered by `{foobar, foobaz}` because at least one member must occur. The Rust regex parser/HIR is already designed for this kind of analysis and exposes literal extraction explicitly as a search optimization. citeturn16search0turn16search9turn16search24

Compile the result into:

```cpp
struct PrefilterPlan {
    std::vector<Needle> needles;
    std::vector<GroupMask> needle_to_groups;
    GroupMask always_scan;
};
```

Then split the Hyperscan DB into perhaps 8–32-pattern groups. A group is scanned only if its required-literal gate fired; expressions for which no safe gate exists live in `always_scan`.

That grouping matters. A single global prefilter only lets you skip Hyperscan when **none of 100 expressions is plausible**. With groups, a file that contains a candidate for two regexes does not force you to execute the 100-regex union DB. Hyperscan's own performance guidance says separate databases are preferable when only subsets are relevant instead of scanning an unnecessarily large union and discarding irrelevant results afterwards. citeturn14view0

Use pattern-only statistics to select discriminative factors. A static source-code byte-frequency table is legal under your rules because it isn't learned from or cached for the searched tree. Prefer longer factors and uncommon punctuation/case combinations.

For a single required literal, your C++ AVX2 prefilter can be extremely small:

```text
needle = "somethingRare"

pick offsets i,j with discriminative bytes

for 32 candidate starts:
    a = load32(hay + i)
    b = load32(hay + j)
    mask = eq(a, needle[i]) & eq(b, needle[j])

    for set bits:
        verify full literal
```

For length one, use `memchr`; for length two, compare both bytes; for longer needles, this two-position fingerprint normally reduces full compares dramatically. Rust's `memchr` package confirms that AVX2 vectorized byte search is the expected baseline on x86-64. citeturn15search5

The best version **fuses this with the pass you already make for NUL/high-bit classification**. One 32-byte AVX2 load can contribute to:

```text
zero-byte detection
ASCII/high-bit detection
required-byte/fingerprint filtering
```

instead of running:

```text
SSE classification pass
+ SIMD prefilter pass
+ Hyperscan pass
```

For one-regex no-match source-code searches with a strong literal, I would target **10–25 ms off the current 98 ms**. For 100 regexes containing distinctive mandatory text, **20–50 ms** is realistic enough to justify the work.

The major caveat is your 1000-literal case: an extra prefilter is probably the wrong algorithm there. With 1000 independent literals, the chance that at least one cheap fingerprint appears in any 10 KiB source file becomes high, so you pay an additional complete pass and still enter Hyperscan.

**3. Give literals their own final matcher instead of using a regex engine as a literal engine.**

Your data already tells you the dispatch thresholds should not be “Hyperscan for all fixed strings”:

```text
1 literal:       shgrep wins by 4 ms
100 literals:    shgrep loses by 12 ms
1000 literals:   shgrep loses by 24 ms
```

Implement three literal regimes:

```text
1 literal
    -> AVX2 substring search / memmem-style fingerprint

small literal set
    -> Teddy-style packed SIMD candidate search

large literal set
    -> Aho-Corasick family or benchmark against Hyperscan FDR/HWLM
```

For the large-set case, I would **benchmark the Rust `aho-corasick`/regex ecosystem through the same C ABI before spending months writing a C++ Teddy implementation**. The rg/regex ecosystem historically switches between packed SIMD/Teddy-style searching and automaton-based approaches according to the literal set, rather than treating all sets identically. Its underlying primitives are vector accelerated. citeturn15search5turn15search9

A final literal matcher has a major advantage over a literal *prefilter*: there's no confirmation scan. For each match you already know:

```text
pattern ID
end offset
start = end - literal_length[pattern_id]
```

so exact byte offsets are trivial, and line accounting remains your existing lazy newline-counting path.

Do not force one algorithm for all 1000 sets. Compile pattern metadata once and choose by measured cost:

```text
total literal bytes
number of literals
shortest literal
number of 1-byte / 2-byte needles
case sensitivity
estimated Teddy bucket occupancy
automaton size
```

Benchmark each compiled pattern plan against a representative 80 MB corpus once during development, then hard-code thresholds; do not inspect or cache target-tree contents to select them.

The expected win is **8–25 ms** on your 100/1000-literal no-match cases. The attractive fact is that you only need to recover 24 ms to equal rg at 1000 literals, and your walker gives you headroom beyond that.

**4. Do not generically concatenate files for `hs_scan_vector`. There is one useful safe subset.**

Hyperscan's documentation is unambiguous: vectored scanning behaves as though all supplied blocks were concatenated into one logical input, or fed successively to one streaming matcher. Therefore **a vector element is not a regex reset boundary**. citeturn14view1

This is wrong:

```text
[file A, file B, file C] -> one hs_scan_vector()
```

because a pattern can begin at the end of A and finish at the beginning of B. `^`, `$`, end-of-data behavior, start-of-match state and single-match exhaustion can also differ from one independent scan per file.

There is no universal separator for arbitrary byte regexes. Any byte sequence you choose can be consumed by something such as `.*`, a negated class, `[\s\S]`, an explicit byte class or an unbounded repetition.

There is, however, a rigorous **pure-literal** batching construction.

Let `Lmax` be the longest literal. Put a guard of `Lmax` bytes between files:

```text
file0 | GGG...G (Lmax bytes) | file1 | GGG...G | file2
```

A literal whose length is at most `Lmax` cannot start in one real file and reach the next real file, because crossing the entire guard requires more than `Lmax` bytes. Matches lying partly or wholly inside guard intervals are simply discarded.

You do not even need to copy the files if you compile a vectored-mode DB:

```text
vectors = [
    file0,
    guard,
    file1,
    guard,
    file2,
    ...
]
```

Maintain prefix lengths. Hyperscan reports logical offsets in the concatenated input model; map a match to a file only when `[from,to)` lies completely within that file's interval. Because callbacks arrive in increasing scan progression, attribution can use a moving interval cursor rather than a binary search per match. citeturn14view1

Restrictions:

- use this only with pure literals;
- compile a separate `HS_MODE_VECTORED` database;
- do not use per-expression `HS_FLAG_SINGLEMATCH`, because a match in file A could exhaust that expression for subsequent files;
- discard every match touching a guard;
- cap batches, e.g. 32–128 files, so workers don't sit waiting for huge batches;
- keep the existing block DB for matched-heavy or latency-sensitive workloads.

For bounded-width regexes you could theoretically use a guard longer than the maximum possible match, but anchors, EOD programs, zero-width assertions, SOM and single-match state make proving file-local equivalence substantially more complicated. I would not ship it.

Also temper expectations: Hyperscan's own performance guide says buffering inputs into larger writes generally provides little benefit unless writes are extremely tiny, on the order of a couple of bytes. citeturn14view0 Therefore first measure:

```text
hs_scan(db, 64 B)
hs_scan(db, 256 B)
hs_scan(db, 1 KiB)
hs_scan(db, 4 KiB)
hs_scan(db, 16 KiB)
hs_scan(db, 64 KiB)
```

against already resident buffers, one scratch per pinned worker, no filesystem. If extrapolated fixed cost across 6,920 calls is below ~3 ms wall, drop batching completely. If it is 8–15 ms, pure-literal vector batching becomes interesting.

**5. Exploit file-existence mode harder.**

Your `-l` wins show an important specialization: for files-only output you care only about the first match in a file. Both the Rust regex meta engine and Hyperscan permit early termination; regex-automata's boolean `is_match` is explicitly allowed to stop once future input cannot change the answer. citeturn15search9

Make `SearchMode::FilesWithMatches` a first-class compilation mode rather than an output flag applied to a generic scan:

```text
no SOM
no match-start recovery
boolean prefilter
earliest possible termination
no line calculation
no stored match vector
```

You're already doing enough of this to win by 7–9 ms, so this is mostly a “do not regress it” constraint for the other changes.

## PCRE-compatible patterns and the 100-regex problem

Your biggest easy win is to **remove Chimera from the critical fallback path**.

Your benchmark is:

```text
shgrep Chimera/PCRE1:   667 ms
ripgrep -P / PCRE2:     116 ms
difference:             551 ms
```

Do not start by building a more elaborate Hyperscan→PCRE hybrid. Chimera is already fundamentally that family of design. Start with the same generation of confirmation engine ripgrep uses: **current PCRE2 with JIT**.

PCRE2's current API documents that JIT can greatly speed many patterns; `pcre2_match()` automatically uses available JIT code, while `pcre2_jit_match()` offers a more direct interface with less checking. PCRE2 also performs start optimizations at compile time, including minimum-match-length and required-code-unit tests that can reject impossible subjects without doing general matching. citeturn21search0turn21search4turn21search6

The initial implementation should therefore be almost boring:

```text
pcre2_compile()
pcre2_jit_compile(..., PCRE2_JIT_COMPLETE)

one match_context / worker
one JIT stack / worker

per file:
    pcre2_jit_match(...)
```

Cache compiled PCRE2 patterns exactly as you already cache compiled Hyperscan pattern databases; this is explicitly a compiled-pattern cache and satisfies your constraint.

Do **not** use PCRE2 partial mode merely to process arbitrary file chunks unless you need it. PCRE2 documents that partial mode disables some normal fast-failure optimizations, including a remembered last literal and minimum-match-length shortcut. citeturn21search10 Your one-buffer-per-file architecture is actually favorable here.

Only after direct PCRE2 JIT is measured should you test this hybrid:

```text
safe mandatory-literal / HS_PREFILTER scan
          |
          +-- no candidate -> no match
          |
          +-- candidate    -> PCRE2 JIT over original subject
```

Crucially, first use Hyperscan/prefilter as a **file-level yes/no gate**. Do not assume a Hyperscan prefilter callback gives you a sufficiently tight region in which a backtracking engine may safely execute. Prefilter mode intentionally permits false positives, and constructs involving lookbehind or variable-length context can require bytes before a candidate. Hyperscan exposes prefilter compilation specifically to permit unsupported constructs to be approximated conservatively. citeturn14view2

A more aggressive optimization is **candidate-line PCRE2 confirmation**, but only after static proof that the expression is line-local.

Your eligibility predicate should reject at least:

```text
explicit \n or \r consumption
DOTALL / (?s)
classes capable of consuming newline
absolute subject anchors
lookbehind that reaches before the candidate line
constructs with semantics depending on subject start/end
```

Then:

```text
mandatory literal search
    -> candidate literal positions
    -> map positions to line intervals
    -> deduplicate candidate lines
    -> PCRE2 JIT only candidate lines
```

That is exactly the sort of architecture that makes grep workloads much cheaper than arbitrary whole-subject PCRE execution.

Be extremely conservative here. Slicing a line into a new “subject” silently changes `^`, `$`, `\A`, `\z`, word-boundary context and lookbehind semantics. A line-scoped fast path is valuable only if your parser proves those effects irrelevant.

On your backreference benchmark, a reasonable first target for direct PCRE2 is **~100–180 ms**, because rg already demonstrates that the workload can live in that region on the same computer. Getting from 667 ms to that range is far more valuable than shaving a microsecond from `ReadFile`.

For the **ordinary 100-regex** case, I would not try to make PCRE2 run 100 patterns individually. Use the regex-automata/lazy-DFA path above. Current `regex-automata` explicitly supports multi-pattern regexes and can report pattern IDs; its meta matcher composes prefilters, lazy DFA and slower engines according to the pattern. citeturn15search9turn14view3

A useful adaptive architecture is:

```text
                    Pattern planner
                          |
          +---------------+----------------+
          |               |                |
       literals       regular RE        PCRE-only
          |               |                |
    literal engine   meta/lazy DFA       PCRE2 JIT
          |               |
          |          positive requiring
          |          exact HS semantics?
          |               |
          +---------------+
                          |
                     Hyperscan
                   confirmation
```

That may sound inelegant compared with “Hyperscan does everything,” but it is exactly the kind of specialization that high-performance grep implementations exploit.

One piece of 2020–2026 research is relevant to the long-term fallback story: Barrière and Pit-Claudel's 2023 work derives linear-time algorithms for substantially richer regex subsets, including captureless lookbehind and, under JavaScript semantics, broader lookarounds. Some of those techniques have been integrated into V8. citeturn20academia7 It is interesting evidence that “lookaround ⇒ backtracking” is not theoretically inevitable. It is **not** a near-term replacement for PCRE2 in shgrep: the semantics are different and you would be implementing a regex engine. Treat it as future-engine research, not a top-five optimization.

## Windows I/O and freshness

On Windows, I would make only conservative changes to your opening path. You are already doing the important one: root-relative opens avoid reparsing a full DOS path and eliminate the expensive post-open `GetFinalPathNameByHandleW` containment check.

For normal synchronous scanning, benchmark this native configuration:

```cpp
DesiredAccess =
    FILE_READ_DATA | SYNCHRONIZE;

ShareAccess =
    FILE_SHARE_READ |
    FILE_SHARE_WRITE |
    FILE_SHARE_DELETE;

CreateDisposition =
    FILE_OPEN;

CreateOptions =
    FILE_NON_DIRECTORY_FILE |
    FILE_OPEN_REPARSE_POINT |
    FILE_SEQUENTIAL_ONLY |
    FILE_SYNCHRONOUS_IO_NONALERT;
```

`FILE_SEQUENTIAL_ONLY`/`FILE_FLAG_SEQUENTIAL_SCAN` is a documented hint that the file will be accessed sequentially; Windows can adapt caching/read-ahead behavior accordingly. `FILE_OPEN_REPARSE_POINT` prevents normal reparse-point processing, which is appropriate to your no-symlink/junction rule. citeturn5view1turn6search1

I would **not predict a major win from `FILE_SEQUENTIAL_ONLY` for this benchmark**. Your average file is ~11 KiB and the benchmark is warm-cache; read-ahead policy matters far more on larger/cold sequential reads. Windows documents sequential-access flags as cache-manager hints, not a fast-open facility. citeturn5view1turn5view3 Measure it, but a 10–25 ms miracle would surprise me.

Likewise, replacing `ReadFile` with `NtReadFile` is a low-priority experiment. It can remove a user-mode wrapper layer, but it does not bypass NTFS, Cache Manager, I/O Manager or filesystem filters; there is no credible mechanism by which that alone erases a tens-of-milliseconds workload gap. Keep it only if ETW/microbenchmarks show a measurable aggregate saving.

The highest-value I/O audit is simpler: **verify that your 64 KiB classification probe is the first part of the final read, not a read you later repeat.**

Given the size obtained from the directory listing:

```text
allocate initial buffer using listed size
read min(size, 64 KiB) directly into final buffer
classify those bytes
if binary -> stop
if text   -> continue at offset bytes_already_read
```

For races where the file grows or shrinks, treat the listed size only as a capacity hint and continue until actual EOF/reliable end-of-file semantics; resize as needed. Never use the directory-listing size as proof of immutable content.

If your present implementation really performs:

```text
probe[64K] <- ReadFile(offset 0)
then
final[] <- ReadFile(offset 0 ...)
```

eliminating that duplicate read should come before exotic I/O work. If you already reuse the probe bytes, there is nothing to do here.

For small files, target **one file open + one read + one close**. Avoid requesting access rights you do not need. Avoid a metadata query after opening unless a correctness property requires it.

Overlapped I/O is unlikely to improve your stated **warm-cache, many-small-file** benchmark. Windows supports overlapped reads and permits multiple operations to be in flight on a handle when opened appropriately. citeturn5view1turn5view2 But it cannot make the path-resolution/security/filter work of thousands of file creates disappear, and warm cached reads often finish so cheaply that IOCP bookkeeping is additional work. A bounded asynchronous pipeline is worth testing for cold NVMe scans, not as your first warm-cache optimization.

Also note that “18/24/36 scanning threads didn't help” does not prove asynchronous cold I/O can never help—it only says additional worker threads were not useful in your measured configuration. Keep separate numbers for warm and cold cache.

On Defender, there is no normal-user application flag that says “please skip real-time scanning for my trusted grep.” Microsoft explicitly provides a Defender Performance Analyzer that attributes antivirus cost to files, paths, extensions and processes; its troubleshooting guidance also recommends Process Monitor and Windows Performance Recorder when deeper diagnosis is needed. citeturn21search3turn21search9 Use that to settle whether your `NtCreateFile` theory is actually responsible for 5 ms, 20 ms or 50 ms rather than optimizing around an assumption.

The useful experiment is:

```text
A. walk only
B. walk + open/close
C. walk + open + read, no classification/scanner
D. C + binary/encoding classification
E. D + trivial literal scan
F. D + hs_scan
G. D + regex-automata
```

Run each with Defender active, then capture Defender's scan attribution and WPR/ProcMon traces. That gives you an actual lower bound for matcher optimization.

**USN journal/fsmonitor cannot solve your content-search problem under constraint 1.**

Suppose an MCP process searched at time `T0`, then asks at `T1` whether pattern `P2` occurs. The USN journal can tell you that `foo.cpp` has not generated a relevant change record since a checkpoint. But because you are forbidden to cache `foo.cpp`'s contents or a result derived from those contents, you possess **no information whatsoever about whether `P2` occurs in foo.cpp**. You must read it again.

Even for the same pattern, your rule forbids cached results, so “unchanged since previous search” does not authorize reuse.

Git's filesystem-monitor architecture is useful precisely because Git maintains state and uses change notifications to avoid reconsidering paths believed unchanged; that optimization model is different from your every-search-must-read-current-bytes requirement. citeturn8search1turn8search9

Windows change notifications and the USN journal also require recovery logic: notification buffers can overflow, and journals can be deleted, recreated or lose old records as they wrap. citeturn9search4turn7search6 That's manageable for an invalidation cache, but you have disallowed the thing it would invalidate.

So the answer on freshness is unusually clean:

> **USN gives essentially zero content-search acceleration under your exact rules.**

At most it could accelerate maintenance of a persistent path/metadata inventory, but your allowed-cache list does not include such an inventory, and even if you relaxed that rule it would eliminate directory enumeration—not the compulsory content opens/reads. Your directory enumeration is already only 9 ms anyway.

## Measurement targets and final ranking

Before changing the architecture, isolate the fixed Hyperscan cost. Pin one thread, reuse one scratch, preload buffers and execute at least hundreds of thousands of scans per size/database. Measure separately:

| Test | What it tells you |
|---|---|
| `hs_scan` 64 B, no match | near-fixed invocation/setup cost |
| 256 B / 1 KiB / 4 KiB | where fixed cost stops dominating |
| 16 KiB / 64 KiB | steady-state slope |
| 1 regex vs 100 regexes | Rose/NFA pattern-set cost |
| 1 vs 100 vs 1000 literals | HWLM/FDR/Teddy set cost |
| same buffers through regex-automata | whether engine substitution explains rg |
| same buffers through PCRE2 JIT | maximum Chimera replacement win |
| trivial AVX2 pass | pure memory-bandwidth floor |

Hyperscan's source makes those comparisons especially useful: pure-literal scans go through a dedicated HWLM path while general Rose blocks perform additional initialization and engine work; small blocks have their own coalesced matching path. citeturn19view1turn19view2

Also collect aggregate per-search counters instead of instrumenting every file with expensive timers:

```text
files_opened
bytes_read
files_binary_skipped
ASCII bytes
UTF-8 bytes
prefilter_bytes
prefilter_rejected_files
prefilter_candidate_files
hs_scan_calls
hs_scan_bytes
PCRE2_calls
regex_automata_calls
matches
```

Then use QPC/TSC timing around whole stages per worker.

The final plan I would execute is:

| Priority | Action | Ship criterion |
|---:|---|---|
| **1** | **PCRE2 JIT fallback** | Backref benchmark ≤150–180 ms without correctness regressions |
| **2** | **regex-automata multi-pattern/lazy-DFA fast path** | 100-regex no-match ≤75 ms scanner+walk, ideally below rg's 69 ms total after tuning |
| **3** | **required-literal SIMD gate, fused with classification; grouped HS DBs** | ≥80% of files rejected before HS on realistic regex sets and ≥10 ms whole-search win |
| **4** | **dedicated literal-set matcher** | 1000 literals ≤70–75 ms without regressing one-literal or `-l` paths |
| **5** | **single-read/I/O tightening** | ≥3 ms reproducible warm-cache improvement; otherwise stop |
| Experimental | guarded pure-literal `hs_scan_vector` batching | only keep if isolated scan-call overhead predicts ≥5 ms wall gain |
| Reject | generic cross-file regex batching | incorrect semantics |
| Reject | USN/fsmonitor as content accelerator | requires forbidden cached information |
| Reject | more scan threads | already disproven on your machine |
| Reject | mmap for thousands of tiny files | your experiment and ripgrep's architecture both point the other way |
| Reject | direct/raw volume access, MFT tricks, kernel driver, IoRing | conflicts with constraints or prior measurements |

The theoretical floor is the important reality check. With no content-derived persistent information, every search that may match any eligible file must perform, in some form:

\[
T_{\min} \ge T_{\text{enumerate}}
+ T_{\text{open every eligible file}}
+ T_{\text{obtain current bytes}}
+ T_{\text{inspect enough of those bytes to prove match/no-match}}
+ T_{\text{output}}
\]

A pattern-derived SIMD prefilter can make “inspect” very cheap, but it cannot eliminate the requirement to obtain and examine current bytes. On a warm NTFS tree with thousands of tiny files, once matching approaches memory-bandwidth speed, file creation/filter/cache-manager overhead becomes the floor.

That is why the goal should **not** be “make Hyperscan scan 80 MB faster.” Eighty megabytes is tiny for modern SIMD matching, and your own measurement says increasing from one to 1000 literals adds only about 25 ms. The winning strategy is to minimize expensive work **per independent 11 KiB file** and to select an engine whose fixed cost fits that file size.

The strongest prediction from the evidence is this:

> **A shgrep that uses rg-family lazy-DFA/prefilter algorithms for ordinary regexes, PCRE2 JIT for Perl features, a dedicated literal engine for fixed-string sets, and your existing faster Windows walker should beat ripgrep on this machine without violating freshness.**

Conversely, **a shgrep that insists every ordinary regex and every literal set must enter Hyperscan is unlikely to win all of your target workloads**, because your own benchmarks already show the mismatch: Hyperscan wins some highly selective/early-exit cases, but rg's low-fixed-cost prefilter/lazy-DFA architecture wins precisely where your remaining gaps are largest. citeturn14view3turn15search9turn19view0