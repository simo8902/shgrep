#pragma once
#include <mutex>
#include <shared_mutex>

#if defined(__clang__)
#define SHGREP_CAPABILITY(name) __attribute__((capability(name)))
#define SHGREP_SCOPED_CAPABILITY __attribute__((scoped_lockable))
#define SHGREP_GUARDED_BY(lock) __attribute__((guarded_by(lock)))
#define SHGREP_ACQUIRE(...) __attribute__((acquire_capability(__VA_ARGS__)))
#define SHGREP_ACQUIRE_SHARED(...) __attribute__((acquire_shared_capability(__VA_ARGS__)))
#define SHGREP_REQUIRES(...) __attribute__((requires_capability(__VA_ARGS__)))
#define SHGREP_RELEASE(...) __attribute__((release_capability(__VA_ARGS__)))
#define SHGREP_RELEASE_SHARED(...) __attribute__((release_shared_capability(__VA_ARGS__)))
#define SHGREP_LOCK_BOUNDARY __attribute__((no_thread_safety_analysis))
#else
#define SHGREP_CAPABILITY(name)
#define SHGREP_SCOPED_CAPABILITY
#define SHGREP_GUARDED_BY(lock)
#define SHGREP_ACQUIRE(...)
#define SHGREP_ACQUIRE_SHARED(...)
#define SHGREP_REQUIRES(...)
#define SHGREP_RELEASE(...)
#define SHGREP_RELEASE_SHARED(...)
#define SHGREP_LOCK_BOUNDARY
#endif

namespace shgrep::sync {
// The annotations describe our own lock boundary without changing standard-library headers.
// Standard mutex internals are trusted here; caller lock contracts and guarded data remain checked.
class SHGREP_CAPABILITY("mutex") Mutex {
    std::mutex mutex_;
public:
    void lock() SHGREP_ACQUIRE() SHGREP_LOCK_BOUNDARY { mutex_.lock(); }
    void unlock() SHGREP_RELEASE() SHGREP_LOCK_BOUNDARY { mutex_.unlock(); }
};

template<class MutexType>
class SHGREP_SCOPED_CAPABILITY LockGuard {
    MutexType& mutex_;
public:
    explicit LockGuard(MutexType& mutex) SHGREP_ACQUIRE(mutex) SHGREP_LOCK_BOUNDARY : mutex_(mutex) { mutex_.lock(); }
    ~LockGuard() SHGREP_RELEASE() SHGREP_LOCK_BOUNDARY { mutex_.unlock(); }
    LockGuard(const LockGuard&) = delete;
    LockGuard& operator=(const LockGuard&) = delete;
};

class SHGREP_CAPABILITY("mutex") SharedMutex {
    std::shared_mutex mutex_;
public:
    void lock() SHGREP_ACQUIRE() SHGREP_LOCK_BOUNDARY { mutex_.lock(); }
    void unlock() SHGREP_RELEASE() SHGREP_LOCK_BOUNDARY { mutex_.unlock(); }
    void lock_shared() SHGREP_ACQUIRE_SHARED() SHGREP_LOCK_BOUNDARY { mutex_.lock_shared(); }
    void unlock_shared() SHGREP_RELEASE_SHARED() SHGREP_LOCK_BOUNDARY { mutex_.unlock_shared(); }
};

class SHGREP_SCOPED_CAPABILITY SharedLockGuard {
    SharedMutex& mutex_;
public:
    explicit SharedLockGuard(SharedMutex& mutex) SHGREP_ACQUIRE_SHARED(mutex) SHGREP_LOCK_BOUNDARY
        : mutex_(mutex) { mutex_.lock_shared(); }
    ~SharedLockGuard() SHGREP_RELEASE() SHGREP_LOCK_BOUNDARY { mutex_.unlock_shared(); }
    SharedLockGuard(const SharedLockGuard&) = delete;
    SharedLockGuard& operator=(const SharedLockGuard&) = delete;
};
}
