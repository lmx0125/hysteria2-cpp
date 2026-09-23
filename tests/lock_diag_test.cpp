// lock_diag_test.cpp - M2 regression: LockTimer must not read the clock when
// diagnostics are disabled.
//
// Every lock/unlock pair used to call steady_clock::now() twice whether or
// not anyone wanted the data (~30-80 ns per site, 30+ sites on the hot
// paths). LockTimer is now gated on a cached flag; the test hook counts the
// clock reads so the disabled path can be asserted to be free of them.

#include "hytest.hpp"

#include "hy2/diag/lock_diag.hpp"

using namespace hy2::diag;

HY_TEST(LockDiagDisabledSkipsClockReads)
{
    SetLockDiagEnabledForTest(0);
    const unsigned long long before = gLockTimerClockReads.load();
    {
        LockTimer t("test.disabled");
        t.done();
    }
    HY_CHECK_EQ(gLockTimerClockReads.load(), before);
    SetLockDiagEnabledForTest(-1); // restore the environment default
}

HY_TEST(LockDiagEnabledReadsClockForTimer)
{
    SetLockDiagEnabledForTest(1);
    const unsigned long long before = gLockTimerClockReads.load();
    {
        LockTimer t("test.enabled");
        t.done();
    }
    // one read in the constructor, one in done()
    HY_CHECK_EQ(gLockTimerClockReads.load(), before + 2);
    SetLockDiagEnabledForTest(-1); // restore the environment default
}
