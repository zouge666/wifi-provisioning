import pytest

from wifiprov.device.lockout import Lockout


def failures(lockout, count):
    for _ in range(count):
        lockout.record_failure()


def test_a_new_lockout_lets_everyone_in(clock):
    lockout = Lockout(clock=clock)
    assert not lockout.is_locked()
    assert lockout.retry_after() == 0


def test_it_locks_after_the_maximum_number_of_failures(clock):
    lockout = Lockout(max_failures=5, duration=300, clock=clock)
    failures(lockout, 4)
    assert not lockout.is_locked()
    lockout.record_failure()
    assert lockout.is_locked()
    assert lockout.retry_after() == 300


def test_the_wait_counts_down_and_is_rounded_up(clock):
    lockout = Lockout(max_failures=1, duration=300, clock=clock)
    lockout.record_failure()
    clock.advance(100)
    assert lockout.retry_after() == 200
    clock.advance(0.5)
    assert lockout.retry_after() == 200  # 199.5 seconds left, shown as 200
    clock.advance(199.5)
    assert lockout.retry_after() == 0


def test_it_opens_again_when_the_time_is_up_and_starts_counting_afresh(clock):
    lockout = Lockout(max_failures=5, duration=300, clock=clock)
    failures(lockout, 5)
    clock.advance(299)
    assert lockout.is_locked()
    clock.advance(1)
    assert not lockout.is_locked()
    failures(lockout, 4)
    assert not lockout.is_locked()
    lockout.record_failure()
    assert lockout.is_locked()


def test_a_correct_code_resets_the_count(clock):
    lockout = Lockout(max_failures=5, clock=clock)
    failures(lockout, 4)
    lockout.record_success()
    failures(lockout, 4)
    assert not lockout.is_locked()


def test_failures_during_a_lockout_do_not_extend_it(clock):
    lockout = Lockout(max_failures=1, duration=300, clock=clock)
    lockout.record_failure()
    clock.advance(100)
    lockout.record_failure()
    clock.advance(200)
    assert not lockout.is_locked()


@pytest.mark.parametrize(
    "options", [{"max_failures": 0}, {"max_failures": -1}, {"duration": 0}, {"duration": -5}]
)
def test_nonsense_settings_are_refused(options):
    with pytest.raises(ValueError):
        Lockout(**options)
