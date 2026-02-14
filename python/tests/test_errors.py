"""Tests for revenant.errors — exception hierarchy."""

from revenant.errors import AuthError, RevenantError, ServerError, TLSError


def test_revenant_error_is_exception():
    assert issubclass(RevenantError, Exception)


def test_auth_error_inherits_revenant():
    assert issubclass(AuthError, RevenantError)
    e = AuthError("bad creds")
    assert isinstance(e, RevenantError)
    assert str(e) == "bad creds"


def test_server_error_inherits_revenant():
    assert issubclass(ServerError, RevenantError)


def test_tls_error_inherits_revenant():
    assert issubclass(TLSError, RevenantError)


def test_tls_error_default_not_retryable():
    e = TLSError("config issue")
    assert e.retryable is False
    assert str(e) == "config issue"


def test_tls_error_retryable_flag():
    e = TLSError("timed out", retryable=True)
    assert e.retryable is True
    assert str(e) == "timed out"


def test_catch_all_with_base():
    """All specific errors should be catchable via RevenantError."""
    for cls in (AuthError, ServerError, TLSError):
        try:
            raise cls("test")
        except RevenantError:  # noqa: PERF203
            pass  # expected


def test_tls_error_pickle_roundtrip():
    """TLSError should survive pickle/unpickle with retryable flag preserved."""
    import pickle

    e = TLSError("timed out", retryable=True)
    restored = pickle.loads(pickle.dumps(e))
    assert isinstance(restored, TLSError)
    assert str(restored) == "timed out"
    assert restored.retryable is True


def test_tls_error_pickle_not_retryable():
    """TLSError with retryable=False should survive pickle round-trip."""
    import pickle

    e = TLSError("config issue", retryable=False)
    restored = pickle.loads(pickle.dumps(e))
    assert isinstance(restored, TLSError)
    assert str(restored) == "config issue"
    assert restored.retryable is False


def test_tls_error_setstate_none():
    """__setstate__ with None should not crash (e.g. manual unpickling edge case)."""
    e = TLSError("test", retryable=True)
    e.__setstate__(None)
    # retryable should remain unchanged
    assert e.retryable is True
