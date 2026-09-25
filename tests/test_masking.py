"""敏感值变体与确定性脱敏。"""

from __future__ import annotations

from app.masking import deterministic_token, normalize_value


def test_phone_variants_normalize_identically():
    variants = ["13800001234", "138-0000-1234", "138 0000 1234", "138.0000.1234"]
    normalized = {normalize_value(v, "digits") for v in variants}
    assert normalized == {"13800001234"}


def test_email_case_and_separator_variants():
    variants = ["Foo@Bar.com", "foo@bar.com", "FOO@BAR.COM", "f.o.o@bar.com"]
    normalized = {normalize_value(v, "alnum") for v in variants}
    # alnum 归一化会把点也去掉；前三者必须一致，含点变体单独一类（确定性可解释）
    assert normalize_value("Foo@Bar.com", "alnum") == normalize_value("foo@bar.com", "alnum")
    assert all(n.isalnum() for n in normalized)


def test_token_stable_within_tenant_and_scope():
    a = deterministic_token("t1", "phone", "13800001234", "s")
    b = deterministic_token("t1", "phone", "13800001234", "s")
    assert a == b and a.startswith("tok_")


def test_token_differs_across_tenant_and_scope():
    base = deterministic_token("t1", "phone", "13800001234", "s")
    assert deterministic_token("t2", "phone", "13800001234", "s") != base
    assert deterministic_token("t1", "email", "13800001234", "s") != base


def test_token_is_one_way():
    # 令牌中不得包含原值任何片段
    token = deterministic_token("t1", "phone", "13800001234", "s")
    assert "13800001234" not in token and "138" not in token


def test_unknown_normalizer_rejected():
    import pytest

    from app.errors import GatewayError  # noqa

    with pytest.raises(ValueError):
        normalize_value("x", "no-such-normalizer")
