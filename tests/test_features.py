from src.features import FEATURE_NAMES, extract_features, features_to_vector


def test_feature_count_and_order():
    assert len(FEATURE_NAMES) == 12
    assert len(features_to_vector("https://example.com")) == 12


def test_https_flag():
    assert extract_features("https://example.com")["uses_https"] == 1
    assert extract_features("http://example.com")["uses_https"] == 0


def test_ip_host():
    assert extract_features("http://192.168.1.10/login")["has_ip_address"] == 1
    assert extract_features("http://example.com")["has_ip_address"] == 0


def test_at_symbol():
    assert extract_features("http://google.com@evil.xyz/")["has_at_symbol"] == 1


def test_keywords():
    assert extract_features("http://secure-login-verify.com")["suspicious_keyword_count"] == 3


def test_suspicious_tld():
    assert extract_features("http://free-gift.xyz")["has_suspicious_tld"] == 1
    assert extract_features("http://wikipedia.org")["has_suspicious_tld"] == 0


def test_path_depth_and_subdomains():
    f = extract_features("https://a.b.example.com/x/y/z")
    assert f["path_depth"] == 3 and f["num_subdomains"] == 2


def test_empty_string_never_raises():
    assert len(extract_features("")) == 12


def test_no_scheme_and_unicode():
    assert extract_features("example.com/login")["uses_https"] == 0
    assert len(extract_features("http://пример.рф/страница")) == 12


def test_very_long_url():
    assert extract_features("http://a.com/" + "x" * 5000)["url_length"] > 5000


def test_malformed_url_never_raises():
    assert len(extract_features("http://[::1")) == 12
