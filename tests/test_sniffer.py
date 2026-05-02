# Unit tests for sniffer.py
# Run with: pytest tests/

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sniffer import mask_ip, clean_payload

# test ip masking
def test_mask_ip_basic():
    result = mask_ip("192.168.1.50")
    assert result == "192.168.1.xxx"

def test_mask_ip_keeps_first_three():
    result = mask_ip("10.0.0.1")
    assert result.startswith("10.0.0.")

def test_mask_ip_bad_input():
    result = mask_ip("notanip")
    assert result == "notanip"

# test payload redaction
def test_clean_payload_email():
    result = clean_payload("email me at test@gmail.com please")
    assert "test@gmail.com" not in result
    assert "[REDACTED_EMAIL]" in result

def test_clean_payload_password():
    result = clean_payload("login?password=abc123")
    assert "abc123" not in result

def test_clean_payload_token():
    result = clean_payload("api?token=xyz789")
    assert "xyz789" not in result

def test_clean_payload_cookie():
    result = clean_payload("Cookie: session=abcdef; user=admin")
    assert "session=abcdef" not in result

def test_clean_payload_auth():
    result = clean_payload("Authorization: Bearer mytoken123")
    assert "mytoken123" not in result

def test_clean_payload_safe_text():
    # normal text should not change
    result = clean_payload("GET /index.html HTTP/1.1")
    assert result == "GET /index.html HTTP/1.1"

def test_two_emails_both_redacted():
    result = clean_payload("from a@test.com to b@test.com")
    assert "a@test.com" not in result
    assert "b@test.com" not in result
