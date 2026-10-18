from __future__ import annotations

from vuln_xss import render_user_profile


def test_render_profile_escapes_xss_tags():
    res = render_user_profile("<script>alert('xss')</script>")
    # Before repair: res.body contains raw unescaped <script> tag.
    # After repair: html.escape turns it to &lt;script&gt;.
    assert "<script>" not in str(res.body)
    assert "&lt;script&gt;" in str(res.body)
