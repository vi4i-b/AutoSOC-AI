"""OS integration layer.

Every module in this package hides a platform difference behind a small,
testable interface. UI code must never call netsh/iptables/ipconfig/systemctl
directly — it goes through these modules instead.
"""
