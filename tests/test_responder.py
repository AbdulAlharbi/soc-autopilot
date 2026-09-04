from socpilot.agents.responder import expand_action


CTX = {"user": "j.doe", "host": None, "malicious_ips": ["1.1.1.1", "2.2.2.2"], "pids": [10, 20], "signals": {"mailbox_rule_created": True}}


def test_each_expands_one_action_per_value():
    acts = expand_action({"tool": "firewall", "operation": "block_ip", "params": {"ip": "{each:malicious_ips}"}}, CTX)
    assert [a.params["ip"] for a in acts] == ["1.1.1.1", "2.2.2.2"]


def test_native_types_preserved_for_whole_placeholders():
    acts = expand_action({"tool": "edr", "operation": "kill_process", "params": {"host": "{user}", "pid": "{each:pids}"}}, CTX)
    assert acts[0].params["pid"] == 10 and isinstance(acts[0].params["pid"], int)


def test_unresolved_placeholder_drops_action():
    assert expand_action({"tool": "edr", "operation": "scan_host", "params": {"host": "{host}"}}, CTX) == []


def test_when_condition():
    spec = {"tool": "iam", "operation": "remove_mailbox_rules", "params": {"user": "{user}"}, "when": "signals.mailbox_rule_created"}
    assert len(expand_action(spec, CTX)) == 1
    assert expand_action(dict(spec, when="signals.oauth_consent"), CTX) == []


def test_embedded_placeholders_render_as_text():
    acts = expand_action({"tool": "ticketing", "operation": "create_ticket", "params": {"title": "Tune for {user} on {malicious_ips}"}}, CTX)
    assert acts[0].params["title"].startswith("Tune for j.doe on [")
