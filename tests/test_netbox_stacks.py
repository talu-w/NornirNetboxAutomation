"""Tests for the stack-member resolver (Virtual Chassis first, then <host>-<member> names)."""

from __future__ import annotations

from types import SimpleNamespace

from bunnyauto.netbox.stacks import (
    is_stack_wide,
    management_ip,
    own_interfaces,
    resolve_stack,
)


def _device(id_, name, *, ip=None, chassis=None, position=None):
    return SimpleNamespace(
        id=id_,
        name=name,
        primary_ip={"address": ip} if ip else None,
        virtual_chassis={"id": chassis} if chassis else None,
        vc_position=position,
    )


class _NB:
    """Just enough of pynetbox's ``dcim`` for the resolver, counting device lookups."""

    def __init__(self, everywhere=(), chassis=None):
        self.lookups: list[dict] = []
        everywhere = list(everywhere)

        def filter_devices(**filters):
            self.lookups.append(filters)
            if "virtual_chassis_id" in filters:
                wanted = filters["virtual_chassis_id"]
                return [d for d in everywhere if (d.virtual_chassis or {}).get("id") == wanted]
            prefix = filters["name__isw"].casefold()
            return [d for d in everywhere if d.name.casefold().startswith(prefix)]

        self.dcim = SimpleNamespace(
            devices=SimpleNamespace(filter=filter_devices),
            virtual_chassis=SimpleNamespace(get=lambda id_: (chassis or {}).get(id_)),
        )


A1 = _device(1, "SwitchA-1", ip="10.0.0.11/24")
A2 = _device(2, "SwitchA-2")
A3 = _device(3, "SwitchA-3")


def test_standalone_device_owns_every_port():
    sw = _device(9, "core-a", ip="10.0.0.9/24")
    stack = resolve_stack(_NB(), sw, {1, 2}, [sw])

    assert not stack.is_stack
    assert stack.owner("Gi2/0/1") is sw
    assert stack.owner("Port-channel1") is sw


def test_named_members_own_their_ports_and_the_connected_device_anchors_the_rest():
    stack = resolve_stack(_NB(), A1, {1, 2, 3}, [A1, A2, A3])

    assert stack.source == "name"
    assert stack.own_member == 1
    assert stack.owner("GigabitEthernet2/0/7") is A2
    assert stack.owner("Te3/1/1") is A3
    assert stack.owner("Port-channel1") is A1
    assert [d.id for d in stack.devices()] == [1, 2, 3]


def test_a_name_suffix_alone_is_not_a_stack():
    # Only member-1 ports, or ports that never mention the device's own number.
    assert not resolve_stack(_NB(), A1, {1}, [A1, A2]).is_stack
    assert not resolve_stack(_NB(), A1, {2, 3}, [A1, A2, A3]).is_stack
    assert not resolve_stack(_NB(), A1, {0, 1}, [A1, A2]).is_stack


def test_a_member_sharing_the_stack_management_ip_is_still_a_member():
    twin = _device(2, "SwitchA-2", ip="10.0.0.11/24")
    stack = resolve_stack(_NB(), A1, {1, 2}, [A1, twin])

    assert stack.owner("Gi2/0/1") is twin


def test_two_devices_claiming_one_member_is_ambiguous():
    dup = _device(4, "SwitchA-2.other.example.com")
    stack = resolve_stack(_NB(), A1, {1, 2}, [A1, A2, dup])

    assert stack.owner("Gi2/0/1") is None
    assert stack.unresolved[2] == (
        "more than one NetBox device could be member 2: SwitchA-2, SwitchA-2.other.example.com"
    )


def test_missing_members_are_looked_up_outside_the_scope_once_per_stack():
    outside = _device(3, "SwitchA-3")
    nb = _NB(everywhere=[A1, outside])

    stack = resolve_stack(nb, A1, {1, 2, 3}, [A1], scope_label="tag 'nornirtest'")

    assert stack.unresolved == {
        2: "NetBox has no device named SwitchA-2",
        3: "SwitchA-3 is outside this run's scope (tag 'nornirtest')",
    }
    assert nb.lookups == [{"name__isw": "switcha-"}]


def test_virtual_chassis_positions_and_master():
    top = _device(10, "bldg-a-top", ip="10.0.0.5/24", chassis=7, position=1)
    bottom = _device(11, "bldg-a-bottom", chassis=7, position=2)
    chassis = {7: SimpleNamespace(name="bldg-a", master={"id": 11})}
    nb = _NB(everywhere=[top, bottom], chassis=chassis)

    stack = resolve_stack(nb, top, {1, 2, 3}, [top, bottom])

    assert stack.source == "virtual-chassis"
    assert stack.owner("Gi1/0/1") is top
    assert stack.owner("Gi2/0/1") is bottom
    assert stack.owner("Po1") is bottom  # the chassis master holds stack-wide ports
    assert stack.unresolved == {3: "Virtual Chassis 'bldg-a' has no member at position 3"}


def test_virtual_chassis_member_outside_the_scope_is_part_of_the_switch():
    # NetBox doesn't copy tags to a chassis member: bottom lacks the env tag.
    top = _device(10, "bldg-a-top", chassis=7, position=1)
    bottom = _device(11, "bldg-a-bottom", chassis=7, position=2)
    chassis = {7: SimpleNamespace(name="bldg-a", master={"id": 11})}
    nb = _NB(everywhere=[top, bottom], chassis=chassis)

    stack = resolve_stack(nb, top, {1, 2}, [top])

    assert stack.owner("Gi2/0/1") is bottom
    assert stack.inherited == [bottom]
    assert stack.unresolved == {}
    assert stack.anchor is bottom  # the chassis master, in scope or not


def test_name_based_member_outside_the_scope_is_not_inherited():
    # Without a Virtual Chassis a name is only inference, so scope still applies.
    stack = resolve_stack(_NB(everywhere=[A1, A2]), A1, {1, 2}, [A1])

    assert stack.owner("Gi2/0/1") is None
    assert stack.inherited == []


def test_management_ip_reads_every_shape():
    assert management_ip(SimpleNamespace(primary_ip={"address": "10.0.0.1/24"})) == "10.0.0.1"
    assert management_ip(SimpleNamespace(primary_ip=SimpleNamespace(address="10.0.0.2/32"))) == (
        "10.0.0.2"
    )
    assert management_ip(SimpleNamespace(primary_ip=None, primary_ip4="10.0.0.3/24")) == "10.0.0.3"
    assert management_ip(SimpleNamespace(primary_ip=None)) is None


# ---------------------------------------------------------------------------
# claimed members and stand-ins: may the connected device hold an ownerless port?
# ---------------------------------------------------------------------------


def test_member_missing_from_netbox_lets_the_connected_device_stand_in():
    # One NetBox device for the whole stack: its copy of member 2's port is the port.
    stack = resolve_stack(_NB(everywhere=[A1]), A1, {1, 2}, [A1])

    assert stack.claimed == set()
    assert stack.stand_in("Gi2/0/1") is A1


def test_member_outside_the_scope_is_claimed_and_never_stood_in_for():
    stack = resolve_stack(_NB(everywhere=[A1, A2]), A1, {1, 2}, [A1])

    assert stack.claimed == {2}
    assert stack.stand_in("Gi2/0/1") is None


def test_ambiguous_member_is_claimed():
    dup = _device(4, "SwitchA-2.other.example.com")
    stack = resolve_stack(_NB(), A1, {1, 2}, [A1, A2, dup])

    assert stack.claimed == {2}
    assert stack.stand_in("Gi2/0/1") is None


def test_out_of_scope_sibling_with_its_own_ip_is_a_separate_switch_not_a_claim():
    # core-2 is left out by --site, but it's a separately managed chassis.
    core1 = _device(1, "core-1", ip="10.0.0.1/24")
    core2 = _device(2, "core-2", ip="10.0.0.2/24")
    stack = resolve_stack(_NB(everywhere=[core1, core2]), core1, {1, 2}, [core1])

    assert stack.unresolved[2] == (
        "core-2 has its own management IP (10.0.0.2), so it is a separate switch, "
        "not a member of this stack"
    )
    assert stack.claimed == set()
    assert stack.stand_in("Gi2/0/1") is core1


def test_member_one_port_seen_through_member_two_has_no_stand_in():
    # SwitchA-2's template calls its own Gi2/0/x GigabitEthernet1/0/x, so a
    # GigabitEthernet1/0/1 on it is never member 1's port.
    a2 = _device(2, "SwitchA-2", ip="10.0.0.11/24")
    stack = resolve_stack(_NB(), a2, {1, 2}, [a2])

    assert stack.claimed == set()  # member 1 simply isn't in NetBox
    assert stack.stand_in("Gi1/0/1") is None
    assert stack.stand_in("Po1") is None  # not ownerless: it goes to the anchor


def test_resolved_members_and_standalone_devices_need_no_stand_in():
    assert resolve_stack(_NB(), A1, {1, 2}, [A1, A2]).stand_in("Gi2/0/1") is None
    sw = _device(9, "core-a", ip="10.0.0.9/24")
    assert resolve_stack(_NB(), sw, {1, 2}, [sw]).stand_in("Gi2/0/1") is None


def test_missing_virtual_chassis_position_lets_the_connected_device_stand_in():
    top = _device(10, "bldg-a-top", chassis=7, position=1)
    bottom = _device(11, "bldg-a-bottom", chassis=7, position=2)
    chassis = {7: SimpleNamespace(name="bldg-a", master={"id": 10})}
    nb = _NB(everywhere=[top, bottom], chassis=chassis)

    stack = resolve_stack(nb, top, {1, 2, 3}, [top])

    assert stack.claimed == set()
    assert stack.stand_in("Gi2/0/1") is None  # member 2 has a device: bottom owns it
    assert stack.stand_in("Gi3/0/1") is top


def test_member_number_of_each_stack_device():
    stack = resolve_stack(_NB(), A1, {1, 2}, [A1, A2, A3])

    assert stack.member_number(A2) == 2
    assert stack.member_number(A3) is None  # named like a member, but reported no ports


def test_stack_wide_interfaces_are_port_channels_and_virtual_ones():
    assert is_stack_wide("Port-channel1")
    assert is_stack_wide("Vlan10")
    assert is_stack_wide("Loopback0")
    assert not is_stack_wide("GigabitEthernet2/0/1")


def test_own_interfaces_drop_other_members_ports():
    # Older NetBox answered a VC master's device_id filter with every member's ports.
    mine = SimpleNamespace(name="Gi1/0/1", device={"id": 10})
    members = SimpleNamespace(name="Gi2/0/1", device={"id": 11})
    nb = SimpleNamespace(
        dcim=SimpleNamespace(interfaces=SimpleNamespace(filter=lambda device_id: [mine, members]))
    )

    assert own_interfaces(nb, SimpleNamespace(id=10)) == [mine]
