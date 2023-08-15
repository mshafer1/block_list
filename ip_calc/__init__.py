"""IP address tools."""
import json
import pathlib
import typing

from self_balancing_binary_search_tree import SBBST, TreeNode
from tqdm import tqdm


def _int_to_num_ending_ones(x: int):
    """Return count of on bits at end of x.

    >>> _int_to_num_ending_ones(0)
    0

    >>> _int_to_num_ending_ones(2)
    0

    >>> _int_to_num_ending_ones(1)
    1

    >>> _int_to_num_ending_ones(3)
    2

    >>> _int_to_num_ending_ones(7)
    3
    """
    binary = bin(x)
    ending_ones = len(binary) - len(binary.rstrip("1"))
    return ending_ones


def _int_to_num_leading_ones(x: int):
    """Return number of on bits at start of number (fixed 8-bit width).

    >>> _int_to_num_leading_ones(0)
    0

    >>> _int_to_num_leading_ones(5)
    0

    >>> _int_to_num_leading_ones(255)
    8

    >>> _int_to_num_leading_ones(128)
    1
    """
    binary = bin(x).lstrip("0b").rjust(8, "0")
    leading_ones = len(binary) - len(binary.lstrip("1"))
    return leading_ones


_leading_ones_lookup = {n: _int_to_num_leading_ones(n) for n in range(256)}

_ending_ones_lookup = {n: _int_to_num_ending_ones(n) for n in range(256)}

_n_leading_ones_to_int = {n: int("0b" + "1" * n + "0" * (8 - n), 2) for n in range(0, 9)}


class IP(typing.NamedTuple):
    """IP Address model."""

    data: typing.Tuple[int, int, int, int]
    mask: typing.Optional[int]

    @classmethod
    def from_cidr(cls, value: str):
        """Load IP from Classless Inter-Domain Routing value."""
        base, mask = value.split("/")
        mask = int(mask)
        return cls.from_string(value=base, mask=mask)

    @classmethod
    def from_string(cls, value: str, mask: typing.Optional[int]):
        """Load IP from string and mask.

        >>> IP.from_string('10.2.20.23', 24)
        IP(data=(10, 2, 20, 23), mask=24)
        """
        octets = value.split(".")
        result = cls(tuple(int(octet) for octet in octets), mask)
        return result

    def as_string(self):
        """Return IP in cidr notation.

        >>> IP(data=(10, 2, 20, 23), mask=24).as_string()
        '10.2.20.23/24'
        """
        return f"{'.'.join(str(part) for part in self.data)}" + (
            "" if not self.mask else f"/{self.mask}"
        )

    @property
    def _bitmask(self):
        """IP address bitmask as tuple of octets.

        >>> IP(data=(10, 2, 20, 23), mask=24)._bitmask
        (255, 255, 255, 0)

        >>> IP(data=(10, 2, 20, 23), mask=17)._bitmask
        (255, 255, 128, 0)

        >>> IP(data=(10, 2, 20, 23), mask=18)._bitmask
        (255, 255, 192, 0)

        >>> IP(data=(10, 2, 20, 23), mask=23)._bitmask
        (255, 255, 254, 0)
        """
        if self.mask is None:
            return tuple([255] * 4)
        masked_octets = self.mask // 8
        result = [255] * masked_octets

        last_octet_mask = _n_leading_ones_to_int[self.mask % 8]
        result.append(last_octet_mask)

        result.extend([0] * (4 - len(result)))

        return tuple(result)

    @property
    def network(self):
        """Network IP (lowest) for range.

        >>> IP(data=(10, 2, 20, 23), mask=24).network
        IP(data=(10, 2, 20, 0), mask=None)

        >>> IP(data=(10, 2, 20, 23), mask=14).network
        IP(data=(10, 0, 0, 0), mask=None)
        """
        result = tuple([v & m for v, m in zip(self.data, self._bitmask)])

        return IP(result, None)

    @property
    def broadcast(self):
        """Broadcast IP (highest) for range.

        >>> IP(data=(10, 2, 20, 23), mask=24).broadcast
        IP(data=(10, 2, 20, 255), mask=None)

        >>> IP(data=(10, 2, 20, 23), mask=14).broadcast
        IP(data=(10, 3, 255, 255), mask=None)
        """
        wildmask = [255 ^ m for m in self._bitmask]
        result = tuple([v | m for v, m in zip(self.data, wildmask)])
        return IP(result, None)

    def is_subset_of(self, o: "IP"):
        """Return whether self is a subset of IP range 'o'.

        >>> IP(data=(10, 2, 20, 23), mask=25).is_subset_of(IP(data=(10, 2, 20, 23), mask=24))
        True

        >>> IP(data=(10, 2, 20, 23), mask=24).is_subset_of(IP(data=(10, 2, 20, 23), mask=24))
        True

        >>> IP(data=(10, 2, 20, 23), mask=24).is_subset_of(IP(data=(10, 2, 20, 23), mask=25))
        False
        """
        return o.network <= self.network and o.broadcast >= self.broadcast

    def has_overlap_with(self, o: "IP"):
        """Return whether this IP has any overlap with IP o.

        >>> IP.from_cidr("1.12.0.0/14").has_overlap_with(IP.from_cidr("1.12.0.0/18"))
        True

        >>> IP.from_cidr("1.27.0.0/14").has_overlap_with(IP.from_cidr("1.12.0.0/18"))
        False
        """
        return any(
            [
                self.network <= o.network and self.broadcast >= o.network,
                self.network <= o.broadcast and self.broadcast >= o.broadcast,
                self.is_subset_of(o),
                o.is_subset_of(self),
            ]
        )

    def unions_with(self, o: "IP"):
        """Return union merges with o, if no overlap, just returns in order.

        >>> IP(data=(10, 2, 20, 23), mask=24).unions_with(IP(data=(10, 2, 20, 23), mask=25))
        (IP(data=(10, 2, 20, 23), mask=24),)

        >>> IP(data=(10, 2, 20, 23), mask=24).unions_with(IP(data=(10, 2, 20, 23), mask=25))
        (IP(data=(10, 2, 20, 23), mask=24),)
        """
        if self.is_subset_of(o):
            return (o,)
        elif o.is_subset_of(self):
            return (self,)
        elif o.network > self.broadcast:
            return (self, o)
        elif self.network > o.broadcast:
            return (o, self)
        else:
            if self.has_overlap_with(o):
                raise Exception("Oh, hey!, this did happen!!")
            else:
                return (o, self)

    @property
    def __as_int(self):
        octets = self.data
        value = 0
        for n, octet in enumerate(octets):
            value += 256 ** (4 - n - 1) * int(octet)
        return value

    def is_adjacent_to(self, o: "IP") -> bool:
        """Return whether self and o are next to each other in the IP address space.

        >>> IP.from_cidr("3.2.33.128/26").is_adjacent_to(IP.from_cidr("3.2.33.192/26"))
        True

        >>> IP.from_cidr("3.2.33.192/26").is_adjacent_to(IP.from_cidr("3.2.33.128/26"))
        True
        """
        if self.has_overlap_with(o):
            return False
        lower, higher = self.unions_with(o)
        return lower.broadcast.__as_int + 1 == higher.network.__as_int

    @staticmethod
    def merge(first: "IP", last: "IP") -> typing.Optional["IP"]:
        """Attempt to predict IP that covers from first.network to last.broadcast.

        Returns None if not mergable.

        >>> IP.merge(IP.from_cidr('3.2.34.128/26'), IP.from_cidr('3.2.34.192/26'))
        IP(data=(3, 2, 34, 128), mask=25)

        >>> IP.merge(IP.from_cidr('3.2.32.0/26'), IP.from_cidr('3.2.32.64/26'))
        IP(data=(3, 2, 32, 0), mask=25)

        >>> IP.merge(IP.from_cidr('13.34.0.128/27'), IP.from_cidr('13.34.0.160/27'))
        IP(data=(13, 34, 0, 128), mask=26)

        >>> IP.merge(IP.from_cidr('13.34.3.128/27'), IP.from_cidr('13.34.3.224/27'))
        IP(data=(13, 34, 3, 128), mask=25)

        >>> IP.merge(IP.from_cidr('13.34.4.64/27'), IP.from_cidr('13.34.4.96/27'))
        IP(data=(13, 34, 4, 64), mask=26)

        >>> IP.merge(IP.from_cidr('3.2.0.0/24'), IP.from_cidr('3.2.2.0/24'),)

        >>> IP.merge(IP.from_cidr('3.2.2.0/24'), IP.from_cidr('3.2.3.0/24'),)
        IP(data=(3, 2, 2, 0), mask=23)
        """
        lower, higher = min([first, last]), max([first, last])
        start = lower.network
        broadcast = higher.broadcast

        if lower.is_subset_of(higher):
            return higher
        elif higher.is_subset_of(lower):
            return lower

        possible_wild_mask = []
        for val, start_val in zip(broadcast.data[::-1], start.data[::-1]):
            number = "0b" + "1" * _ending_ones_lookup[val ^ start_val]
            if number == "0b":
                break
            possible_wild_mask.append(int(number, 2))
        possible_wild_mask.extend([0] * (4 - len(possible_wild_mask)))
        possible_wild_mask = list(reversed(possible_wild_mask))

        possible_bitmask = []
        for network_part, mask_part in zip(start.data, possible_wild_mask):
            val = mask_part ^ 255 | (_n_leading_ones_to_int[_leading_ones_lookup[network_part]])
            possible_bitmask.append(val)

        mask = sum([_leading_ones_lookup[part] for part in possible_bitmask])

        new_value = IP(start.data, mask)
        if new_value.network == lower.network and new_value.broadcast == higher.broadcast:
            return new_value
        return None


def _excel_column_number_to_name(column_number):
    """Type convert from integer to base 26 (A=1).

    >>> _excel_column_number_to_name(1)
    'A'

    >>> _excel_column_number_to_name(2)
    'B'

    >>> _excel_column_number_to_name(26)
    'Z'

    >>> _excel_column_number_to_name(27)
    'AA'
    """
    output = ""
    index = column_number - 1
    while index >= 0:
        character = chr((index % 26) + ord("A"))
        output = output + character
        index = index // 26 - 1

    return output[::-1]


def _name_generator():
    n = 1
    while True:
        yield _excel_column_number_to_name(n)
        n += 1


_node_names = iter(_name_generator())


def _pop_and_merge(stack: typing.List[IP], merge_with: IP):
    """Pop overlapping off of stack, then push the merged values.

    >>> _pop_and_merge([IP.from_cidr("1.12.0.0/14")], IP.from_cidr("1.12.34.0/23"))
    [IP(data=(1, 12, 0, 0), mask=14)]

    >>> _pop_and_merge([IP.from_cidr("1.12.0.0/14")], IP.from_cidr("1.12.0.0/20"))
    [IP(data=(1, 12, 0, 0), mask=14)]

    >>> _pop_and_merge([IP.from_cidr("1.12.0.0/14")], IP.from_cidr("1.12.34.0/23"))
    [IP(data=(1, 12, 0, 0), mask=14)]

    >>> _pop_and_merge([IP.from_cidr("1.12.0.0/14")], IP.from_cidr("1.12.64.0/18"))
    [IP(data=(1, 12, 0, 0), mask=14)]

    >>> _pop_and_merge([IP.from_cidr("1.12.0.0/14")], IP.from_cidr("1.13.0.0/18"))
    [IP(data=(1, 12, 0, 0), mask=14)]


    >>> _pop_and_merge([IP.from_cidr("1.12.0.0/14")], IP.from_cidr("1.116.0.0/15"))
    [IP(data=(1, 12, 0, 0), mask=14), IP(data=(1, 116, 0, 0), mask=15)]

    >>> _pop_and_merge([IP.from_cidr("1.12.0.0/14"), IP(data=(1, 116, 0, 0), mask=15)], IP.from_cidr("1.116.0.0/18"))
    [IP(data=(1, 12, 0, 0), mask=14), IP(data=(1, 116, 0, 0), mask=15)]
    """  # noqa: W505 - doctests are long.
    ip_ranges_to_remerge: typing.List[IP] = []
    for i, other_ip in enumerate(reversed(stack)):
        if not any(
            [
                other_ip.has_overlap_with(merge_ip)
                for merge_ip in (ip_ranges_to_remerge + [merge_with])
            ]
        ):
            break
        ip_ranges_to_remerge.append(other_ip)
    if not ip_ranges_to_remerge:
        stack.append(merge_with)
        return stack

    # pop ips to merge off
    del stack[-(i):]
    for ip in ip_ranges_to_remerge:
        merge_with = ip.unions_with(merge_with)[0]

    return _pop_and_merge(stack, merge_with)


def _walk_in_order(
    node: TreeNode, action: typing.Optional[typing.Callable[[TreeNode], None]] = None
):
    for node in _yield_in_order(node):
        action(node)


def _yield_in_order(node: TreeNode):
    """
    Yield all nodes in order

    >>> st = SBBST(); _ = [st.insert(x) for x in range(10)]
    >>> list([x.val for x in _yield_in_order(st.head)])
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    """
    if node.left:
        for sub_node in _yield_in_order(node.left):
            yield sub_node
    yield node
    if node.right:
        for sub_node in _yield_in_order(node.right):
            yield sub_node


def _yield_post_order(node: TreeNode):
    """
    Yield all nodes in order

    >>> st = SBBST(); _ = [st.insert(x) for x in range(10)]
    >>> set([x.val for x in _yield_post_order(st.head)]) == set(range(10))
    True
    """
    if node.left:
        for sub_node in _yield_post_order(node.left):
            yield sub_node

    if node.right:
        for sub_node in _yield_post_order(node.right):
            yield sub_node

    yield node

def _search(node: typing.Optional[TreeNode], value: IP):
    if node is None:
        return None
    val: IP = node.val
    if value.is_subset_of(val):
        return node
    elif value < val:
        return _search(node.left, value=value)
    else:
        return _search(node.right, value=value)


def _print_graph_as_dot(graph: TreeNode, *_, _first=True):
    if _first:
        print("digraph IPtree{")

        def _assign_name(o):
            if "name" not in o.__dict__:
                o.name = next(_node_names)

        _walk_in_order(node=graph, action=_assign_name)

    targets = [f"{child.name}" for child in (graph.left, graph.right) if child is not None]
    color = 'fillcolor = "grey" style="filled"' if _first else ""
    print(f'{graph.name} [label="{graph.val.as_string()}" {color}]')
    if targets:
        print(f"{graph.name} -> {', '.join(targets)}")
    if graph.left is not None:
        _print_graph_as_dot(graph.left, _first=False)
    if graph.right is not None:
        _print_graph_as_dot(graph.right, _first=False)
    if _first:
        print("}")


def _merge_adjacent_in_tree(st: SBBST):
    print("Merging...")
    st.getListInOrder()
    to_insert = []
    start_of_group = None
    last = None
    group = []

    merged_count = 0
    for ip in st.listInOrder:
        if last is None:
            last = ip
            continue

        if last.is_adjacent_to(ip):
            if not start_of_group:
                start_of_group = last
                group = [last]
            group.append(ip)
        else:
            if start_of_group is not None:
                merged_count = _merge_adjacent_ips_helper(st, to_insert, group, merged_count)
                start_of_group = None

        last = ip
    if start_of_group is not None:
        merged_count = _merge_adjacent_ips_helper(st, to_insert, group, merged_count)
        start_of_group = None
    for replace_ip in to_insert:
        st.insert(replace_ip)

    print(f"  merged {merged_count} entries")
    return merged_count > 0


def _merge_adjacent_ips_helper(st, to_insert, group, merged_count: int) -> int:
    for part in group:
        st.delete(part)
    merge_last = group[0]
    for merge_current in group[1:]:
        merged = IP.merge(merge_last, merge_current)
        if merged:
            merged_count += 1
            merge_last = merged
        else:
            to_insert.append(merge_last)
            merge_last = merge_current
    to_insert.append(merge_last)
    group = []
    return merged_count


def merge_and_simplify(
    files: typing.List[pathlib.Path],
    print_graph=False,
    output: typing.Optional[pathlib.Path] = None,
    pretty: bool = False,
):
    """Merge overlapping and adjacent IP ranges in files (JSON), and store in output (JSON)."""
    st = SBBST()

    for file in files:
        print("\n\nProcessing -", file.name)
        data: typing.List[str] = json.loads(file.read_text())

        ip_ranges_stack = []

        for node in tqdm(data, desc="Evaluating: "):
            if "/" in node:
                value = IP.from_cidr(node)
            else:
                value = IP.from_string(node, mask=None)

            ip_ranges_stack = _pop_and_merge(ip_ranges_stack, value)

        for node in tqdm(ip_ranges_stack, desc="  inserting: "):
            already_covered = _search(st.head, node)
            if not already_covered:
                st.insert(node)
        while _merge_adjacent_in_tree(st):
            pass

    ip_ranges_stack = []
    for node in _yield_in_order(st.head):
        ip_ranges_stack = _pop_and_merge(ip_ranges_stack, node.val)

    for node in _yield_post_order(st.head):
        st.deleteNode(node, node.val)

    for ip in ip_ranges_stack:
        st.insert(ip)

    if print_graph:
        _print_graph_as_dot(st.head)


    st.getListInOrder()
    with output.open("w") as fout:
        kwargs = {}
        if pretty:
            kwargs["indent"] = 4
        json.dump([x.as_string() for x in st.listInOrder], fout, **kwargs)
