import json
import pathlib
import typing

from self_balancing_binary_search_tree import SBBST, TreeNode
from tqdm import tqdm


def _int_to_num_ending_ones(x: int):
    binary = bin(x)
    ending_ones = len(binary) - len(binary.rstrip("1"))
    return ending_ones


def _int_to_num_leading_ones(x: int):
    binary = bin(x).lstrip("0b")
    ending_ones = len(binary) - len(binary.lstrip("1"))
    return ending_ones


_leading_ones_lookup = {n: _int_to_num_leading_ones(n) for n in range(256)}

_ending_ones_lookup = {n: _int_to_num_ending_ones(n) for n in range(256)}

_n_leading_ones_to_int = {n: int("0b" + "1" * n + "0" * (8 - n), 2) for n in range(0, 9)}


class IP(typing.NamedTuple):
    data: typing.Tuple[int, int, int, int]
    mask: typing.Optional[int]

    @classmethod
    def from_cidr(cls, value: str):
        base, mask = value.split("/")
        mask = int(mask)
        return cls.from_string(value=base, mask=mask)

    @classmethod
    def from_string(cls, value: str, mask: typing.Optional[int]):
        """
        >>> IP.from_string('10.2.20.23', 24)
        IP(data=(10, 2, 20, 23), mask=24)
        """
        octets = value.split(".")
        result = cls(tuple(int(octet) for octet in octets), mask)
        return result

    def as_string(self):
        """
        >>> IP(data=(10, 2, 20, 23), mask=24).as_string()
        '10.2.20.23/24'
        """
        return f"{'.'.join(str(part) for part in self.data)}" + (
            "" if not self.mask else f"/{self.mask}"
        )

    @property
    def bitmask(self):
        """
        >>> IP(data=(10, 2, 20, 23), mask=24).bitmask
        (255, 255, 255, 0)
        """
        if self.mask is None:
            return tuple([255] * 4)
        masked_octets = self.mask // 8
        result = [255] * masked_octets

        last_octet_mask = int("0b" + ("1" * (self.mask % 8)).ljust(8, "0"), 2)
        result.append(last_octet_mask)

        if len(result) < 4:
            result.extend([0] * (4 - len(result)))

        return tuple(result)

    @property
    def network(self):
        """
        >>> IP(data=(10, 2, 20, 23), mask=24).network
        IP(data=(10, 2, 20, 0), mask=None)

        >>> IP(data=(10, 2, 20, 23), mask=14).network
        IP(data=(10, 0, 0, 0), mask=None)
        """
        result = tuple([v & m for v, m in zip(self.data, self.bitmask)])

        return IP(result, None)

    @property
    def broadcast(self):
        """
        >>> IP(data=(10, 2, 20, 23), mask=24).broadcast
        IP(data=(10, 2, 20, 255), mask=None)

        >>> IP(data=(10, 2, 20, 23), mask=14).broadcast
        IP(data=(10, 3, 255, 255), mask=None)
        """
        wildmask = [255 ^ m for m in self.bitmask]
        result = tuple([v | m for v, m in zip(self.data, wildmask)])
        return IP(result, None)

    def is_subset_of(self, o: "IP"):
        """
        >>> IP(data=(10, 2, 20, 23), mask=25).is_subset_of(IP(data=(10, 2, 20, 23), mask=24))
        True

        >>> IP(data=(10, 2, 20, 23), mask=24).is_subset_of(IP(data=(10, 2, 20, 23), mask=24))
        True

        >>> IP(data=(10, 2, 20, 23), mask=24).is_subset_of(IP(data=(10, 2, 20, 23), mask=25))
        False
        """
        return o.network <= self.network and o.broadcast >= self.broadcast

    def has_overlap_with(self, o: "IP"):
        return any(
            [
                self.network <= o.network and self.broadcast >= o.network,
                self.network <= o.broadcast and self.broadcast >= o.broadcast,
                self.is_subset_of(o),
                o.is_subset_of(self),
            ]
        )

    def unions_with(self, o: "IP"):
        """
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
            left = min(self.network, o.network)
            right = max(self.broadcast, o.broadcast)

            wild_bit_count = 0
            for v in right[::-1]:
                if v == 255:
                    wild_bit_count += 8
                else:
                    binary_value = bin(v)
                    wild_bit_count += len(binary_value) - len(binary_value.rstrip("1"))
                    break

    @property
    def as_int(self):
        octets = self.data
        value = 0
        for n, octet in enumerate(octets):
            value += 256 ** (4 - n - 1) * int(octet)
        return value

    def is_adjacent_to(self, o: "IP") -> bool:
        """
        >>> IP.from_cidr("3.2.33.128/26").is_adjacent_to(IP.from_cidr("3.2.33.192/26"))
        True

        >>> IP.from_cidr("3.2.33.192/26").is_adjacent_to(IP.from_cidr("3.2.33.128/26"))
        True
        """
        if self.has_overlap_with(o):
            return False
        lower, higher = self.unions_with(o)
        return lower.broadcast.as_int + 1 == higher.network.as_int

    @staticmethod
    def merge(lower: "IP", higher: "IP"):
        """
        >>> merge(IP.from_cidr('3.2.34.128/26'), IP.from_cidr('3.2.34.192/26'))
        IP(data=(3, 2, 34, 128), mask=25)

        >>> merge(IP.from_cidr('3.2.32.0/26'), IP.from_cidr('3.2.32.64/26'))
        IP(data=(3, 2, 32, 0), mask=25)

        >>> merge(IP.from_cidr('13.34.0.128/27'), IP.from_cidr('13.34.0.160/27'))
        IP(data=(13, 34, 0, 128), mask=26)

        >>> merge(IP.from_cidr('13.34.3.128/27'), IP.from_cidr('13.34.3.224/27'))
        IP(data=(13, 34, 3, 128), mask=25)

        >>> merge(IP.from_cidr('13.34.4.64/27'), IP.from_cidr('13.34.4.96/27'))
        IP(data=(13, 34, 4, 64), mask=26)
        """
        start = lower.network
        broadcast = higher.broadcast

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
    """
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
    """
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
    if node.left:
        _walk_in_order(node.left, action=action)
    if action:
        action(node)
    if node.right:
        _walk_in_order(node.right, action=action)


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
                start_of_group = None

        last = ip
    for replace_ip in to_insert:
        st.insert(replace_ip)

    print(f"  merged {merged_count} entries")
    return merged_count > 0


def merge_and_simplify(
    files: typing.List[pathlib.Path],
    print_graph=False,
    output: typing.Optional[pathlib.Path] = None,
    pretty: bool = False,
):
    st = SBBST()

    for file in files:
        print("\n\nProcessing -", file.name)
        data: typing.List[str] = json.loads(file.read_text())

        ip_ranges_stack = []

        for ip in tqdm(data, desc="Evaluating: "):
            if "/" in ip:
                value = IP.from_cidr(ip)
            else:
                value = IP.from_string(ip, mask=None)

            ip_ranges_stack = _pop_and_merge(ip_ranges_stack, value)

        for ip in tqdm(ip_ranges_stack, desc="  inserting: "):
            already_covered = _search(st.head, ip)
            if not already_covered:
                st.insert(ip)
        if print_graph:
            _print_graph_as_dot(st.head)

        while _merge_adjacent_in_tree(st):
            pass

    with output.open("w") as fout:
        kwargs = {}
        if pretty:
            kwargs["indent"] = 4
        json.dump([x.as_string() for x in ip_ranges_stack], fout, **kwargs)
