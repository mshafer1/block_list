import typing

import pytest
from self_balancing_binary_search_tree import SBBST

import ip_calc

class _MergeTestArgs(typing.NamedTuple):
    lower: ip_calc.IP
    higher: ip_calc.IP
    expected: typing.Optional[ip_calc.IP]


@pytest.mark.parametrize(["lower", "higher", "expected"], [
    _MergeTestArgs(ip_calc.IP.from_cidr("47.88.92.0/23"), ip_calc.IP.from_cidr("47.88.92.0/22"), ip_calc.IP.from_cidr("47.88.92.0/22"))
])
def test__lower_higher_and_expected__merge__expected(lower: ip_calc.IP, higher: ip_calc.IP, expected: typing.Optional[ip_calc.IP]):
    result = ip_calc.IP.merge(lower=lower, higher=higher)

    assert result == expected

class _MergeAdjacentTreeArgs(typing.NamedTuple):
    values: list[ip_calc.IP]
    expected: list[ip_calc.IP]


@pytest.mark.parametrize(
    ["values", "expected"],
    [
        _MergeAdjacentTreeArgs(
            values=[
                ip_calc.IP.from_cidr(x)
                for x in (
                    "3.2.0.0/24",
                    "3.2.2.0/24",
                    "3.2.3.0/24",
                )
            ],
            expected=[ip_calc.IP.from_cidr(x) for x in ("3.2.0.0/24", "3.2.2.0/23")],
        )
    ],
)
def test__value__merge_adjacent_in_tree__expected_values(
    values: typing.Iterable[ip_calc.IP], expected: typing.List[ip_calc.IP]
):
    st = SBBST()
    for o in values:
        st.insert(o)

    while ip_calc._merge_adjacent_in_tree(st):
        pass

    st.getListInOrder()
    assert st.listInOrder == expected
