import typing

import pytest

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
