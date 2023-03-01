import ipaddress
import array
import logging


DEBUG = logging.DEBUG
INFO = logging.INFO
WARNING = logging.WARNING
ERROR = logging.ERROR

_LOG_LEVELS = dict(
  DEBUG=DEBUG,
  INFO=INFO,
  WARNING=WARNING,
  ERROR=ERROR,
)


def log(lev, msg):
  for l in msg.split('\n'):
    logging.log(lev, l)


def setup_logging(level, log_file=None):
  log_level = _LOG_LEVELS[level] if isinstance(level, str) else level
  formatter = logging.Formatter(
    fmt='%(asctime)s.%(msecs)03d %(levelname)s:\t%(message)s',
    datefmt='%Y-%m-%d %H:%M:%S')
  handlers = []

  h = logging.StreamHandler()
  h.setLevel(log_level)
  h.setFormatter(formatter)
  handlers.append(h)

  if log_file:
    h = logging.FileHandler(log_file)
    h.setLevel(log_level)
    h.setFormatter(formatter)
    handlers.append(h)

  logging.basicConfig(level=log_level, handlers=handlers)


def is_network(ipn):
  return isinstance(ipn, (ipaddress.IPv4Network, ipaddress.IPv6Network))


def is_address(ipn):
  return isinstance(ipn, (ipaddress.IPv4Address, ipaddress.IPv6Address))


def iphost_to_str(ip):
  if ip.version == 4 or not ip.ipv4_mapped:
    return str(ip)

  # Return the more user friendly format for IPV4 mapped IPV6 addresses.
  return '::ffff:' + '.'.join([str(x) for x in ip.packed[-4:]])


def ipstr(ip):
  if isinstance(ip, ipaddress.IPv4Network):
    return str(ip)
  if isinstance(ip, ipaddress.IPv6Network):
    return iphost_to_str(ip.network_address) + f'/{ip.prefixlen}'

  return iphost_to_str(ip)


def get_ip_net(ip, strict=False):
  return ipaddress.ip_network(ip, strict=strict) if '/' in ip else ipaddress.ip_address(ip)


def get_canonical_ip(ip):
  ipn = get_ip_net(ip)

  return ipstr(ipn)


def get_ipn_ip(ipn):
  return ipn.network_address if is_network(ipn) else ipn


class StringTable(object):

  def __init__(self):
    self._stable = {}

  def get(self, s):
    v = self._stable.get(s, None)
    if v is None:
      v = s
      self._stable[v] = v

    return v


_NONE = object()

def dget(d, n, t):
  v = d.get(n, _NONE)
  if v is _NONE:
    v = t()
    d[n] = v

  return v


def lget(l, n, t):
  v = l[n]
  if v is None:
    v = t()
    l[n] = v

  return v


class Address(object):

  def __init__(self, ip, prefix=None):
    if isinstance(ip, bytes):
      addr_bytes = ip
    else:
      ipn = get_ip_net(ip) if isinstance(ip, str) else ip
      if is_address(ipn):
        addr_bytes = ipn.packed
      elif is_network(ipn):
        addr_bytes = ipn.network_address.packed
      else:
        raise RuntimeError(f'Invalid initializer for Address object: {ip}')

    self._bytes = array.array('B', addr_bytes)

    if prefix is not None:
      self.clear_for_prefix(prefix)

  def clear_for_prefix(self, prefix):
    assert 8 * len(self) >= prefix, f'Invalid prefix {prefix} for {8 * len(self)} bit address'

    n = prefix // 8
    i = prefix % 8
    if len(self) > n and i > 0:
      self._bytes[n] &= ~((1 << (8 - i)) - 1)
      n += 1
    for x in range(n, len(self)):
      self._bytes[x] = 0

  def clear_bit(self, n):
    self._bytes[n // 8] &= ~(1 << (7 - (n % 8)))

  def __len__(self):
    return len(self._bytes)

  @property
  def bytes(self):
    return self._bytes.tobytes()

  @property
  def address(self):
    return ipaddress.ip_address(self.bytes)

