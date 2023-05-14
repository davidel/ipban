import ipaddress
import os
import pickle
import re
import requests
import tempfile
import tarfile

import utils as ut


def _parse_zones(path, zones, net_args=None, min_bits=None):
  args = net_args.copy() if net_args else dict()

  ut.log(ut.DEBUG, f'Parsing {path} : {args}')

  with open(path, mode='r') as zf:
    for ln in zf.read().split('\n'):
      ln = ln.strip()
      if ln:
        try:
          ipn = ipaddress.ip_network(ln)
          if min_bits is None or ipn.prefixlen >= min_bits:
            zones[ln] = args

            ut.log(ut.DEBUG, f'  {ln}')
          else:
            ut.log(ut.INFO, f'Skipping zone {ln}, not enough bits ({ipn.prefixlen} < {min_bits})')
        except Exception as e:
          ut.log(ut.ERROR, f'Invalid network "{ln}" : {e}')


_DUMMY_COUNTRIES = set([
  'ZZ',
])

def _create_dbfile(zfiles_dirs, zpath, min_bits=None):
  stable = ut.StringTable()
  zones = {}
  for zfiles_dir in zfiles_dirs:
    for zfname in os.listdir(zfiles_dir):
      m = re.match(r'([a-zA-Z]+)\.zone', zfname)
      if not m:
        ut.log(ut.WARNING, f'Skipping file {zfname} : Cannot parse country name')
        continue
      country = stable.get(m.group(1).upper())
      if country in _DUMMY_COUNTRIES:
        ut.log(ut.INFO, f'Skipping zones for country : {country}')
        continue
      net_args = dict(country=country)
      _parse_zones(os.path.join(zfiles_dir, zfname), zones,
                   net_args=net_args,
                   min_bits=min_bits)

  ut.log(ut.DEBUG, f'Parsed {len(zones)} zones')

  with tempfile.NamedTemporaryFile(dir=os.path.dirname(zpath), delete=False) as tmp:
    pickle.dump(zones, tmp.file)
    tmp.file.close()
    os.replace(tmp.name, zpath)


def _get_zone_files(dest_path, url, zfdir):
  zfname = re.match(r'.*/([^/]+)$', url).group(1)
  tfile = os.path.join(dest_path, zfname)
  if not os.path.exists(tfile):
    zdata = requests.get(url, verify=False)
    zdata.raise_for_status()
    with open(tfile, mode='wb') as f:
      f.write(zdata.content)

  zfiles_dir = os.path.join(dest_path, zfdir)
  if not os.path.exists(zfiles_dir):
    os.mkdir(zfiles_dir)
    tar = tarfile.open(tfile)
    tar.extractall(path=zfiles_dir)
    tar.close()

  return zfiles_dir


_FILES = (
  dict(url='https://www.ipdeny.com/ipblocks/data/countries/all-zones.tar.gz',
       dname='zone_files_ipv4'),
  dict(url='https://www.ipdeny.com/ipv6/ipaddresses/blocks/ipv6-all-zones.tar.gz',
       dname='zone_files_ipv6'),
)

def _get_zones(dest_path):
  zpath = os.path.join(dest_path, 'zones.db.pkl')
  if not os.path.exists(zpath):
    with tempfile.TemporaryDirectory() as tmp_path:
      zfiles = [_get_zone_files(tmp_path, x['url'], x['dname']) for x in _FILES]

      _create_dbfile(zfiles, zpath)

  return zpath


class ZonesArena(object):

  def __init__(self):
    self._nets = {}

  def load_zones(self, path=None):
    if path is None:
      path = tempfile.gettempdir()

    zpath = _get_zones(path)

    with open(zpath, mode='rb') as f:
      nets = pickle.load(f)

    for net, net_args in nets.items():
      self.add_zone(net, net_args)

    return self

  def add_zone(self, net, net_args=None, strict=True):
    if ut.is_network(net):
      ipn = net
    else:
      ipn = ipaddress.ip_network(net, strict=strict)

    nn = ut.dget(self._nets, ipn.version, lambda: [None] * ipn.max_prefixlen)
    pnn = ut.lget(nn, ipn.prefixlen - 1, dict)

    zi = dict(net=ipn, **net_args) if net_args else dict(net=ipn)
    pnn[ipn.network_address.packed] = zi

    return zi

  def lookup(self, ip, strict=True):
    if isinstance(ip, str):
      ip = ut.get_ip_net(ip, strict=strict)

    if ut.is_network(ip):
      ipa = ip.network_address
      base_prefix = ip.prefixlen
    else:
      ipa = ip
      base_prefix = ipa.max_prefixlen

    addr = ut.Address(ipa, prefix=base_prefix)

    nn = self._nets.get(ipa.version, None)
    if nn is not None:
      for i in range(base_prefix, 0, -1):
        pnn = nn[i - 1]
        if pnn is not None:
          zi = pnn.get(addr.bytes, None)
          if zi is not None:
            return zi

        addr.clear_bit(i - 1)

