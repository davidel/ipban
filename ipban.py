#!/usr/bin/env python3

import argparse
import ipaddress
import collections
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import traceback
import yaml

import utils as ut
import zones as zn


_IPBAN_RULES = 'IPBAN'
_IPSET_NAME = 'ipban'


def default_entry():
  return dict(mtime=int(time.time()))


def load_config(path):
  ut.log(ut.DEBUG, f'Loading configuration from {path}')
  with open(path, mode='r') as f:
    cfg = yaml.load(f, Loader=yaml.FullLoader)

    # HACK: Temporary conversion!
    ips = cfg['blocked_ips']
    if not isinstance(ips, dict):
      nips = {ip: default_entry() for ip in ips}
      cfg['blocked_ips'] = nips

    return cfg


def save_config(path, cfg):
  ut.log(ut.DEBUG, f'Saving configuration to {path}')

  shutil.copy(path, path + '.bak')

  fd, tpath = tempfile.mkstemp(dir=os.path.dirname(path), text=True)
  with os.fdopen(fd, mode='wt') as f:
    yaml.dump(cfg, f, default_flow_style=False)

  mode = os.stat(path)[stat.ST_MODE] if os.path.exists(path) else 0o755
  os.replace(tpath, path)
  os.chmod(path, mode)


def save_ipset(name):
  return subprocess.check_output(('ipset', 'save', name))


def ipset_restore(data):
  subprocess.run(('ipset', 'restore'), input=data, check=True, capture_output=True)


def ipset_ip_name(name, family):
  return f'{name}_ip_v{family}'


def ipset_net_name(name, family):
  return f'{name}_net_v{family}'


def ipset_name_from_ip(name, ip):
  ipn = ut.get_ip_net(ip)

  return ipset_net_name(name, ipn.version) if ut.is_network(ipn) else ipset_ip_name(name, ipn.version)


def ipset_generate_ips_restore(name, ips):
  cmds = []
  for ip in ips:
    sname = ipset_name_from_ip(name, ip)
    cmds.append(f'add {sname} {ip}')

  return '\n'.join(cmds)


def resolve_args(args, ver, defver=0):
  rargs = []
  for arg in args:
    if isinstance(arg, dict):
      rarg = arg.get(ver, None)
      if rarg is None:
        rarg = arg[defver]
    else:
      rarg = arg

    rargs.append(rarg)

  return tuple(rargs)


def iptables(*args, **kwargs):
  subprocess.check_call(('iptables',) + resolve_args(args, 4), **kwargs)
  subprocess.check_call(('ip6tables',) + resolve_args(args, 6), **kwargs)


def ipset_create(name, ip_kind='hash:ip', net_kind='hash:net'):
  ut.log(ut.DEBUG, f'Creating "{name}" IPSET')
  subprocess.check_call(('ipset', '-exist', 'create', ipset_ip_name(name, 4), ip_kind, 'family', 'inet'))
  subprocess.check_call(('ipset', '-exist', 'create', ipset_net_name(name, 4), net_kind, 'family', 'inet'))
  subprocess.check_call(('ipset', '-exist', 'create', ipset_ip_name(name, 6), ip_kind, 'family', 'inet6'))
  subprocess.check_call(('ipset', '-exist', 'create', ipset_net_name(name, 6), net_kind, 'family', 'inet6'))


def ipset_add(name, ip):
  ut.log(ut.DEBUG, f'Adding "{ip}" to the "{name}" IPSET')
  sname = ipset_name_from_ip(name, ip)
  subprocess.check_call(('ipset', '-exist', 'add', sname, ip))


def ipset_del(name, ip):
  ut.log(ut.DEBUG, f'Removing "{ip}" from the "{name}" IPSET')
  sname = ipset_name_from_ip(name, ip)
  subprocess.check_call(('ipset', '-exist', 'del', sname, ip))


def create_ruleset(rule_name):
  ut.log(ut.DEBUG, f'Creating IPTABLES "{rule_name}" ruleset')
  iptables('-N', rule_name)

  iptables('-I', 'INPUT', '-j', rule_name)
  iptables('-I', 'FORWARD', '-j', rule_name)


def block_set(rule_name, name):
  ut.log(ut.DEBUG, f'Adding IPTABLES rule to block the "{name}" IPSET')
  ipmset = {4: ipset_ip_name(name, 4), 6: ipset_ip_name(name, 6)}
  netmset = {4: ipset_net_name(name, 4), 6: ipset_net_name(name, 6)}

  iptables('-I', rule_name, '-m', 'set', '--match-set', ipmset, 'src', '-j', 'DROP')
  iptables('-I', rule_name, '-m', 'set', '--match-set', netmset, 'src', '-j', 'DROP')


def init_firewall(cfg):
  ut.log(ut.DEBUG, f'Initializing IPSET firewall')
  ipset_create(_IPSET_NAME)

  restore_data = ipset_generate_ips_restore(_IPSET_NAME, list(cfg['blocked_ips'].keys))
  if restore_data:
    ipset_restore(restore_data.encode())

  create_ruleset(_IPBAN_RULES)
  block_set(_IPBAN_RULES, _IPSET_NAME)


def get_sorted_ips(ips):

  def sortip(ip):
    ipn = ut.get_ip_net(ip)

    return ut.get_ipn_ip(ipn).packed

  skeys = sorted(ips.keys(), key=sortip)

  return {ip: ips[ip] for ip in skeys}


def ipset_purge_list(ips):
  ipns, ipnets = [], []
  for ip in ips:
    ipn = ut.get_ip_net(ip)
    if ut.is_network(ipn):
      ipnets.append(ipn)
    else:
      ipns.append(ipn)

  dropped = []
  cnets = list(ipnets)
  for i in range(0, len(cnets)):
    inn = cnets[i]
    if inn is None:
      continue
    for j in range(0, len(cnets)):
      if i == j:
        continue
      jnn = cnets[j]
      if jnn is None or jnn.version != inn.version:
        continue
      if jnn.subnet_of(inn):
        cnets[j] = None
        dropped.append(jnn)
      elif inn.subnet_of(jnn):
        cnets[i] = None
        dropped.append(inn)
        break

  ipnets = [ipn for ipn in cnets if ipn is not None]
  cips = []
  for ipn in ipns:
    dropit = False
    for ipnet in ipnets:
      if ipn.version == ipnet.version and ipn in ipnet:
        dropit = True
        dropped.append(ipn)
        break

    if not dropit:
      cips.append(ipn)

  return ipnets, cips, dropped


def add_ip_list(cfg, ips, args):
  ipcs = [ut.get_canonical_ip(ip) for ip in ips]

  ut.log(ut.DEBUG, f'Adding IP: {ipcs}')

  sip, added = cfg['blocked_ips'], []
  for ip in ipcs:
    xip = sip.get(ip)
    if xip is None:
      sip[ip] = default_entry()
      added.append(ip)
    else:
      xip['mtime'] = int(time.time())

  for ip in added:
    ipset_add(_IPSET_NAME, ip)

  cfg['blocked_ips'] = get_sorted_ips(sip)
  save_config(args.config_file, cfg)


def add_ip(cfg, args):
  add_ip_list(cfg, args.ip, args)


def del_ip(cfg, args):
  ipcs = [ut.get_canonical_ip(ip) for ip in args.ip]

  sip, dropped = cfg['blocked_ips'], []
  for ip in ipcs:
    if sip.pop(ip, None) is not None:
      dropped.append(ip)

  if dropped:
    for ip in dropped:
      ipset_del(_IPSET_NAME, ip)

    cfg['blocked_ips'] = get_sorted_ips(sip)
    save_config(args.config_file, cfg)


def madd_ip(cfg, args):
  if args.file:
    with open(args.file, mode='r') as f:
      data = f.read()
  else:
    data = sys.stdin.read()

  ips = collections.defaultdict(int)
  for ip in data.split('\n'):
    ip = ip.strip(' \t"\'')
    if ip and not ip.startswith('#'):
      try:
        # This will raise if the IP (or IP/NET) is invalid.
        ipc = ut.get_canonical_ip(ip)
        ips[ipc] += 1
      except ValueError:
        ut.log(ut.DEBUG, f'Invalid IP: {ip}')

  add_ips = [k for k, v in ips.items() if v >= args.min_count]
  if add_ips:
    add_ip_list(cfg, add_ips, args)


def purge(cfg, args):
  sip = cfg['blocked_ips']
  ipnets, cips, dropped = ipset_purge_list(list(sip.keys()))

  if dropped:
    for ipn in dropped:
      ipset_del(_IPSET_NAME, ut.ipstr(ipn))

    psip = dict()
    for ipn in cips + ipnets:
      ip = ut.ipstr(ipn)
      psip[ip] = sip[ip]

    cfg['blocked_ips'] = get_sorted_ips(psip)
    save_config(args.config_file, cfg)


def zones_purge(cfg, args):
  za = zn.ZonesArena().load_zones()
  cza = zn.ZonesArena()

  sip = cfg['blocked_ips']
  matches = collections.defaultdict(list)
  for ip in sip.keys():
    ipn = ut.get_ip_net(ip)
    if ut.is_network(ipn):
      cza.add_zone(ipn)

    zi = za.lookup(ipn)
    if zi is not None:
      matches[zi['net']].append(ip)

  dropped = set()
  match_nets = set()
  for net, ips in matches.items():
    zi = za.lookup(net)
    country = zi.get('country', '??')
    if len(ips) >= args.min_count:
      ut.log(ut.INFO, f'Dropping IPs in {zi["net"]} country={country}')

      for ip in ips:
        ut.log(ut.INFO, f'  {ip}')
        sip.pop(ip, None)
        dropped.add(ip)

      match_nets.add(net)
    else:
      ut.log(ut.DEBUG, f'Net {zi["net"]} country={country} has {len(ips)} IPs')

  if dropped:
    for ip in dropped:
      ipset_del(_IPSET_NAME, ip)

    for net in match_nets:
      zi = cza.lookup(net)
      if zi is None:
        nets = ut.ipstr(net)
        ipset_add(_IPSET_NAME, nets)
        sip[nets] = default_entry()

    cfg['blocked_ips'] = get_sorted_ips(sip)
    save_config(args.config_file, cfg)


def net_lookup(cfg, args):
  za = zn.ZonesArena().load_zones()

  for ip in args.ip:
    ipn = ut.get_ip_net(ip)
    zi = za.lookup(ipn)
    if zi is not None:
      country = zi.get('country', '??')
      ut.log(ut.INFO, f'{ipn}\t{zi["net"]}\t{country}')
    else:
      ut.log(ut.ERROR, f'{ipn}\tNot Found!')


def run(args):
  cfg = load_config(args.config_file)
  if args.cmd == 'init':
    init_firewall(cfg)
  elif args.cmd == 'addip':
    add_ip(cfg, args)
  elif args.cmd == 'delip':
    del_ip(cfg, args)
  elif args.cmd == 'madd':
    madd_ip(cfg, args)
  elif args.cmd == 'purge':
    purge(cfg, args)
  elif args.cmd == 'zones_purge':
    zones_purge(cfg, args)
  elif args.cmd == 'net_lookup':
    net_lookup(cfg, args)
  else:
    raise RuntimeError(f'Unknown command: {args.cmd}')


def main(args):
  try:
    run(args)
  except Exception as ex:
    fex = traceback.format_exc()
    ut.log(ut.ERROR, f'{fex}\n{ex}')
    sys.exit(1)


if __name__ == '__main__':
  parser = argparse.ArgumentParser(description='IP blocking utility',
                                   formatter_class=argparse.ArgumentDefaultsHelpFormatter)
  parser.add_argument('--config_file', type=str, required=True,
                      help='The path to the configuration file')
  parser.add_argument('--cmd', type=str, required=True,
                      choices={'init', 'addip', 'delip', 'madd', 'purge', 'zones_purge', 'net_lookup'},
                      help='The command to issue')
  parser.add_argument('--ip', nargs='+',
                      help='The IP(s) to add')
  parser.add_argument('--file', type=str,
                      help='The file to be used as input/output (depending on the command)')
  parser.add_argument('--min_count', type=int, default=10,
                      help='The minimum number of IP occurrences to trigger a ban')
  parser.add_argument('--log_level', type=str, default='INFO',
                      help='The logging level (DEBUG, INFO, WARNING, ERROR)')
  parser.add_argument('--log_file', type=str,
                      help='The log file path')

  args = parser.parse_args()
  ut.setup_logging(args.log_level, log_file=args.log_file)
  main(args)
