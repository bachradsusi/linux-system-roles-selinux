#! /usr/bin/python3
# -*- coding: utf-8 -*-

# Copyright: (c) 2014, Dan Keder <dan.keder@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import sys
import traceback

SELINUX_IMP_ERR = None
try:
    import selinux
    HAVE_SELINUX = True
except ImportError:
    SELINUX_IMP_ERR = traceback.format_exc()
    HAVE_SELINUX = False

SEOBJECT_IMP_ERR = None
try:
    import seobject
    HAVE_SEOBJECT = True
except ImportError:
    SEOBJECT_IMP_ERR = traceback.format_exc()
    HAVE_SEOBJECT = False

def get_runtime_status(ignore_selinux_state=False):
    return ignore_selinux_state or selinux.is_selinux_enabled()


def semanage_port_get_ports(seport, setype, proto):
    """ Get the list of ports that have the specified type definition.

    :param community.general.seport: Instance of seobject.portRecords

    :type setype: str
    :param setype: SELinux type.

    :type proto: str
    :param proto: Protocol ('tcp' or 'udp')

    :rtype: list
    :return: List of ports that have the specified SELinux type.
    """
    records = seport.get_all_by_type(locallist=1)
    if (setype, proto) in records:
        return records[(setype, proto)]
    else:
        return []


def semanage_port_get_type(seport, port, proto):
    """ Get the SELinux type of the specified port.

    :param community.general.seport: Instance of seobject.portRecords

    :type port: str
    :param port: Port or port range (example: "8080", "8080-9090")

    :type proto: str
    :param proto: Protocol ('tcp' or 'udp')

    :rtype: tuple
    :return: Tuple containing the SELinux type and MLS/MCS level, or None if not found.
    """
    if isinstance(port, str):
        ports = port.split('-', 1)
        if len(ports) == 1:
            ports.extend(ports)
    else:
        ports = (port, port)

    key = (int(ports[0]), int(ports[1]), proto)

    records = seport.get_all()
    return records.get(key)


def semanage_port_add(ports, proto, setype, do_reload, serange='s0', sestore=''):
    """ Add SELinux port type definition to the policy.

    :type ports: list
    :param ports: List of ports and port ranges to add (e.g. ["8080", "8080-9090"])

    :type proto: str
    :param proto: Protocol ('tcp' or 'udp')

    :type setype: str
    :param setype: SELinux type

    :type do_reload: bool
    :param do_reload: Whether to reload SELinux policy after commit

    :type serange: str
    :param serange: SELinux MLS/MCS range (defaults to 's0')

    :type sestore: str
    :param sestore: SELinux store

    :rtype: bool
    :return: True if the policy was changed, otherwise False
    """
    change = False
    try:
        seport = seobject.portRecords(sestore)
        seport.set_reload(do_reload)
        ports_by_type = semanage_port_get_ports(seport, setype, proto)
        for port in ports:

            change = True
            port_type = semanage_port_get_type(seport, port, proto)
            if port_type is None:
                seport.add(port, proto, serange, setype)
            else:
                seport.modify(port, proto, serange, setype)

    except (ValueError, IOError, KeyError, OSError, RuntimeError) as e:
        # module.fail_json(msg="%s: %s\n" % (e.__class__.__name__, to_native(e)), exception=traceback.format_exc())
        raise e

    return change


def semanage_port_del(ports, proto, setype, do_reload, sestore=''):
    """ Delete SELinux port type definition from the policy.

    :type ports: list
    :param ports: List of ports and port ranges to delete (e.g. ["8080", "8080-9090"])

    :type proto: str
    :param proto: Protocol ('tcp' or 'udp')

    :type setype: str
    :param setype: SELinux type.

    :type do_reload: bool
    :param do_reload: Whether to reload SELinux policy after commit

    :type sestore: str
    :param sestore: SELinux store

    :rtype: bool
    :return: True if the policy was changed, otherwise False
    """
    change = False
    try:
        seport = seobject.portRecords(sestore)
        seport.set_reload(do_reload)
        ports_by_type = semanage_port_get_ports(seport, setype, proto)
        for port in ports:
            if port in ports_by_type:
                change = True
                seport.delete(port, proto)

    except (ValueError, IOError, KeyError, OSError, RuntimeError) as e:
        # module.fail_json(msg="%s: %s\n" % (e.__class__.__name__, to_native(e)), exception=traceback.format_exc())
        raise e

    return change


def main():

    ports = sys.argv[1].split(",")
    proto = sys.argv[2]
    setype = sys.argv[3]
    state = sys.argv[4]
    do_reload = True

    result = {
        'ports': ports,
        'proto': proto,
        'setype': setype,
        'state': state,
    }

    if state == 'present':
        result['changed'] = semanage_port_add(ports, proto, setype, do_reload)
    elif state == 'absent':
        result['changed'] = semanage_port_del(ports, proto, setype, do_reload)


if __name__ == '__main__':
    main()
