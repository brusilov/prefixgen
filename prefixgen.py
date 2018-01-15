import requests
import simplejson as json
import sys
import re
import netaddr


def ripe_lookup(ripe_obj):
    if ripe_vault.count(ripe_obj) > 1:
        print(ripe_obj + ' already exists')
        return
    if re.findall(asset_regex, ripe_obj):
        asset_var = 1
        try:
            response = requests.get(
                'http://rest.db.ripe.net/search.json?query-string={0}&flags=no-filtering'.format(ripe_obj), timeout=10)
            response.raise_for_status()
        except requests.exceptions.ConnectTimeout:
            print('ConnectTimeout')
        except requests.exceptions.ReadTimeout:
            print('ReadTimeout')
        except requests.exceptions.ConnectionError:
            print('ConnectionError')
        except requests.exceptions.HTTPError as err:
            print('HTTPError' + ' for ' + ripe_obj)
            print('Response is: {content}'.format(content=err.response.content))
    else:
        asset_var = 0
        try:
            response = requests.get(
                'http://rest.db.ripe.net/search.json?query-string={0}&inverse-attribute=origin&flags=no-filtering'.format(ripe_obj),
                timeout=10)
            response.raise_for_status()
        except requests.exceptions.ConnectTimeout:
            print('ConnectTimeout')
        except requests.exceptions.ReadTimeout:
            print('ReadTimeout')
        except requests.exceptions.ConnectionError:
            print('ConnectionError')
        except requests.exceptions.HTTPError as err:
            print('HTTPError' + ' for ' + ripe_obj)
            print('Response is: {content}'.format(content=err.response.content))

    json_obj = json.loads(response.content)
    if 'errormessages' in json_obj.keys():
        print(ripe_obj)
        print(json_obj['errormessages']['errormessage'])
        return

    for obj1 in json_obj['objects']['object']:
        for obj2 in obj1['attributes']['attribute']:
            if obj2['name'] == 'members' and asset_var == 1:
                ripe_vault.append(obj2['value'])
                ripe_lookup(obj2['value'])
            elif obj2['name'] == 'route' and asset_var == 0:
                ripe_vault.append(obj2['value'])


def prefixes_merge(prefixes_list):
    start_prefixes_dict = {str(n): [] for n in range(32, 0, -1)}
    final_prefixes_dict = {}
    final_prefixes_list = []

    for ip in prefixes_list:
        start_prefixes_dict[netaddr.IPNetwork(ip).prefixlen.__str__()].append(netaddr.IPNetwork(ip))

    for k, v in start_prefixes_dict.items():
        if str(v or '') == '':
            continue
        final_prefixes_dict[k] = netaddr.cidr_merge(v)

    for k, v in final_prefixes_dict.items():
        for i in v:
            final_prefixes_list.append([k, i.__str__()])

    flat = [x for row in final_prefixes_list for x in row]

    print('no ip prefix-list {0}'.format(sys.argv[1]))
    for idx, i in enumerate(flat[1:], 1):
        if idx % 2 == 1:
            if flat.count(i) > 1 and i.endswith(flat[idx - 1]):
                continue
            elif i.endswith(flat[idx-1]):
                print('ip prefix-list {0} permit {1}'.format(sys.argv[1], i))
            else:
                print('ip prefix-list {0} permit {1} {2}'.format(sys.argv[1], i, 'le ' + flat[idx-1]))


asset_regex = re.compile(r'(AS-\w*|as-\w*)')
prefix_regex = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}')
ripe_vault = []

ripe_lookup(sys.argv[1])
prefixes = list(filter(prefix_regex.match, ripe_vault))
prefixes_merge(prefixes)
