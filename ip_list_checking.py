import asyncio
import json
from time import perf_counter
from backend import check_status, results

# SOLVED.
# Throws Error.
# OSError: [Errno 24] Too many open files: '/etc/resolv.conf'
def get_host_addresses(cidr = '202.83.124.0/26'):
    import ipaddress
    subnet = ipaddress.IPv4Network(cidr, strict=False)
    hosts = list(map(lambda ip: ip.__str__(), subnet.hosts()))
    return hosts 

ip_addresses = get_host_addresses()

# ip_addresses = [
#     '103.251.167.4',
#     '103.251.167.5',
#     '103.251.167.6',
#     '103.251.167.7',
#     '103.251.167.8',
#     '103.251.167.9',
#     '103.251.167.10',
#     '103.251.167.11',
#     '103.251.167.12',
#     '103.251.167.13',
#     '103.251.167.14',
#     '103.251.167.15',
#     '103.251.167.16',
#     '103.251.167.17',
#     '103.251.167.18',
#     '103.251.167.19',
#     '103.251.167.20',
#     '103.251.167.21',
#     '103.251.167.22',
#     '103.251.167.23',
#     '103.251.167.24',
#     '103.251.167.25',
#     '103.251.167.26',
#     '103.251.167.27',
#     '103.251.167.28',
#     '103.251.167.29',
#     '103.251.167.30',
# ]

async def get_statuses(ip_list):
    task_list = []
    for ip in ip_list:
        task = asyncio.create_task(check_status(ip))
        task_list.append(task)
    statuses_list  = await asyncio.gather(*task_list)
    ip_list_status_result = dict()
    for ip, status_res in zip(ip_list, statuses_list):
        ip_list_status_result[ip] = status_res
    return json.dumps(ip_list_status_result, indent=4)



start = perf_counter()
print(asyncio.run(get_statuses(ip_addresses)))
end = perf_counter()

print('############### TIME TAKES ############## :: ', end - start)


# print(results)

