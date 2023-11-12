import asyncio
import json
from time import perf_counter
from backend import check_status, results
# from backend_aiodns import check_status as aiodns_check_status

# SOLVED.
# Throws Error.
# OSError: [Errno 24] Too many open files: '/etc/resolv.conf'
def get_host_addresses(cidr = '202.83.124.0/25'):
    import ipaddress
    subnet = ipaddress.IPv4Network(cidr, strict=False)
    hosts = list(map(lambda ip: ip.__str__(), subnet.hosts()))
    return hosts 

ip_addresses1 = get_host_addresses()
ip_addresses2 = get_host_addresses(cidr='202.83.124.128/24')



async def get_statuses(ip_list):
    task_list = []
    for ip in ip_list:
        task = asyncio.create_task(check_status(ip))
        # task = asyncio.create_task(aiodns_check_status(ip))
        task_list.append(task)
    statuses_list  = await asyncio.gather(*task_list)
    ip_list_status_result = dict()
    for ip, status_res in zip(ip_list, statuses_list):
        ip_list_status_result[ip] = status_res
    return json.dumps(ip_list_status_result, indent=4)



import multiprocessing
start = perf_counter()
print(asyncio.run(get_statuses(ip_addresses2)))
end = perf_counter()

print('############### TIME TAKES ############## :: ', end - start)


# print(results)

