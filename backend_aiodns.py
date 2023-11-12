import asyncio
import aiodns

blacklist_providers = [
 'access.redhawk.org',
 'all.s5h.net',
 'b.barracudacentral.org',
 'bl.spamcop.net',
 'cbl.abuseat.org',
 'dialup.blacklist.jippg.org',
 'dialups.mail-abuse.org',
 'dnsbl.abuse.ch',
 'dnsbl.dronebl.org',
 'dnsbl.justspam.org',
 'dnsbl.sorbs.net',
 'dnsbl.tornevall.org',
 'dnsbl-1.uceprotect.net',
 'dnsbl-2.uceprotect.net',
 'dnsbl-3.uceprotect.net',
 'dul.dnsbl.sorbs.net',
 'black.junkemailfilter.com',
 'http.dnsbl.sorbs.net',
 'intruders.docs.uu.se',
 'misc.dnsbl.sorbs.net',
 'opm.tornevall.org',
 'pbl.spamhaus.org',
 'recent.dnsbl.sorbs.net',
 'relays.mail-abuse.org',
 'sbl.spamhaus.org',
 'smtp.dnsbl.sorbs.net',
 'spam.dnsbl.sorbs.net',
 'ubl.unsubscore.com',
 'web.dnsbl.sorbs.net',
 'xbl.spamhaus.org',
 'zen.spamhaus.org',
 'zombie.dnsbl.sorbs.net',
 'bl.mailspike.net'
]



loop = asyncio.get_event_loop()
resolver = aiodns.DNSResolver(loop=loop)


def make_url_from_ip(ip_addr, bl_provider):
    reversed_ip_addr = '.'.join(ip_addr.split('.')[::-1])
    return f'{reversed_ip_addr}.{bl_provider}'


async def query(name, query_type):
    try:
        answer = await resolver.query(name, query_type)
    except Exception as e:
        # print(e)
        return False
    return True


async def check_status(ip_addr):
    tasks = []
    for bl in blacklist_providers:
        url = make_url_from_ip(ip_addr, bl)
        task = asyncio.create_task(query(url, 'A'))
        tasks.append(task)
    statuses = await asyncio.gather(*tasks)
    result = []
    for bl_provider, status in zip(blacklist_providers, statuses):
        # result[bl_provider] = status
        if status:
            result.append(bl_provider)
     
    return result

    

# coro = query('google.com', 'A')
from time import perf_counter
start = perf_counter()
result = loop.run_until_complete(check_status('202.83.124.95'))
end = perf_counter()
print('time took: ', end-start)
print(result)