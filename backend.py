import dns.resolver

import dns.rdatatype
import dns.name 

from dns.asyncresolver import Resolver
from time import perf_counter
import asyncio

# DONE: list the anti-spam databases
# needed to decrease the providers down to 30ish to bring down the async calls into half.
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


#TODO: SAVE STATUS RESULTS
results = {
 'access.redhawk.org': False,
 'all.s5h.net': False,
 'b.barracudacentral.org': False,
 'bl.spamcop.net': False,
 'bl.tiopan.com': False,
 'blackholes.wirehub.net': False,
 'blacklist.sci.kun.nl': False,
 'block.dnsbl.sorbs.net': False,
 'blocked.hilli.dk': False,
 'bogons.cymru.com': False,
 'cbl.abuseat.org': False,
 'dev.null.dk': False,
 'dialup.blacklist.jippg.org': False,
 'dialups.mail-abuse.org': False,
 'dialups.visi.com': False,
 'dnsbl.abuse.ch': False,
 'dnsbl.anticaptcha.net': False,
 'dnsbl.antispam.or.id': False,
 'dnsbl.dronebl.org': False,
 'dnsbl.justspam.org': False,
 'dnsbl.kempt.net': False,
 'dnsbl.sorbs.net': False,
 'dnsbl.tornevall.org': False,
 'dnsbl-1.uceprotect.net': False,
 'duinv.aupads.org': False,
 'dnsbl-2.uceprotect.net': False,
 'dnsbl-3.uceprotect.net': False,
 'dul.dnsbl.sorbs.net': False,
 'escalations.dnsbl.sorbs.net': False,
 'hil.habeas.com': False,
 'black.junkemailfilter.com': False,
 'http.dnsbl.sorbs.net': False,
 'intruders.docs.uu.se': False,
 'ips.backscatterer.org': False,
 'korea.services.net': False,
 'mail-abuse.blacklist.jippg.org': False,
 'misc.dnsbl.sorbs.net': False,
 'msgid.bl.gweep.ca': False,
 'new.dnsbl.sorbs.net': False,
 'no-more-funn.moensted.dk': False,
 'old.dnsbl.sorbs.net': False,
 'opm.tornevall.org': False,
 'pbl.spamhaus.org': False,
 'proxy.bl.gweep.ca': False,
 'psbl.surriel.com': False,
 'pss.spambusters.org.ar': False,
 'rbl.schulte.org': False,
 'rbl.snark.net': False,
 'recent.dnsbl.sorbs.net': False,
 'relays.bl.gweep.ca': False,
 'relays.mail-abuse.org': False,
 'relays.nether.net': False,
 'rsbl.aupads.org': False,
 'sbl.spamhaus.org': False,
 'smtp.dnsbl.sorbs.net': False,
 'socks.dnsbl.sorbs.net': False,
 'spam.dnsbl.sorbs.net': False,
 'spam.olsentech.net': False,
 'spamguard.leadmon.net': False,
 'spamsources.fabel.dk': False,
 'ubl.unsubscore.com': False,
 'web.dnsbl.sorbs.net': False,
 'xbl.spamhaus.org': False,
 'zen.spamhaus.org': False,
 'zombie.dnsbl.sorbs.net': False,
 'bl.mailspike.net': False,
}

#TODO: MAKE URL TO DO PERFORM CHECKING
def make_url_from_ip(ip_addr, bl_provider):
    reversed_ip_addr = '.'.join(ip_addr.split('.')[::-1])
    return f'{reversed_ip_addr}.{bl_provider}'

count = 0
async def check_provider_status(url):
    isp_dns = '127.0.0.53'
    google_dns = '8.8.8.8'
    cloudflare_dns = '1.1.1.1'

    # setting configure=False 
    # makes sure Resolver Stub doesn't check system's /etc/resolv.conf
    # eachtime
    async_resolver = Resolver(configure=False)
    async_resolver.nameservers = [google_dns]
    async_resolver.lifetime = 100
    async_resolver.timeout = 2

    # We need to get A record   
    record_type = dns.rdatatype.A
    lifetime = 30

    try:
        global count
        count += 1
        answers = await async_resolver.resolve(url, record_type, lifetime=lifetime)
    except Exception as e:
        # print(e)
        return False
    return True


#TODO: CHECK FOR THE PRESENCE IN ANTI-SPAM DATABASE FOR THE IP
async def check_status(ip_addr):
    # urls = [make_url_from_ip(ip_addr, bl) for bl in blacklist_providers]
    checking_tasks = []
    for bl in blacklist_providers:
        url = make_url_from_ip(ip_addr, bl)

        # check_provider_status is network bound function
        task = asyncio.create_task(check_provider_status(url))
        checking_tasks.append(task)
    statuses  = await asyncio.gather(*checking_tasks)
    # print(statuses)
    result = results.copy()
    # result = dict()
    result = []
    for bl_provider, status in zip(blacklist_providers, statuses):
        # result[bl_provider] = status
        if status:
            result.append(bl_provider)
     
    return result


if __name__ == '__main__':
    start = perf_counter()
    ip_addr = '202.83.124.95'
    print(asyncio.run(check_status(ip_addr)))
    stop = perf_counter()
    print('############### TIME TAKES ############## :: ', stop - start)
    print('TOTAL DATABASE CHECKED: ', count)

    # print(results)
    # display_results()

