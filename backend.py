import dns.resolver

import dns.rdatatype
import dns.name 

from dns.asyncresolver import Resolver
from time import perf_counter
import asyncio

#TODO: list the anti-spam databases
blacklist_providers = [
 'access.redhawk.org',
 'all.s5h.net',
 'b.barracudacentral.org',
 'bl.spamcop.net',
 'bl.tiopan.com',
 'blackholes.wirehub.net',
 'blacklist.sci.kun.nl',
 'block.dnsbl.sorbs.net',
 'blocked.hilli.dk',
 'bogons.cymru.com',
 'cbl.abuseat.org',
 'dev.null.dk',
 'dialup.blacklist.jippg.org',
 'dialups.mail-abuse.org',
 'dialups.visi.com',
 'dnsbl.abuse.ch',
 'dnsbl.anticaptcha.net',
 'dnsbl.antispam.or.id',
 'dnsbl.dronebl.org',
 'dnsbl.justspam.org',
 'dnsbl.kempt.net',
 'dnsbl.sorbs.net',
 'dnsbl.tornevall.org',
 'dnsbl-1.uceprotect.net',
 'duinv.aupads.org',
 'dnsbl-2.uceprotect.net',
 'dnsbl-3.uceprotect.net',
 'dul.dnsbl.sorbs.net',
 'escalations.dnsbl.sorbs.net',
 'hil.habeas.com',
 'black.junkemailfilter.com',
 'http.dnsbl.sorbs.net',
 'intruders.docs.uu.se',
 'ips.backscatterer.org',
 'korea.services.net',
 'mail-abuse.blacklist.jippg.org',
 'misc.dnsbl.sorbs.net',
 'msgid.bl.gweep.ca',
 'new.dnsbl.sorbs.net',
 'no-more-funn.moensted.dk',
 'old.dnsbl.sorbs.net',
 'opm.tornevall.org',
 'pbl.spamhaus.org',
 'proxy.bl.gweep.ca',
 'psbl.surriel.com',
 'pss.spambusters.org.ar',
 'rbl.schulte.org',
 'rbl.snark.net',
 'recent.dnsbl.sorbs.net',
 'relays.bl.gweep.ca',
 'relays.mail-abuse.org',
 'relays.nether.net',
 'rsbl.aupads.org',
 'sbl.spamhaus.org',
 'smtp.dnsbl.sorbs.net',
 'socks.dnsbl.sorbs.net',
 'spam.dnsbl.sorbs.net',
 'spam.olsentech.net',
 'spamguard.leadmon.net',
 'spamsources.fabel.dk',
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


async def check_provider_status(url):
    isp_dns = '127.0.0.53'
    google_dns = '8.8.8.8'
    cloudflare_dns = '1.1.1.1'

    resolver = Resolver()
    resolver.nameservers = [cloudflare_dns]
    resolver.timeout = 20

    # We need to get A record   
    record_type = dns.rdatatype.A

    try:
        answers = await resolver.resolve(url, record_type)
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
    for bl_provider, status in zip(blacklist_providers, statuses):
        if status:
            print(f"{bl_provider} : {'✅'if status else False}")


if __name__ == '__main__':
    start = perf_counter()
    ip_addr = '103.251.167.20'
    asyncio.run(check_status(ip_addr))
    stop = perf_counter()
    print('############### TIME TAKES ############## :: ', stop - start)
    print('TOTAL DATABASE CHECKED: ', len(blacklist_providers))

    # display_results()

