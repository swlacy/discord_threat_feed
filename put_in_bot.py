# PUT THIS CODE IN YOUR BOT
# Should regularly query feeds (maybe once per hour)
# Then paste return strings in your threat feed channel

from discord_threat_feed import get_threat_feed

# Alias list:
# 'cisa':   'https://www.cisa.gov/uscert/ncas/alerts.xml'
# 'nist':   'https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml'
# 'tp':     'https://threatpost.com/feed/'
# 'bp':     'https://www.bleepingcomputer.com/feed'
#
#

# If posts aren't being made, check that they aren't listed in `post_id.db`

latest_cisa_rss = get_threat_feed('cisa')
if latest_cisa_rss:
    print(latest_cisa_rss) # Should instead direct to a channel your bot can post in

latest_nist_rss = get_threat_feed('nist')
if latest_nist_rss:
    print(latest_nist_rss) # Should instead direct to a channel your bot can post in

latest_tp_rss = get_threat_feed('tp')
if latest_tp_rss:
    print(latest_tp_rss) # Should instead direct to a channel your bot can post in

latest_bc_rss = get_threat_feed('bc')
if latest_bc_rss:
    print(latest_bc_rss) # Should instead direct to a channel your bot can post in