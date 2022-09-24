#!/usr/bin/env python3

'''
Discord bot module that pulls cyber threat alerts from several RSS feeds
'''

from hashlib import sha256
from feedparser import parse as rss
from markdownify import markdownify as md

DB_FILE = 'post_id.db'       # Database file; if lost, reconstruct with db_recon.py

# Accepts list of strings with post content
# Returns formatted, single string for posting
def make_str(element_list):
    '''
    Format post for publishing in standardized format:

    **[!] {publisher} ALERT: {title}**
    *Published {date}*

    > {content}

    *Read more at {link}*
    '''
    ret_str = f'**[!] {element_list[0]} ALERT: '        # Publisher, bolded
    ret_str += f'{element_list[1]}**\n'                 # Title, bolded
    ret_str += f'*Published {element_list[2]}*\n\n'     # Post date, italicized
    ret_str += f'> {element_list[3]}\n\n'               # Post summary, quoted
    ret_str += f'*Read more at {element_list[4]}*\n\n'  # Source, italicized
    return ret_str

# Accepts post post_id (sha256 sum)
# Returns True if post_id found in database file; false otherwise
def query_db(post_id):
    '''
    Check if post already made by referencing the post_id database
    '''
    with open(DB_FILE, 'r', encoding='utf-8') as database:
        if post_id in database.read():
            return True
    return False

# Accepts post post_id (sha256 sum)
# Returns nothing
def append_db(post_id):
    '''
    Add post post_id to database file
    '''
    with open(DB_FILE, 'a', encoding='utf-8') as database:
        database.write(f'{post_id}\n')

# Accepts formatted post string
# Interfaces with database file to determine whether to post
# Returns full post string or None depending on determination above
def post(post_str):
    '''
    Appends post post_id to post string
    Checks database:
        If already posted, skip post
        If not yet posted, post and append post_id to database file
    '''
    post_id = sha256(post_str.encode("utf-8")).hexdigest()
    post_str += f'`post_id={post_id}`' # Hash, code-blocked
    if query_db(post_id):
        return None
    append_db(post_id)
    return post_str

# Accepts raw RSS content and initial substring to exclude
# Returns markdown-formatted content as a single string
def content_format(content, split_str):
    '''
    Markdownifies content
    '''
    if split_str:
        content = content.split(split_str, 1)[1]
    content = md(content)
    if len(content) > 1500:
        content = content[0:1500] + '...' # Strip to fit within max single-message char count
    content = content.replace('\n\n', '\n')
    content = content.replace('\n', '\n> ')
    return content

######################################## ADD FUNCTIONS HERE ########################################

def cisa_gov_alerts():
    '''
    cisa.gov NCAS alerts
    '''
    url = 'https://www.cisa.gov/uscert/ncas/alerts.xml'
    split_str = '<h3>Summary</h3><p class="tip-intro" style="font-size: 15px;">'
    feed = rss(url).entries[0]
    element_list = [None] * 5
    element_list[0] = 'CISA (NCAS)'
    element_list[1] = feed.title
    element_list[2] = feed.published
    element_list[3] = content_format(feed.summary, split_str)
    element_list[4] = feed.link
    return element_list

def nist_gov_cves():
    '''
    nist.gov CVE alerts
    '''
    url = 'https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml'
    split_str = None
    feed = rss(url).entries[0]
    element_list = [None] * 5
    element_list[0] = 'NIST CVE'
    element_list[1] = feed.title
    element_list[2] = feed.updated
    element_list[3] = content_format(feed.summary, split_str)
    element_list[4] = feed.link
    return element_list

def threatpost_com_newslinks():
    '''
    ThreatPost news links
    '''
    url = 'https://threatpost.com/feed/'
    split_str = None
    feed = rss(url).entries[0]
    element_list = [None] * 5
    element_list[0] = 'ThreatPost'
    element_list[1] = feed.title
    element_list[2] = feed.published
    element_list[3] = content_format(feed.summary, split_str)
    element_list[4] = feed.link
    return element_list

def bleepingcomputer_com_newslinks():
    '''
    Bleeping Computer news links
    '''
    url = 'https://www.bleepingcomputer.com/feed/'
    split_str = None
    feed = rss(url).entries[0]
    element_list = [None] * 5
    element_list[0] = 'Bleeping Computer'
    element_list[1] = feed.title
    element_list[2] = feed.published
    element_list[3] = content_format(feed.summary, split_str)
    element_list[4] = feed.link
    return element_list

####################################################################################################

# Accepts function to run
# Returns formatted post string
def get_threat_feed(func):
    '''
    Driver
    '''
    # Create database file if it doesn't exist; otherwise, open + close
    open(DB_FILE, 'a+',  encoding='utf-8').close()

    ret_str = ''
    match func:
        case 'cisa':
            ret_str = post(make_str(cisa_gov_alerts()))
        case 'nist':
            ret_str = post(make_str(nist_gov_cves()))
        case 'tp':
            ret_str = post(make_str(threatpost_com_newslinks()))
        case 'bc':
            ret_str = post(make_str(bleepingcomputer_com_newslinks()))
        case _:
            ret_str = f'Undefined function alias \'{func}\'; check spelling'

    return ret_str
