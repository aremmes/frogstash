import sys
import json
import requests
import time
import calendar
import datetime
import smtplib
import MySQLdb as mdb
from pymongo import MongoClient
from elasticsearch import Elasticsearch
from collections import defaultdict
from email.mime.text import MIMEText

def query_string(timeframe, term, npa_type):
  if npa_type == "international":
    term = "011"+term
  if timeframe is "current":
    return "request_method:INVITE && _exists_:ruri_host && (from_uri_host:64.94.19* || from_uri_host:198.58.4*) +@timestamp: [now-3h TO now] +from_uri_user:%s*" % (term)
  elif timeframe is "past" :
    return "request_method:INVITE && _exists_:ruri_host && (from_uri_host:64.94.19* || from_uri_host:198.58.4*) +@timestamp: [now-3h-15m TO now-15m] +from_uri_user:%s*" % (term)

def count_query(timeframe, dst, src):
  if src.startswith('+'):
    src = src[1:]
  if dst.startswith('+'):
    dst = dst[1:]
  if timeframe is "current":
    return "request_method:INVITE && _exists_:ruri_host && (from_uri_host:64.94.19* || from_uri_host:198.58.4*) +@timestamp: [now-3h TO now] +from_uri_user:%s +ruri_user:%s" % (src, dst)
  if timeframe is "past":
    return "request_method:INVITE && _exists_:ruri_host && (from_uri_host:64.94.19* || from_uri_host:198.58.4*) +@timestamp: [now-3h-15m TO now-15m] +from_uri_user:%s +ruri_user:%s" % (src, dst)

def get_branch_id_from_src(con, src):
  if src.startswith('+'):
    src = src[1:]
  query = "SELECT b.branchId FROM branch b LEFT JOIN inventory i ON (b.customerId = i.assignedTo) WHERE i.identifier='%s'" % (src)
  cursor = con.cursor()
  cursor.execute(query)
  data = cursor.fetchall()
  for row in data:
    return row[0]

def customer_info(con, branch_id):
  query = "SELECT c.companyName, c.platformId FROM branch b LEFT JOIN customer c ON c.customerId=b.customerId WHERE b.branchId=%s" % (branch_id)
  cursor = con.cursor()
  cursor.execute(query)
  data = cursor.fetchall()
  return data[0]

def getCDR(con, config, timeframe, npa_type, calltype):
  if npa_type is "domestic":
    npa_list = "dom_npa_list"
    threshold = "dom_threshold"
  if npa_type is "international":
    npa_list = "intl_npa_list"
    threshold = "threshold"

  es = Elasticsearch([{'host': config['elasticsearch']['host'], 'port': 9200}])
  detected_fraud = list()

  for term in config[npa_list]:
    query = query_string(timeframe, term, npa_type)
    if calltype == "fax":
      query = query+" +log_message:FAX*"
    else:
      query = query+" +pstn_route_number:siproutes"
    page = es.search(
      index = 'opensips-*',
      scroll = '2m',
      search_type = 'scan',
      size = 100000,
      body = {
        "fields": ["from_uri_user", "ruri_user", "@timestamp", "log_message"],
        "query": {
            "bool": {
            "must": [
                { "range": { "@timestamp": { "gte": "now-3h", "lte": "now" } } },
                { "exists": { "field": "ruri_host" } },
                { "match": { "request_method": "INVITE" } },
                { "regexp": { "from_uri_user": "(1?(319|605|641|712|218)|011(242|246|264|268|284|340|345|441|473|649|664|670|671|684|721|758|767|784|809|829|849|867|868|869|876|939)).*" } }
            ],
            "should": [
                { "wildcard": { "from_uri_host": "64.94.19*" } },
                { "wildcard": { "from_uri_host": "198.58.4*" } }
            ],
            "minimum_should_match": 1
         }
      }
    })
    target = open('frog.log', 'a')
    target.write(query+"\n")
    target.close()
    sid = page['_scroll_id']
    scroll_size = page['hits']['total']
  
    used_numbers = list()
    while (scroll_size > 0):
      page = es.scroll(scroll_id = sid, scroll = '2m')
      sid = page['_scroll_id']
      scroll_size = len(page['hits']['hits'])
      hits = page['hits']['hits']
      for hit in hits:
        result = hit['fields']
        if result['from_uri_user'] in used_numbers:
          #already checked
          break
        else:
          used_numbers.append(result['from_uri_user'])
          src = result['from_uri_user'][0]
          dst = result['ruri_user'][0]
          log = result['log_message'][0]
          branch_id = get_branch_id_from_src(con, src)
          count = get_count(config, timeframe, dst, src, calltype)
          past_count = get_count(config, "past", dst, src, calltype)
          if branch_id is None:
            branch_id = -1
            customerName = "N/A"
            platform = "N/A"
          else:
            cust = customer_info(con, branch_id)
            customerName = cust[0]
            platform = "N/A"
            if int(cust[1]) is 1:
              platform = "Asterisk"
            elif int(cust[1]) is 2:
              platform = "Broadworks"
          result = {
            'customer': customerName,
            'platform': platform,
            'branchId': branch_id,
            'count': count,
            'past_count': past_count,
            'dst': dst,
            'src': src
          }
          if isFraud(config, result, threshold):
            detected_fraud.append(result)
  if len(detected_fraud) > 0:
    notify_support(config, npa_type, detected_fraud)

def format_message(npa_type, detected_fraud):
  message = ""
  for fraud in detected_fraud:
    message += "%s Fraud\n======================\nCustomer: %s\nBranch ID: %s\nCount: %s\nSource#: %s\nDestination#: %s\n======================\n" % (npa_type, fraud['customer'], fraud['branchId'], fraud['count'], str(fraud['src']), str(fraud['dst']))
  return message

def notify_support(config, npa_type, detected_fraud):
  message = format_message(npa_type, detected_fraud)
  msg = MIMEText(message)
  msg['Subject'] = '%s Fraud Detected' % npa_type
  msg['From'] = 'jfifer@coredial.com'
  msg['To'] = 'jfifer@coredial.com'
  target = open('frog.log', 'a')
  target.write(message+"\n")
  target.close()
  con = mdb.connect('localhost', 'root', 'monkeyshit', 'fraud');
  cursor = con.cursor()
  for fraud in detected_fraud:
    query = "INSERT INTO detected (dst, src, branch_id, customer, count) VALUES ('%s','%s','%s','%s','%s')" % (fraud['dst'], fraud['src'], fraud['branchId'], fraud['customer'], fraud['count'])
    cursor.execute(query)
  con.close()

  s = smtplib.SMTP('localhost')
  s.sendmail('jfifer@coredial.com', 'jfifer@coredial.com', msg.as_string())
  s.quit()

def isFraud(config, result, threshold_type):
  if str(result['branchId']) in config[threshold_type]:
    if threshold_type == 'threshold':
      block = config[threshold_type][str(result['branchId'])]['block']
    warn = config[threshold_type][str(result['branchId'])]['warn']
  else:
    if threshold_type == 'threshold':
      block = config[threshold_type]['_default_']['block']
    warn = config[threshold_type]['_default_']['warn']

  if int(result['count']) >= warn and int(result['count']) >= int(result['past_count']):
    return True
  else:
    return False

def get_count(config, timeframe, dst, src, calltype) :
  es = Elasticsearch([{'host': config['elasticsearch']['host'], 'port': 9200}])
  for term in config['dom_npa_list']:
    query = count_query(timeframe, dst, src)
    if calltype == "fax":
      query = query+" +log_message:FAX*"
    else:
      query = query+" +pstn_route_number:siproutes"
 
    target = open('frog.log', 'a')
    target.write(query)
    target.close()
    page = es.search(
      index = 'opensips-*',
      scroll = '2m',
      search_type = 'scan',
      size = 100000,
      body = {
        "fields": ["from_uri_user", "ruri_user", "@timestamp"],
        "query": {
          "query_string": {
            "query": query,
            "analyze_wildcard": "true"
          }
        }
    })
    sid = page['_scroll_id']
    scroll_size = page['hits']['total']

    used_numbers = list()
    while (scroll_size > 0):
      page = es.scroll(scroll_id = sid, scroll = '2m')
      sid = page['_scroll_id']
      scroll_size = len(page['hits']['hits'])
      hits = page['hits']['hits']
      return len(hits)

def main(argv):
  target = open('/home/jfifer/frogstash/frog.log', 'a')
  target.write("Running...\n")
  target.close()
  with open('/home/jfifer/frogstash/config/config.json') as json_data:
    config = json.load(json_data)
  con = mdb.connect(config["dsn"]["host"], config["dsn"]["user"], config["dsn"]["pass"], config["dsn"]["db"]);
  if len(argv) is 0:
    print "Please supply a command"
    exit()
  cmd = argv[0]
  if cmd == "detect_domestic_fraud":
    current_cdr = getCDR(con, config, "current", "domestic", "call")
  elif cmd == "detect_intl_fraud":
    current_cdr = getCDR(con, config, "current", "international", "call")
  elif cmd == "detect_fax_fraud":
    current_cdr = getCDR(con, config, "current", "domestic", "fax")
  else:
    print "Invalid command %s" % (argv[0])
    exit()

if __name__ == "__main__":
  main(sys.argv[1:])
