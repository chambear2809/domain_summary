#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
Python 2.7.x only
domain_summary


Copyright (C) 2015 Cisco Systems Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

'''
__appname__ = 'html_domain_summary'
__version__ = '1.0.0'

import argparse
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings() 
import re
import cobra.mit.access
import cobra.mit.session
import sys
# This is the abstract class to store ACI mo
class AbsBaseObj:
    def __init__(self, mo):
        self.mo = mo
        self.tDn = None

    @property
    def name(self):
        return self.mo.name

    def get_mo(self):
        return self.mo


class AbsRangeObj(AbsBaseObj):
    def __init__(self, mo):
        AbsBaseObj.__init__(self, mo)
        self.list = []
        self.tDn = None

    @property
    def list(self):
        return self.list

    @property
    def tDn(self):
        return self.tDn

    @tDn.setter
    def tDn(self, tDn):
        self.tDn = tDn


# This class is to store the vlan pool information
class VlanPool(AbsRangeObj):
    def add_range(self, mo):
        first_id = getattr(mo, 'from')
        first_id = first_id.strip("vlan-")
        last_id = mo.to
        last_id = last_id.strip("vlan-")
        if first_id == last_id:
            range = first_id
        else:
            range = first_id + "-" + last_id
        self.list.append(range)


# This class is to store the node profile information
class Node(AbsRangeObj):
    def add_range(self, mo):
        first_id = mo.from_
        last_id = mo.to_
        if first_id == last_id:
            range = first_id
        else:
            range = first_id + "-" + last_id
        self.list.append(range)

# This class is to store the interface profile information
class IfProf(AbsRangeObj):
    def add_range(self, mo):
        first_id = mo.fromCard + "/" + mo.fromPort
        last_id = mo.toCard + "/" + mo.toPort
        if first_id == last_id:
            range = first_id
        else:
            range = first_id + "-" + last_id
        self.list.append(range)


# Get Tenant and EPG information from infraRtDomAtt.tDn
def dn_to_epg(dn):
    m = re.search('/tn-(.+)/ap-.+/epg-(.+)', str(dn))
    if m:
        return m.group(1) + ':' + m.group(2)
    else:
        return None

# Parse command line arguments
def get_args():
    parser = argparse.ArgumentParser(description="Show the summary of AEP")
    parser.add_argument('-u', default='admin', dest='username',help='Default is admin')
    parser.add_argument('-p', dest='password', required=True)
    parser.add_argument('-a', dest='url',help='URL of APIC(Ex. http://10.0.0.1)', required=True)
    args = parser.parse_args()
    return args

def dic_0_Term(domainInfo):
    print
    print
    headerz =   "{:<20s}{:<20s}{:<25s}{:<20s}{:<20s}{:<20s}{:<20s}{:<20s}{:<20s}{:<20s}\n".format("DOMAIN","TYPE","EPG","VLAN","vlan_info","NODE","nodeinfo","port_info","IF_PROF","AEP")
    print ' ', headerz
    print '========================================================================================================================================================================================\n'
    for i in domainInfo:
        linez = "{:<20s}{:<20s}{:<25s}{:<20s}{:<20s}{:<20s}{:<20s}{:<20s}{:<20s}{:<20s}".format(i["DOMAIN"],i["TYPE"],i["EPG"],i["VLAN"],i["vlan_info"],i["NODE"],i["nodeinfo"],i["port_info"],i["IF_PROF"],i["AEP"])
        print ' ',linez
    return linez


# Main function
def main(ipaddr, username, password):
    apicUrl = "https://"+ ipaddr
    ls = cobra.mit.session.LoginSession(apicUrl, username, password,secure=False, timeout=180)
    md = cobra.mit.access.MoDirectory(ls)
    md.login()

#     print '########################################################### Get Node Profiles'
    q = cobra.mit.request.ClassQuery('uni/' + 'infraNodeP')
    q.subtree = 'full'
    mos = md.query(q)
    ##
    nodes = {}
    for mo in mos:
        node = Node(mo)
        for leaf in  mo.leaves:
            for node_blk in leaf.nodeblk:
                node.add_range(node_blk)
        nodes[mo.dn] = node
#     for i in nodes:
#         print '==nodes==> ',i

#     print '########################################################### Get Interface Profiles'
    q = cobra.mit.request.ClassQuery('uni/' + 'infraAccPortP')
    q.subtree = 'full'
    q.subtreeClassFilter = ['infraRtAccPortP', 'infraHPortS', 'infraPortBlk']
    mos = md.query(q)
    ##
    if_profs = {}
    for mo in mos:
        for rtaccportps in mo.rtaccPortP:
            tDn = rtaccportps.tDn
            for hport in  mo.hports:
                if_prof = IfProf(mo)
                if_prof.tDn = tDn
                for portblk in hport.portblk:
                    if_prof.add_range(portblk)
                if_profs[hport.dn] = if_prof
#     for i in if_profs:
#         print '==if_profs==> ',i

#     print '########################################################### Get Interface Policy Groups'
    q = cobra.mit.request.ClassQuery('uni/' + 'infraAccPortGrp')
    q.subtree = 'children'
    q.subtreeClassFilter = 'infraRtAccBaseGrp'
    mos = md.query(q)
    ##
    if_pol_groups = {}
    for mo in mos:
        if_pol_groups[mo.dn] = mo
#     for i in if_pol_groups:
#         print '==if_pol_groups==> ',i

#     print '########################################################### Get AEP information'
    q = cobra.mit.request.ClassQuery('uni/' + 'infraAttEntityP')
    q.subtree = 'children'
    q.subtreeClassFilter = 'infraRtAttEntP'
    mos = md.query(q)
    ##
    aeps = {}
    for mo in mos:
        aeps[mo.dn] = mo
#     for i in aeps:
#         print '==aeps==> ',i

#     print '########################################################### Get vlan pools'
    q = cobra.mit.request.ClassQuery('uni/' + 'fvnsVlanInstP')
    q.subtree = 'children'
    q.subtreeClassFilter = 'fvnsEncapBlk'
    mos = md.query(q)
    ##
    vlan_pools = {}
    for mo in mos:
        vlan_pool =  VlanPool(mo)
        for child in mo.children:
            vlan_pool.add_range(child)
        vlan_pools[mo.dn] = vlan_pool
#     for i in vlan_pools:
#       print '==vlan_pools==> ',i

#     print '########################################################### Get Domain information'
    ## l3extDomP, physDomP, l2extDomP, vmmDomP
    domainInfo = []
    HtmldomainInfo = []
    forHtmlString = ""

    forHtmlString += '<pre>'
    forHtmlString += '<!DOCTYPE>'
    forHtmlString += '<html>'
    forHtmlString += '<head>'
    forHtmlString += '<script type="text/javascript" src="http://ajax.googleapis.com/ajax/libs/jquery/1.6.2/jquery.min.js"></script>'
    forHtmlString += '<link rel="shortcut icon" href="/static/favicon.ico" type="image/x-icon">'
    forHtmlString += '<link rel="icon" href="/static/favicon.ico" type="image/x-icon">'
    forHtmlString += '<link href="/static/style.css" rel="stylesheet">'
    forHtmlString += '</head>'
    forHtmlString += '<body>'
    forHtmlString += '<a href="/select_script"><img src="/static/cisco-logo.png" alt="Cisco Logo" width="10%" height="10%" ></a>'
    forHtmlString += "<br>"
    forHtmlString += '<br><b>       Domain Summary: Get Domains, VLAN pools, AEPs, Port and Switch profiles and show the summary of the information<br>'
    forHtmlString += "<br>"
    HtmldomainInfo.append(forHtmlString)
    forHtmlString = ""


    class_list = ('l3extDomP', 'physDomP', 'l2extDomP', 'vmmDomP')
    for cl in class_list:

        q = cobra.mit.request.ClassQuery('uni/' + cl)
        q.subtreeClassFilter = ['infraRsVlanNs', 'infraRtDomP','infraRtDomAtt']
        q.subtree = 'full'
        domains = md.query(q)

        for domain in domains:
            forHtmlString = ""
            temp = {'DOMAIN':"",'TYPE':"",'EPG':"",'VLAN':"",'vlan_info':"",'AEP':"",'IF_POL_G':"",'NODE':"",'nodeinfo':"",'IF_PROF':"",'port_info':""}
            print
            print '================================================================================='
            linez = '================================================================================='
            forHtmlString += linez+"<br>"
            print "DOMAIN: {:<40s}       TYPE:        {:<20s}".format(domain.name, cl)
            linez = "DOMAIN: {:<40s}       TYPE:        {:<20s}".format(domain.name, cl)
            forHtmlString += linez+"<br>"
            temp['DOMAIN'] = domain.name
            temp['TYPE'] = cl
            for child in domain.rtfvDomAtt:
                tDn = child.tDn
                print "    EPG:       {:<40s}".format(dn_to_epg(tDn))
                linez = "    EPG:       {:<40s}".format(dn_to_epg(tDn))
                forHtmlString += linez+"<br>"
                temp['EPG'] = dn_to_epg(tDn)
            for child in domain.rsvlanNs:
                tDn = child.tDn
                if vlan_pools.has_key(tDn):
                    vlan_info = ""
                    for vlan in vlan_pools[tDn].list:
                        vlan_info = vlan_info + " " + vlan
                    print "    VLAN:      {:<40s}VLAN_INFO:  {:<20s}".format(vlan_pools[tDn].name, vlan_info)
                    linez = "    VLAN:      {:<40s}VLAN_INFO:  {:<20s}".format(vlan_pools[tDn].name, vlan_info)
                    forHtmlString += linez+"<br>"
                    temp['VLAN'] = vlan_pools[tDn].name
                    temp['vlan_info'] = vlan_info
            for child in domain.rtdomP:
                tDn = child.tDn
                if aeps.has_key(tDn):
                    print "    AEP:       {:<40s}".format(aeps[tDn].name)
                    linez = "    AEP:       {:<40s}".format(aeps[tDn].name)
                    forHtmlString += linez+"<br>"
                    temp['AEP'] = aeps[tDn].name
                    for child2 in aeps[tDn].rtattEntP:
                        tDn2 = child2.tDn
                        if if_pol_groups.has_key(tDn2):
                            print "    IF_POL_G:  {:<40s}".format(if_pol_groups[tDn2].name)
                            linez = "    IF_POL_G:  {:<40s}".format(if_pol_groups[tDn2].name)
                            forHtmlString += linez+"<br>"
                            temp['IF_POL_G'] = if_pol_groups[tDn2].name
                            for child3 in if_pol_groups[tDn2].rtaccBaseGrp:
                                tDn3 = child3.tDn
                                if if_profs.has_key(tDn3):
                                    tDn4 = if_profs[tDn3].tDn
                                    if nodes.has_key(tDn4):
                                        node_info = " "
                                        for node in nodes[tDn4].list:
                                            node_info = node_info + " " + node
                                        print "    NODE:      {:<40s}NODE_INFO: {:<20s}".format(nodes[tDn4].name, node_info)
                                        linez = "    NODE:      {:<40s}NODE_INFO: {:<20s}".format(nodes[tDn4].name, node_info)
                                        forHtmlString += linez+"<br>"
                                        temp['NODE'] = nodes[tDn4].name
                                        temp['nodeinfo'] = node_info
                                    port_info = ""
                                    for port in if_profs[tDn3].list:
                                        port_info = port_info + " " + port
                                    print "    IF_PROF:   {:<40s}PORT_INFO:  {:<20s}".format(if_profs[tDn3].name, port_info)
                                    linez = "    IF_PROF:   {:<40s}PORT_INFO:  {:<20s}".format(if_profs[tDn3].name, port_info)
                                    forHtmlString += linez+"<br>"
                                    temp['IF_PROF'] = if_profs[tDn3].name
                                    temp['port_info'] = port_info
#                                     print '=== temp ===> ', temp
            domainInfo.append(temp)
            HtmldomainInfo.append(forHtmlString)

    forHtmlString = ""
    forHtmlString += '<div id="power">'
    forHtmlString += 'Powered By'
    forHtmlString += '<img src="/static/cisco-tac.jpg" alt="Cisco TAC" width="25%" height="25%" >'
    forHtmlString += '</div>'

    forHtmlString += '</body>'
    forHtmlString += '</html>'
    forHtmlString += '</pre>'
    HtmldomainInfo.append(forHtmlString)

    return HtmldomainInfo

if __name__ == "__main__":
    apicIP, userID, pw = '', '',''
    main(sys.argv[1],sys.argv[2],sys.argv[3])
