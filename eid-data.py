#!/usr/bin/env python
#
# Copyright (C) 2017-2020 Vincent Hardy (vincent.hardy@linuxunderground.be)
#
# This is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version
# 3.0 as published by the Free Software Foundation.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this software; if not, see
# https://www.gnu.org/licenses/
#

from PyKCS11 import *
import platform
import sys

class getData(object):

    def __init__(self):
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        if platform.system().lower() != 'windows':
            self.pkcs11.load('libbeidpkcs11.so')
        else:
            self.pkcs11.load('beidpkcs11.dll')

    def getInfo(self):
        print(self.pkcs11.getInfo())
        print('======================================================')
        print()

    def getTokenInfo(self,slot):
        print(self.pkcs11.getTokenInfo(slot))
        print('======================================================')
        print()

    def getData(self, slot, name):
        session = self.pkcs11.openSession(slot)
        o = session.findObjects([(CKA_CLASS, CKO_DATA), (CKA_LABEL, name)])[0]        
        value = session.getAttributeValue(o,[CKA_VALUE])[0]
        #print(value)
        text = bytes(value).decode('utf-8')
        print(text)


if __name__ == '__main__':

    beid = getData()
    beid.getInfo()

    slots = beid.pkcs11.getSlotList(tokenPresent=True)

    if len(slots) == 0:
        print("Token not found.")
        sys.exit(2)

    for slot in slots:
        try:
            beid.getTokenInfo(slot)
            beid.getData(slot, 'surname')
            beid.getData(slot, 'firstnames')
        except PyKCS11.PyKCS11Error as e:
            print("Error:", e)
