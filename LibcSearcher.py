#!/usr/bin/env python
import os
import sys
import subprocess


class LibcSearcher(object):
    def __init__(self, func=None, address=None, libc_choice=-1):
        self.condition = {}
        self.libc_choice = libc_choice
        self.symbols = {}
        self._address = 0
        self.db = ""
        self.libc_file = ""
        self.libc_database_path = os.path.join(os.path.realpath(os.path.dirname(__file__)), "libc-database/db/")
        self._onegadget = []
        if func is not None and address is not None:
            self.add_condition(func, address)
            self.decided()


    @property
    def sym(self):
        return self.symbols

    def add_condition(self, func, address):
        if not isinstance(func, str):
            print("The function should be a string")
            sys.exit()
        if not (isinstance(address, int) or isinstance(address, long)):
            print("The address should be an int number")
            sys.exit()
        self.condition[func] = address

    # Wrapper for libc-database's find shell script.
    def decided(self):
        if len(self.condition) == 0:
            print("No leaked info provided.")
            print("Please supply more info using add_condition(leaked_func, leaked_address).")
            sys.exit(0)

        db = self.libc_database_path
        files = []
        # only read "*.symbols" file to find
        for _, _, f in os.walk(db):
            for i in f:
                if i[-8:] == ".symbols":
                    files.append(i)
        result = []
        for ff in files:
            with open(db + ff, "rb") as fd:
                data = fd.read().decode(errors='ignore').split("\n")
                geteq = 0
                conLen = len(self.condition)
                for x in data:
                    t = x.split(' ')
                    if t[0] in self.condition:
                        if (self.condition[t[0]] & 0xFFF) == (int(t[1], 16) & 0xFFF):
                            geteq += 1
                            if geteq == conLen:
                                break
                        else:
                            break
                if geteq == conLen:
                    result.append(ff)

        if len(result) == 0:
            print("No matched libc, please add more libc or try others")
            sys.exit(0)

        if len(result) > 1:
            print("Multi Results:")
            for x in range(len(result)):
                print("%2d: %s" % (x, self.pmore(result[x])))
            print("Please supply more info using \n\tadd_condition(leaked_func, leaked_address).")
            while True:
                if self.libc_choice != -1:
                    in_id = self.libc_choice
                    self.libc_choice = -1
                else:
                    in_id = input(
                        "You can choose it by hand\nOr type 'exit' to quit:")
                    if in_id == "exit" or in_id == "quit":
                        sys.exit(0)
                try:
                    in_id = int(in_id)
                    self.db = result[in_id]
                    break
                except:
                    continue
        else:
            self.db = result[0]
        new_libc_file = self.libc_database_path + self.db[:-8] + ".so"
        if self.libc_file != "" and self.libc_file != new_libc_file:
            self._onegadget = []
            self.symbols.clear()
        self.libc_file = new_libc_file
        self.string_to_symbols()
        print("[+] %s be choosed." % self.pmore(self.db))

    def pmore(self, result):
        result = result[:-8]  # .strip(".symbols")
        with open(self.libc_database_path + result + ".info") as fd:
            info = fd.read().strip()
        return ("%s (id %s)" % (info, result))

    # "__libc_start_main_ret system dup2 read write str_bin_sh"
    def string_to_symbols(self):
        db = self.libc_database_path + self.db
        with open(db, "rb") as fd:
            data = fd.read().decode(errors='ignore').strip("\n").split("\n")
        for d in data:
            f = d.split(" ")[0]
            addr = d.split(" ")[1]
            self.symbols[f] = int(addr, 16)

        conItems = self.condition.items()
        if len(conItems) >= 1:
            self.address = conItems[0][1] - self.symbols[conItems[0][0]]

    # Wrapper for libc-database's dump shell script.
    def dump(self, func=None):
        if not self.db:
            self.decided()
        if func not in self.symbols:
            print("No matched, Make sure you supply a valid function name or just add more libc.")
            return 0
        return self.symbols[func] - self._address

    @property
    def address(self):
        return self._address

    @address.setter
    def address(self, new):
        delta = new - self._address
        update = lambda x: x + delta
        for f in self.symbols:
            self.symbols[f] += delta
        self._onegadget = [i + delta for i in self._onegadget]
        self._address = update(self.address)

    def calc_one_gadget(self):
        try:
            self._onegadget = [self._address + int(i) for i in subprocess.check_output(['one_gadget', '--raw', self.libc_file]).decode().split(' ')]
        except:
            pass

    @property
    def one_gadget(self):
        if not self.db:
            self.decided()
        if len(self._onegadget) == 0:
            self.calc_one_gadget()
        return self._onegadget


if __name__ == "__main__":
    obj = LibcSearcher("fgets", 0x7ff39014bd90, 1)
    print("[+]libc_base: " + hex(obj.address))
    #no libc_base
    print("[+]system  offset: " + hex(obj.dump("system")))
    #add libc_base
    print("[+]/bin/sh offset: " + hex(obj.sym["str_bin_sh"]))
    print("[+]one_gadget: " + str([hex(i) for i in obj.one_gadget]))
    print("[+]libc_file: " + obj.libc_file)


