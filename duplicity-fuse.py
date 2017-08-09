#!/usr/bin/python2
# duplicity-fuse.py
#  mount duplicity backup as a user-space filesystem (fuse)
#
# Original written by Peter Gruber, changes to make work with
# more recent Python versions & Duplicity made by Jose Riha <jose1711 gmail com>
#
# Copyright (C) 2008 Peter Gruber <nokos@gmx.net>
#
# This file is in part based on code of duplicity by.
# Ben Escoto <bescoto@stanford.edu>
#
# This is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 3 of the License, or (at your
# option) any later version.
#
# This is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this; if not, write to the Free Software Foundation,
# Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

import os
import stat
import errno
import sys
import getpass
import gzip
import time
import types
from duplicity import collections, commandline, diffdir, dup_temp, dup_time, file_naming, globals, gpg, log, manifest, patchdir, path, robust, tempdir
from xml.etree.cElementTree import Element, SubElement, QName
from datetime import datetime
from getopt import getopt, GetoptError
from time import mktime
import fuse
from fuse import Fuse
import string

filename_tdp = {}

if not hasattr(fuse, '__version__'):
    raise RuntimeError("your fuse-py doesn't know of fuse.__version__, probably it's too old.")

fuse.fuse_python_api = (0, 2)


def pathencode(s):
    return str(s.__hash__())


def date2num(ff):
    return mktime(ff.timetuple())+1e-6*ff.microsecond


def date2str(ff):
    return ff.strftime("%Y%m%d%H%M%S")


class DuplicityStat(fuse.Stat):
    def __init__(self):
        self.st_mode = 0
        self.st_ino = 0
        self.st_dev = 0
        self.st_nlink = 0
        self.st_uid = 0
        self.st_gid = 0
        self.st_size = 0
        self.st_atime = 0
        self.st_mtime = 0
        self.st_ctime = 0


class DuplicityFS(Fuse):
    options = ["file-to-restore", "archive-dir", "encrypt-key", "num-retries",
               "scp-command", "sftp-command", "sign-key", "timeout", "volsize",
               "verbosity", "gpg-options", "ssh-options"]
    no_options = ["allow-source-mismatch", "force", "ftp-passive",
                  "ftp-regular", "no-encryption",
                  "no-print-statistics", "null-separator",
                  "short-filenames"]
    url = None
    passphrasefd = None
    passwordfd = None
    filecache = {}
    col_stats = None
    dates = []
    dircache = {}

    def readdir(self, path, offset):
        log.Log("readdir "+path, 5)
        if path == '/':
            for r in self.dircache.keys():
                yield fuse.Direntry(r)
        else:
            p = path[1:].split(os.path.sep)
            if self.dircache[p[0]] is None:
                signature_chain = self.col_stats.matched_chain_pair[0]
                for s in range(1, len(self.dates)+1):
                    d = self.dates[s-1]
                    ds = date2str(d)
                    if ds in p[0]:
                        ds = p[0]
                        self.dircache[ds] = getfiletree(ds, signature_chain.get_fileobjs()[0:s])
                        break
            e = findpath(self.dircache[p[0]], p[1:])
            n = [".", ".."] + [x.get("name") for x in e.getchildren()]
            for r in n:
                yield fuse.Direntry(r)

    def getattr(self, path):
        log.Log("getattr "+path, 5)
        st = DuplicityStat()
        p = path[1:].split(os.path.sep)
        if path == '/':
            st.st_mode = stat.S_IFDIR | 0755
            st.st_nlink = 1+len(self.dircache.keys())
            return st
        if len(p) == 1:
            if not self.dircache.has_key(p[0]):
                return -errno.ENOENT
            st.st_mode = stat.S_IFDIR | 0755
            st.st_nlink = 2
            return st
        if self.dircache[p[0]] is None:
            signature_chain = self.col_stats.matched_chain_pair[0]
            for s in range(1, len(self.dates)+1):
                d = self.dates[s-1]
                ds = date2str(d)
                if ds == p[0]:
                    self.dircache[ds] = getfiletree(ds, signature_chain.get_fileobjs()[0:s])
                    break
        e = findpath(self.dircache[p[0]], p[1:])
        if e is None:
            return -errno.ENOENT
        mode = int((3 * '{:b}').format(*[int(x) for x in e.get("perm").split()[-1]]), base=2)
        if e.get("type") == 'dir':
            st.st_mode = stat.S_IFDIR | mode
        else:
            st.st_mode = stat.S_IFREG | mode
        if e.get("size") < 0:  # need to read size from filearch? not in signature?
            ds = filter(lambda x: date2str(x) in p[0], self.dates)
            files = restore_get_patched_rop_iter(self.col_stats, date2num(ds[0]))
            np = apply(os.path.join, p[1:])
            for x in files:
                lp = x.get_relative_path()
                log.Log("looking at %s,%s"%(lp, np), 5)
                le = findpath(self.dircache[p[0]], lp.split(os.path.sep))
                if le is None:
                    log.Log("not found: "+str(le), 5)
                    continue
                if le.get("size") < 0:
                    le.set("size", x.getsize())
                if lp == np:
                    log.Log("found", 5)
                    break
        st.st_size = e.get("size")
        st.st_uid = e.get("uid")
        st.st_gid = e.get("gid")
        st.st_mtime = e.get("mtime")
        st.st_nlink = 1+len(e.getchildren())
        return st

    def open(self, path, flags):
        p = path[1:].split(os.path.sep)
        if path == '/' or len(p) == 1:
            return -errno.ENOENT
        e = findpath(self.dircache[p[0]], p[1:])
        if e is None or e.get("type") == 'dir':
            return -errno.ENOENT
        if flags & os.O_RDWR:
            return -errno.ENOENT
        if flags & os.O_WRONLY:
            return -errno.ENOENT
        return 0

    def read(self, path, size, offset):
        p = path[1:].split(os.path.sep)
        if path == '/' or len(p) == 1:
            return ''
        e = findpath(self.dircache[p[0]], p[1:])
        if e is None or e.get("type") == 'dir':
            return ''
        if self.filecache.has_key(path):
            dat = self.filecache[path]
            return dat[offset:(offset+size)]
        ds = filter(lambda x: date2str(x) in p[0], self.dates)
        self.col_stats = collections.CollectionsStatus(globals.backend, globals.archive_dir).set_values()
        files = restore_get_patched_rop_iter(self.col_stats, date2num(ds[0]))
        np = apply(os.path.join, p[1:])
        dat = None
        s = 0
        while True:
            try:
                f = files.next()
            except StopIteration:
                break
            if f.get_relative_path() == np:
                dat = f.get_data()
                s = f.getsize()
        if dat is not None:
            offset = min(s-1, offset)
            size = min(s-offset, size)
            self.filecache[path] = dat
            return dat[offset:(offset+size)]
        return ''

    def runduplicity(self):
        if self.url is None:
            return
        if self.passphrasefd:
            self.passphrasefd = int(self.passphrasefd)
        if self.passwordfd:
            self.passwordfd = int(self.passwordfd)
        if self.url.find("file:/") != 0:
            get_backendpassphrase(self.passwordfd)
        opts = []
        for i in self.options:
            try:
                v = eval("self."+i.replace("-", ""))
                if v:
                    opts.append("--%s=%s" % (i, v))
            except:
                pass
        for i in self.no_options:
            try:
                v = eval("self."+i.replace("-", ""))
                if v:
                    opts.append("--%s" % (i))
            except:
                pass
        self.options = []
        log.setup()
        # uncomment for debugging
        # log.setverbosity(9)
        commandline.ProcessCommandLine(["list-current-files", "--ssh-askpass"] + opts + [self.url])
        globals.gpg_profile.passphrase = get_passphrase(self.passphrasefd)
        self.col_stats = collections.CollectionsStatus(globals.backend, globals.archive_dir).set_values()
        self.dates = reduce(lambda x, y: x+y, [[datetime.fromtimestamp(b.get_time()) for b in a.get_all_sets()] for a in self.col_stats.all_backup_chains], [])
        self.types = reduce(lambda x, y: x+y, [[b.type for b in a.get_all_sets()] for a in self.col_stats.all_backup_chains], [])
        for s in range(1, len(self.dates)+1):
            signature_chain = self.col_stats.matched_chain_pair[0]
            d = self.dates[s-1]
            ds = date2str(d) + '_' + self.types[s-1]
            self.dircache[ds] = None


def findpath(root, path):
    if len(path) == 0:
        return root
    c = path[0]
    ec = pathencode(c)
    s = root.find(ec)
    if s is None:
        log.Log("node "+c+"("+ec+") in "+str(root)+" not found", 5)
        return None
    if len(path) == 1:
        log.Log("node "+c+"("+ec+") in "+str(root)+" found", 5)
        return s
    log.Log("search "+path[1]+" in "+c+"("+ec+") in "+str(root), 5)
    return findpath(s, path[1:])


def getfiletree(name, w):
    root = Element(name)
    for f in diffdir.get_combined_path_iter(w):
        if f.difftype == 'deleted':
            continue
        s = f.stat
        uid, gid, mtime, size = 0, 0, 0, 0
        if s:
            uid, gid, mtime, size = s.st_uid, s.st_gid, s.st_mtime, s.st_size
        t = f.get_relative_path()
        if t == '.':
            continue
        if t[0:2] == './':
            t = t[2:]
        addtotree(root,t.split(os.path.sep),f.getperms(),size,mtime,uid,gid,f.type)
    return root


def get_passphrase(fd=None):
    """Get passphrase from environment or, failing that, from user"""
    try: return os.environ['PASSPHRASE']
    except KeyError: pass
    log.Log("PASSPHRASE variable not set, asking user.", 4)
    while 1:
        if not fd:
            pass1 = getpass.getpass("GnuPG passphrase: ")
        else:
            pass1 = os.fdopen(fd).read()
        if not pass1 and not globals.gpg_profile.recipients:
            print "Cannot use empty passphrase with symmetric encryption!  Please try again."
            continue
        os.environ['PASSPHRASE'] = pass1
        return pass1

def get_backendpassphrase(fd=None):
    """Get passphrase from environment or, failing that, from user"""
    try: return os.environ['FTP_PASSWORD']
    except KeyError: pass
    log.Log("FTP_PASSWORD variable not set, asking user.", 4)
    while 1:
        if not fd:
            pass1 = getpass.getpass("Backend passphrase: ")
        else:
            pass1 = os.fdopen(fd).read()
        if not pass1:
            print "Need Backend passphrase!  Please try again."
            continue
        os.environ['FTP_PASSWORD'] = pass1
        return pass1


def restore_get_patched_rop_iter(col_stats, time):
    """Return iterator of patched ROPaths of desired restore data"""
    index = ()
    backup_chain = col_stats.get_backup_chain_at_time(time)
    assert backup_chain, col_stats.all_backup_chains
    backup_setlist = backup_chain.get_sets_at_time(time)

    def get_fileobj_iter(backup_set):
        """Get file object iterator from backup_set contain given index"""
        manifest = backup_set.get_manifest()
        for vol_num in manifest.get_containing_volumes(index):
            a = restore_get_enc_fileobj(backup_set.backend,
                                        backup_set.volume_name_dict[vol_num],
                                        manifest.volume_info_dict[vol_num])
            if a:
                yield a
    fileobj_iters = (get_fileobj_iter(x) for x in backup_setlist)
    tarfiles = (patchdir.TarFile_FromFileobjs(x) for x in fileobj_iters)
    log.Log("looking through: "+str(tarfiles),5)
    return patchdir.tarfiles2rop_iter(tarfiles, index)

def restore_get_enc_fileobj(backend, filename, volume_info):
    """Return plaintext fileobj from encrypted filename on backend """
    parseresults = file_naming.parse(filename)
    if filename in filename_tdp:
        tdp = filename_tdp[filename]
    else:
        tdp = dup_temp.new_tempduppath(parseresults)
        filename_tdp[filename] = tdp

    backend.get(filename, tdp)
    if not restore_check_hash(volume_info, tdp):
        return None
    fileobj = tdp.filtered_open_with_delete("rb")
    if parseresults.encrypted and globals.gpg_profile.sign_key:
        restore_add_sig_check(fileobj)
    return fileobj

def restore_check_hash(volume_info, vol_path):
    """Check the hash of vol_path path against data in volume_info"""
    global filename_tdp
    hash_pair = volume_info.get_best_hash()
    if hash_pair:
        calculated_hash = gpg.get_hash(hash_pair[0], vol_path)
        if calculated_hash != hash_pair[1]:
            log.Log("Invalid data - %s hash mismatch:\n"
                           "Calculated hash: %s\n" "Manifest hash: %s\n" %
                           (hash_pair[0], calculated_hash, hash_pair[1]),1)
            return False
    return True

def restore_add_sig_check(fileobj):
    """Require signature when closing fileobj matches sig in gpg_profile"""
    assert (isinstance(fileobj, dup_temp.FileobjHooked) and
            isinstance(fileobj.fileobj, gpg.GPGFile)), fileobj
    def check_signature():
        """Thunk run when closing volume file"""
        actual_sig = fileobj.fileobj.get_signature()
        if actual_sig != globals.gpg_profile.sign_key:
            log.FatalError("Volume was not signed by key %s, not %s" %
                           (actual_sig, globals.gpg_profile.sign_key))
    fileobj.addhook(check_signature)

def addtotree(root,path,perm,size,mtime,uid,gid,type):
    if len(path) == 1:
        c = path[0]
        ec = pathencode(c)
        e = None
        for f in root.getchildren():
            if f.tag == ec:
                e = f
                break
        if e is None:
            e = SubElement(root,ec)
            log.Log("add "+c+"("+ec+") to "+str(root),5)
        else:
            log.Log("found "+c+"("+ec+") in "+str(root),5)
        e.set("perm",perm)
        e.set("size",-1)
        e.set("mtime",mtime)
        e.set("uid",uid)
        e.set("gid",gid)
        e.set("type",type)
        e.set("name",c)
    else:
        c = path[0]
        ec = pathencode(c)
        for f in root.getchildren():
            if f.tag == ec:
                log.Log("adding to "+c+"("+ec+") in "+str(root),5)
                addtotree(f,path[1:],perm,size,mtime,uid,gid,type)
                return
        f = SubElement(root,ec)
        log.Log("new "+c+"("+ec+") in "+str(root),5)
        addtotree(f,path[1:],perm,size,mtime,uid,gid,type)

def main():
    usage="""
Userspace duplicity filesystem

""" + Fuse.fusage

    server = DuplicityFS(version="%prog " + fuse.__version__,
                     usage=usage,
                     dash_s_do='setsingle')
    server.parser.add_option(mountopt="url", metavar="PATH", default='scp://localhost/',
                             help="backup url [default: %default]")
    server.parser.add_option(mountopt="passwordfd", metavar="NUM",
                             help="filedescriptor for the password")
    server.parser.add_option(mountopt="passphrasefd", metavar="NUM",
                             help="filedescriptor for the passphrase")
    for n in server.options:
        server.parser.add_option(mountopt=n.replace("-",""), metavar="STRING",
                                 help=n+" option from duplicity")
    for n in server.no_options:
        server.parser.add_option(mountopt=n.replace("-",""),
                                 help=n+" option from duplicity")
    # uncomment for debugging
    # server.fuse_args.setmod('foreground')

    server.parse(values=server, errex=1)
    try:
        if server.fuse_args.mount_expected():
            server.runduplicity()
    except OSError:
        print >> sys.stderr, "can't enter root of underlying filesystem"
        sys.exit(1)

    server.main()


if __name__ == '__main__':
    main()
