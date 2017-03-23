#!/usr/bin/env python3
import gi
import logging
import logging.handlers
import re
from subprocess import PIPE, Popen
from os import environ
from sys import argv
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk

# Constants
LOGIN_PROMPT = "Login"
PASSWD_PROMPT = "Password"
DOMAIN_PROMPT = "Domain"
ENCODING = 'utf-8'
MAX_INPUT_LEN = 64
RDP_HOST = "10.1.97.200"
DOMAINS = ('pso.local', 'demo.loc', 'OSIC')
APPNAME = 'iexplore'
XFREERDP_OPTIONS = ('/cert-ignore', '+clipboard', '+home-drive', '-themes', '-wallpaper')


oLog = logging.getLogger("xrdp_start")


# Helper functions
def startRDP(o_cfg):
    oLog.debug(o_cfg.auth)
    # password on stdin
    # https://github.com/FreeRDP/FreeRDP/issues/1358,
    # bmiklautz commented on Dec 4, 2014
    arguments = ['/usr/bin/xfreerdp']
    arguments += list(XFREERDP_OPTIONS)
    arguments.append('/u:{}'.format(o_cfg.auth.login))
    arguments.append('/d:{}'.format(o_cfg.auth.domain))
    arguments.append('/v:{}'.format(o_cfg.host))
    arguments.append('/app:||{}'.format(o_cfg.app))
    # password on standard input?
    arguments.append('+from-stdin')
    # run the program
    oLog.debug(arguments)
    oPass = Popen(arguments, stdin=PIPE, stdout=None, stderr=None,
                  shell=False, universal_newlines=True)
    # feed the password to STDIN of xfreerdp
    oPass.communicate(o_cfg.auth.password + "\n")
    return


class LoginInfo:
    dInfo = {}

    @property
    def login(self):
        return self.dInfo.get('login', '')

    @login.setter
    def login(self, x):
        self.dInfo['login'] = x

    @property
    def password(self):
        return self.dInfo.get('password', '')

    @password.setter
    def password(self, x):
        self.dInfo['password'] = x

    @property
    def domain(self):
        return self.dInfo.get('domain', '')

    @domain.setter
    def domain(self, x):
        self.dInfo['domain'] = x

    @property
    def is_filled(self):
        return (('login' in self.dInfo)
                and ('password' in self.dInfo)
                and ('domain' in self.dInfo))

    def __repr__(self):
        return ("Login: {0}, password {1}, domain {2}".format(self.login,
                                                              self.password,
                                                              self.domain))


class ButtonWindow(Gtk.Window):
    def __init__(self, o_config):
        self.authInfo = o_config.auth
        Gtk.Window.__init__(self, title="Please authenticate")
        self.set_border_width(10)

        # Input fields
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.add(vbox)
        # login field
        login_hbx = Gtk.Box(spacing=6)
        vbox.add(login_hbx)
        login_hbx.pack_start(Gtk.Label(LOGIN_PROMPT), True, True, 0)
        self.login_entry = Gtk.Entry()
        self.login_entry.set_max_length(MAX_INPUT_LEN)
        login_hbx.pack_start(self.login_entry, True, True, 0)

        # password field
        passwd_hbx = Gtk.Box(spacing=6)
        passwd_hbx.pack_start(Gtk.Label(PASSWD_PROMPT), True, True, 0)
        self.passwd_entry = Gtk.Entry()
        self.passwd_entry.set_max_length(MAX_INPUT_LEN)
        self.passwd_entry.set_visibility(False)
        passwd_hbx.pack_start(self.passwd_entry, True, True, 0)
        self.passwd_visible = Gtk.CheckButton("View")
        self.passwd_visible.connect("toggled", self.on_visible_toggled)
        passwd_hbx.pack_start(self.passwd_visible, True, True, 0)
        vbox.add(passwd_hbx)

        # domains list as ComboBoxText w/o user input
        domains_hbx = Gtk.Box(spacing=6)
        domains_hbx.pack_start(Gtk.Label(DOMAIN_PROMPT), True, True, 0)
        domain_combo = Gtk.ComboBoxText()
        domain_combo.set_entry_text_column(0)
        domain_combo.connect("changed", self.on_domain_combo_changed)
        for dom in o_config.ls_domains:
            domain_combo.append_text(dom)
        domains_hbx.pack_start(domain_combo, True, True, 0)

        vbox.add(domains_hbx)

        # login/cancel buttons
        hbox = Gtk.Box(spacing=6)
        vbox.add(hbox)
        button = Gtk.Button.new_with_label("Login")
        button.connect("clicked", self.on_login_clicked)
        hbox.pack_start(button, True, True, 0)

        button = Gtk.Button.new_with_mnemonic("_Cancel")
        button.connect("clicked", self.on_close_clicked)
        hbox.pack_start(button, True, True, 0)
        return

    def on_login_clicked(self, button):
        oLog.debug('"Login" button was clicked')
        self.authInfo.login = self.login_entry.get_text()
        self.authInfo.password = self.passwd_entry.get_text()
        # flush GTK events queue
        while Gtk.events_pending():
            Gtk.main_iteration()
        Gtk.main_quit()
        self.destroy()

    def on_domain_combo_changed(self, combo):
        oLog.debug("Domain changed to {}".format(combo.get_active_text()))
        self.authInfo.domain = combo.get_active_text()
        return

    def on_close_clicked(self, button):
        oLog.debug("Closing application")
        while Gtk.events_pending():
            Gtk.main_iteration()
        Gtk.main_quit()

    def on_button_toggled(self, button, name):
        if button.get_active():
            self.authInfo.domain = name
        else:
            pass

    def on_visible_toggled(self, button):
        self.passwd_entry.set_visibility(button.get_active())
        return


class ConfigInfo:
    """Configuration for this program"""
    def __init__(self, o_logObject):
        self.o_auth = LoginInfo()
        self.ls_domains = DOMAINS
        self.b_dryrun = False
        self.s_appName = 'iexplore'
        self.s_hostName = "127.0.0.1"
        self.b_exposeHomeDir = False    # True
        self.b_exposeMedia = False      # True
        self.c_mediaMountPath = '/run/media/' + environ['LOGNAME']
        if 'DOMAINS' in environ:
            self.ls_domains = environ['DOMAINS'].split(':')
        if 'LOGFILE' in environ:
            self.s_logFile = environ['LOGFILE']
            self.setupLog(o_logObject)
        else:
            self.s_logFile = ''
        # do we have any CLI arguments?
        if len(argv) > 1:        # process CLI args
            self.checkVersion(argv)
            self.setupApp(argv)
            self.setupHost(argv)
        return

    def checkVersion(self, argv):
        re_Vers = re.compile('^--ver')
        for s_item in argv:
            o_match = re_Vers.match(s_item)
            if o_match:
                oLog.debug("checkVersion: match found: {0}".format(s_item))
                self.b_dryrun = True
                break

    def setupLog(self, o_log):
        if self.s_logFile:
            o_log.setLevel(logging.DEBUG)
            o_logFormat = logging.Formatter(
                    r'%(asctime)s: %(name)s - %(levelname)s - %(message)s'
                    )
            o_logFile = logging.handlers.RotatingFileHandler(
                    filename=environ['LOGFILE'], maxBytes=1024*1024, 
                    backupCount=3)
            o_logFile.setFormatter(o_logFormat)
            o_log.addHandler(o_logFile)

    def setupApp(self, argv):
        re_App = re.compile(r'^/app:\|\|(.*)$')
        """get application name from ARGV array and store it in the variable"""
        self.s_appName = APPNAME    # default
        for s_item in argv:
            # try CLI arguments until '/app' is found or end of list is reached
            o_match = re_App.match(s_item)
            if o_match:
                oLog.debug("setupApp: match found: {0}, app is {1}".format(
                    s_item, o_match.group(1)))
                self.s_appName = o_match.group(1)
                break
        return

    def setupHost(self, argv):
        re_Host = re.compile(r'^/v:(.*)$')
        self.s_hostName = RDP_HOST
        for s_item in argv:
            o_match = re_Host.match(s_item)
            if o_match:
                oLog.debug('setupHost: match found: {0}, host name/IP is {1}'.format(s_item, o_match.group(1)))
                self.s_hostName = o_match.group(1)
                break
        return

    @property
    def auth(self):
        return self.o_auth

    @property
    def host(self):
        return self.s_hostName

    @property
    def app(self):
        return self.s_appName


if __name__ == "__main__":
    # logging setup
    o_cfg = ConfigInfo(oLog)
    if not o_cfg.b_dryrun:
        win = ButtonWindow(o_cfg)
        win.connect("delete-event", Gtk.main_quit)
        win.show_all()
        Gtk.main()
        oLog.debug("Time to launch program")
        oLog.debug(str(o_cfg.auth))
        if o_cfg.o_auth.is_filled:
            startRDP(o_cfg)
    else:
        print('FreeRDP version 1.1.0 (fake)')
    exit()
