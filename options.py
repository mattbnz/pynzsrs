#------------------------------------------------------------------------------
# Copyright 2012 Matt Brown <matt@mattb.net.nz>
#
# pynzsrs is free software; you can redistribute it and/or modify it under the
# terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# pynzsrs is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# pynzsrs; if not, write to the Free Software Foundation, Inc., 59 Temple
# Place, Suite 330, Boston, MA 02111-1307  USA
#------------------------------------------------------------------------------
import getopt
import json
import os
import sys

class SRSOptions(object):
    """Encapsulates configuration data for the SRSClient.

    This class looks for options configuration data in three
    places:
    1) The ~/.rikrc file.
    2) Environment variables.
    3) Command-line flags provided to the constructor.

    If an option is specified in multiple locations the following
    rules are used. Command-line options beat environment
    variables, and environment variables beat options found in the
    ~/.rikrc file
    """
    CONFIG_PATH = os.path.expanduser('~/.rikrc')
    DEFAULT_CONFIG = {
            'registrar_id': 999,
            'debug': 0,
            'timeout': 180,
            'url': 'srstest.srs.net.nz/srs/registrar',
    }
    ENV_VARS = {
            'SRS_URL': 'url',
            'SRS_REGISTRAR': 'registrar_id',
            'DEBUG': 'debug',
            'GNUPGID': 'gpg_id',
            'SRS_RIK_PASSPHRASE': 'gpg_passphrase',
            'SRS_RIK_PASSPHRASE_FILE': 'gpg_passphrase_file',
    }
    SHORT_OPTS = 'df:hr:t:'
    LONG_OPTS = [
            'registrar_id=', 'file=', 'debug', 'help', 'url=', 'timeout=',
            'gpg_id=', 'gpg_secret=', 'gpg_public=', 'gpg_passphrase=',
            'gpg_passphrase_file=', 'srs_ca=']

    def __init__(self, argv):
        self._options = {}
        self._options.update(self._ReadConfig())
        self._options.update(self._ReadEnvironment())
        self._options.update(self._ReadCommandline(argv))
    
    def __getattr__(self, name):
        if name in self._options:
            return self._options[name]
        raise AttributeError

    def _ReadConfig(self):
        # For compatibility with the standard RIK, create a default
        # config file if there isn't one already.
        if not os.path.exists(self.CONFIG_PATH):
            self._CreateConfig()
    
        with open(self.CONFIG_PATH, 'r') as fp:
            return json.loads(fp.read())

    def _CreateConfig(self):
        with open(self.CONFIG_PATH, 'w') as fp:
            json.dump(self.DEFAULT_CONFIG, fp, indent=4)


    def _ReadEnvironment(self):
        options = {}
        for env_key, opt_key in self.ENV_VARS.iteritems():
            if env_key in os.environ:
                options[opt_key] = os.environ[env_key]
        return options

    def _ReadCommandline(self, argv):
        options = {}
        optlist, args = getopt.getopt(argv,
                self.SHORT_OPTS, self.LONG_OPTS)
        for opt, val in optlist:
            if opt in ('--registrar_id', '-r'):
                options['registar_id'] = val
            elif opt in ('--file', '-f'):
                options['file'] = val
            elif opt in ('--debug', '-d'):
                options['debug'] = 1
            elif opt in ('--help', '-h'):
                options['help'] = 1
            elif opt in ('--timeout', '-t'):
                options['timeout'] = int(val)
            else:
                options[opt.lstrip('-')] = val
        return options
