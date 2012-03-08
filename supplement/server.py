import sys
import os.path
import optparse
import logging

logger = logging.getLogger('supplement')

try:
    from cPickle import loads, dumps
except ImportError:
    from pickle import loads, dumps

try:
    import supplement
except ImportError:
    fname = os.__file__
    if fname.endswith('.pyc'):
        fname = fname[:-1]

    if not os.path.islink(fname):
        raise

    real_prefix = os.path.dirname(os.path.realpath(fname))
    site_packages = os.path.join(real_prefix, 'site-packages')
    old_path = sys.path
    sys.path = old_path + [site_packages]
    try:
        import supplement
    finally:
        sys.path = old_path

from supplement.project import Project
from supplement.assistant import assist, get_location, get_docstring, get_fixed_source
from supplement.scope import get_scope_at
from supplement.watcher import get_monitor
from supplement.fixer import sanitize_encoding
from supplement.linter import lint, check_syntax

class Server(object):
    def __init__(self, conn):
        self.conn = conn
        self.projects = {}
        self.configs = {}
        self.monitor = get_monitor()
        self.monitor.start()

    def configure_project(self, path, config):
        self.configs[path] = config
        self.projects[path] = self.create_project(path)

    def create_project(self, path):
        config = self.configs.get(path, {})
        config.setdefault('hooks', []).insert(0, 'supplement.hooks.override')
        p = Project(path, self.configs.get(path, {}), monitor=self.monitor)
        return p

    def get_project(self, path):
        try:
            return self.projects[path]
        except KeyError:
            pass

        p = self.projects[path] = self.create_project(path)
        return p

    def process(self, name, args, kwargs):
        try:
            is_ok = True
            result = getattr(self, name)(*args, **kwargs)
        except Exception as e:
            logger.exception(e)
            is_ok = False
            result = e.__class__.__name__, str(e)

        return result, is_ok

    def get_fixed_source(self, path, source, lineno):
        return get_fixed_source(self.get_project(path), source, lineno)

    def assist(self, path, source, position, filename):
        return assist(self.get_project(path), source, position, filename)

    def get_location(self, path, source, position, filename):
        return get_location(self.get_project(path), source, position, filename)

    def get_docstring(self, path, source, position, filename):
        return get_docstring(self.get_project(path), source, position, filename)

    def get_scope(self, path, source, lineno, filename, continous):
        return get_scope_at(
            self.get_project(path), sanitize_encoding(source), lineno,
                filename, continous=continous).fullname

    def lint(self, path, source, filename, syntax_only):
        return lint(source)

    def check_syntax(self, source):
        return check_syntax(source)

    def run(self):
        conn = self.conn
        while True:
            if conn.poll(1):
                try:
                    args = loads(conn.recv_bytes())
                except EOFError:
                    break
                except Exception:
                    import traceback
                    traceback.print_exc()
                    break

                if args[0] == 'close':
                    conn.close()
                    break
                else:
                    result, is_ok = self.process(*args)
                    try:
                        self.conn.send_bytes(dumps((result, is_ok), 2))
                    except:
                        import traceback
                        exc = traceback.format_exc()
                        logger.exception(exc)
                        
def main():
    import os
    from multiprocessing.connection import Listener
    usage = '''%prog [options] ADDRESS 
    
    where ADDRESS is the address where the server is listening.
    '''
    parser = optparse.OptionParser(usage)
    parser.add_option("-q", "--quiet", action="store_true", dest="quiet",
                      help="Do not print anything to the console.")
    parser.add_option("-l", "--logfile", action="store", type="string",
                      dest="logfile", default="", metavar="FILE",
                      help="log messages to FILE.")

    if 'SUPP_LOG_LEVEL' in os.environ:
        level = int(os.environ['SUPP_LOG_LEVEL'])
    else:
        level = logging.ERROR

    options, args = parser.parse_args()
    
    if len(args) != 1:
        parser.error("Incorrect number of arguments, expect exactly one address.")
    
    logger.setLevel(level)
    handler = logging.StreamHandler()
    if options.quiet:
        handler.setLevel(logging.CRITICAL)
    handler.setFormatter(logging.Formatter("%(name)s %(levelname)s: %(message)s"))
    logger.addHandler(handler)
    
    if len(options.logfile) > 0:
        handler = logging.FileHandler(options.logfile, mode='w')
        handler.setFormatter(logging.Formatter("%(name)s %(levelname)s: %(message)s"))
        logger.addHandler(handler)
        
    listener = Listener(args[0])
    conn = listener.accept()
    server = Server(conn)
    server.run()

if __name__ == '__main__':
    main()
