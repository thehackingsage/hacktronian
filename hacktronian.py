import Setup.setup as setup
import modules.controller as controller
import sys

intro = controller.Directory(setup.directories[0],0)
attack = controller.Attack(dire=intro)
session = controller.Router(dire=intro, directories=setup.directories, links=setup.links, attack=attack)
try:
    session.start()
except KeyboardInterrupt:
    print('\nExiting...')
    sys.exit(0)
