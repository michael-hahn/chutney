import sys
import argparse

import stem
import stem.connection
from stem.control import Controller
from stem import CircStatus


def take_ctrl(cport):
    """Connect with Tor's control socket to take control of a tor node.
       Returns a controller for future use. User must close the controller
       when finished by calling controller.close() """
    try:
        controller = Controller.from_port(port=cport)
    except stem.SocketError as exc:
        print("Unable to connect to a Tor node from port {}: {}".format(port,exc))
        sys.exit(1)

    try:
        controller.authenticate()
    except stem.connection.MissingPassword:
        print("Controller should never be password protected for simplicity.")
        sys.exit(1)
    except stem.connection.AuthenticationFailure as exc:
        print("Unable to authenticate the controller: {}".format(exc))
        sys.exit(1)

    print("This Tor node is running version {} at pid {}".format(controller.get_version(), controller.get_pid()))
    print("Taking control of the Tor node...successful")
    return controller


def get_circuit(controller):
    """Get information about the circuit Tor currently has available"""

    for circ in sorted(controller.get_circuits()):
        if circ.status != CircStatus.BUILT:
            continue

        print("")
        print("Circuit {} ({})".format(circ.id, circ.purpose))

        for i, entry in enumerate(circ.path):
            div = '+' if (i == len(circ.path) - 1) else '|'
            fingerprint, nickname = entry

            desc = controller.get_network_status(fingerprint, None)
            address = desc.address if desc else 'unknown'

            print(" %s- %s (%s, %s)" % (div, fingerprint, nickname, address))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cport", type=int, default=8008, help="Tor control listener's port number")
    options = parser.parse_args()

    controller = take_ctrl(options.cport)
    get_circuit(controller)

    controller.close()
