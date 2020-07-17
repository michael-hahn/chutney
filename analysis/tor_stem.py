import sys
import argparse
import time
import socks
import socket
import urllib3
import datetime
from urllib3.contrib.socks import SOCKSProxyManager

import stem
import stem.connection
from stem.control import Controller
from stem import CircStatus
from stem import Signal


def take_ctrl(cport):
    """Connect with Tor's control socket to take control of a tor node.
       Returns a controller for future use. User must close the controller
       when finished by calling controller.close() """
    try:
        controller = Controller.from_port(port=cport)
    except stem.SocketError as exc:
        print("Unable to connect to a Tor node from port {}: {}".format(cport,exc))
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


def set_conf(controller):
    """Reset some configurations of Tor client node through its @controller
       See https://medium.com/@iphelix/hacking-the-tor-control-protocol-fb844db6a606 """
    try:
	controller.set_options({
		# disable preemptively creating circuits
		"__DisablePredictedCircuits": "1",
		# do not allow more than 1 circuits to be pending at a time
		"MaxClientCircuitsPending": "1",
		# longer period before creating new circuit
		"NewCircuitPeriod": "60000",
		# longer period for circuit expiration
		"MaxCircuitDirtiness": "60000",
		# try for a long time when building circuits, do not give up on building the circuit
		# this is because circuit building can be very slow under libdft
		"LearnCircuitBuildTimeout": "0",
		"CircuitBuildTimeout": "60000",
		# try not to let Tor detach a stream from a circuit and try a new circuit
		"CircuitStreamTimeout": "60000"})
        print("The following configurations of the controller are modified:")
        print("{}".format(controller.get_conf_map(["__DisablePredictedCircuits", "MaxClientCircuitsPending", "NewCircuitPeriod", "MaxCircuitDirtiness", "LearnCircuitBuildTimeout", "CircuitBuildTimeout", "CircuitStreamTimeout"])))
    except stem.ControllerError as ce:
        print("Set a configuration of a controller failed: {}".format(ce))
    except stem.InvalidArguments as ia:
        print("The configuration argument is invalid: {}".format(ia))
    #try:
    #    controller.signal(stem.Signal.HUP)
    #except stem.ControllerError as ce:
    #    print("Sending HUP to the controller failed: {}".format(ce))
    #except stem.InvalidArguments as ia:
    #    print("The configuration argument is invalid: {}".format(ia))


def get_circuit(controller):
    """Get information about the circuit Tor currently has available. """

    print("{} active circuits exist".format(len(controller.get_circuits())))
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


def close_all_circuit(controller):
    """Close all the circuits of a available from a client node. """
    
    for circ in sorted(controller.get_circuits()):
        try:
            print("Closing circuit {}".format(circ.id))
            controller.close_circuit(circ.id)
        except stem.InvalidArguments as exc:
            print("Cannot close circuit {}: {}".format(circ.id, exc))
    print("Closing all circuits...done")


def new_general_circuit(controller):
    """Create a new circuit with 'general' as its purpose. 
       For our purpose the circuit has one relay node, test009r and one exit node, test008r. """
    try:
        circuit_id = controller.new_circuit(path=["test009r", "test008r"], purpose='general', await_build=True)
        print("Built a new controller circuit: {}".format(circuit_id))
    except stem.ControllerError as exc:
        print("Error building a new general circuit: {}".format(exc))
        return None
    return circuit_id


def scan(controller, sport):
    circuit_id = new_general_circuit(controller)

    def attach_stream(stream):
        if stream.status == 'NEW':
            controller.attach_stream(stream.id, circuit_id)
            print("Stream ID: {} attached to circuit {}".format(stream.id, circuit_id))

    controller.add_event_listener(attach_stream, stem.control.EventType.STREAM)

    try:
        controller.set_conf('__LeaveStreamsUnattached', '1')  # leave stream management to us
        start_time = time.time()

        check_page = query('http://www.google.com/', sport)

        #if 'Congratulations. This browser is configured to use Tor.' not in check_page:
        #    raise ValueError("Request didn't have the right content")

        return time.time() - start_time
    finally:
        controller.remove_event_listener(attach_stream)
        controller.reset_conf('__LeaveStreamsUnattached')


def query(url, sport):
    """Uses urllib3 to fetch a site using the proxy on the @sport. """
    proxy = SOCKSProxyManager('socks5://localhost:{}/'.format(sport))
    r = proxy.request('GET', url)
    return r.data


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cport", type=int, default=8004, help="Tor control listener's port number")
    parser.add_argument("--sport", type=int, default=9004, help="Tor socks listener's port number")
    options = parser.parse_args()

    controller = take_ctrl(options.cport)
    # close_all_circuit(controller)
    set_conf(controller)
    # scan(controller, options.sport)
    new_general_circuit(controller)
    get_circuit(controller)

    controller.close()
