from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel
import subprocess

class IntentSDNTopo(Topo):
    # function to build mininet topology
    def build(self):
        # create switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')

        # create hosts
        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
        h3 = self.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
        h4 = self.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')
        h5 = self.addHost('h5', ip='10.0.0.5/24', mac='00:00:00:00:00:05')
        h6 = self.addHost('h6', ip='10.0.0.6/24', mac='00:00:00:00:00:06')

        # link hosts to switches
        self.addLink(h1, s1)
        self.addLink(h2, s2)
        self.addLink(h3, s2)
        self.addLink(h4, s3)
        self.addLink(h5, s3)
        self.addLink(h6, s4)

        # add inter-switch links to be a triangle topology
        self.addLink(s1, s2)
        self.addLink(s3, s4)
        self.addLink(s2, s4)

    # function to start SDN controller
    def start_controller(self):
        print("Starting Ryu controller in a new xterm window")
        cmd = [
            "sudo",
            "xterm",
            "-hold",
            "-e",
            "ryu-manager",
            "controller/controller.py"
        ]
        self.controller_process = subprocess.Popen(cmd)
        print("Ryu controller started in xterm successfully")

# function to run mininet topology
def run():
    topo = IntentSDNTopo()
    topo.build()
    net = Mininet(
        topo=topo,
        controller=RemoteController('c1', ip='127.0.0.1', port=6653)
    )
    net.start()

    # start controller
    topo.start_controller()

    print("Network is up. Type 'exit' in the CLI to stop.")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()