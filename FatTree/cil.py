def do_iperfmulti( self, line ):
    """Multi iperf UDP test between nodes"""
    args = line.split()
    if len(args) == 1:
        udpBw = args[ 0 ]
        self.mn.iperfMulti(udpBw)
    elif len(args) == 2:
        udpBw = args[ 0 ]
        period = args[ 1 ]
        err = False
        self.mn.iperfMulti(udpBw, float(period))
    else:
        error('invalid number of args: iperfmulti udpBw \n' +
               'udpBw examples: 1M\n')