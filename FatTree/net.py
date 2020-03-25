def iperf_single( self,hosts=None, udpBw='10M', period=5, port=5001):
        """Run iperf between two hosts using UDP.
           hosts: list of hosts; if None, uses opposite hosts
           returns: results two-element array of server and client speeds"""
        if not hosts:
            return
        else:
            assert len( hosts ) == 2
        client, server = hosts
        filename = client.name[1:] + '.out'
        output( '*** Iperf: testing bandwidth between ' )
        output( "%s and %s\n" % ( client.name, server.name ) )
        iperfArgs = 'iperf -u '
        bwArgs = '-b ' + udpBw + ' '
        print "***start server***"
        server.cmd( iperfArgs + '-s' + ' > /home/muzi/log/' + filename + '&')
        print "***start client***"
        client.cmd(
            iperfArgs + '-t '+ str(period) + ' -c ' + server.IP() + ' ' + bwArgs
            +' > /home/muzi/log/' + 'client' + filename +'&')
 
def iperfMulti(self, bw, period=5):
    base_port = 5001
    server_list = []
    client_list = [h for h in self.hosts]
    host_list = []
    host_list = [h for h in self.hosts]
 
    cli_outs = []
    ser_outs = []
 
    _len = len(host_list)
    for i in xrange(0, _len):
        client = host_list[i]
        server = client
        while( server == client ):
            server = random.choice(host_list) 
        server_list.append(server)
        self.iperf_single(hosts = [client, server], udpBw=bw, period= period, port=base_port)
        sleep(.05)
        base_port += 1
    self.hosts[0].cmd('ping -c10'+ self.hosts[-1].IP() + ' > /home/muzi/log/delay.out')
    sleep(period)