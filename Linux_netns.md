# Create host namespaces
ip netns add h1
ip netns add h2
ip netns show
# Create links
ip link add h1-eth0 type veth peer name s1-eth1
ip link add h2-eth0 type veth peer name s1-eth2
ip link show
# Move host ports into namespaces
ip link set h1-eth0 netns h1
ip link show
ip link set h2-eth0 netns h2
ip netns exec h1 ip link show
ip netns exec h2 ip link show
# Configure network
ip netns exec h1 ifconfig h1-eth0 10.1
ip netns exec h2 ifconfig h2-eth0 10.2
ip netns exec h1 ifconfig lo up
ip netns exec h1 ifconfig lo up
# Create switch
ovs-vsctl show
ovs-vsctl add-br s1
# Connect switch ports to OVS
ovs-vsctl add-port s1 s1-eth1
ovs-vsctl add-port s1 s1-eth2
ovs-vsctl show
ifconfig s1-eth1 up
ifconfig s1-eth2 up
#Test network
ip netns exec h1 ping -c1 10.2
# Set up OpenFlow controller
ovs-vsctl set-controller s1 tcp:127.0.0.1
ovs-controller ptcp: &
ovs-vsctl show
# Test network
ip netns exec h1 ping -c1 10.2
注：本文操作均在root用户下进行，普通用户未作测试。

1、创建一个network namespace

    创建名称为nstest的network namespace:

        #ip netns add nstest

    列出系统中已存在的network namespace:

        #ip netns list

2、删除一个network namespace

    删除nstest

        #ip netns delete nstest

3、在network namespace中执行命令

    命令格式：

        ip netns exec <network namespace name> <command>

    显示nstest的网卡信息：

        #ip netns exec nstest ip addr

4、在nestwork namespace中启动一个shell

    命令格式：

    ip netns exec <network namespace name> bash

    退出：exit

5、使用ip命令为network namespace配置网卡

    当使用ip命令创建一个network namespace时，会默认创建一个回环设备，默认该设备不启动，启动该设备：

        #ip netns exec nstest ip link set dev lo up

    在主机上创建两张虚拟网卡：

        #ip link add veth-a type veth peer name veth-b

    将veth-b设备添加到nstest的network namespace中，设备veth-a留在主机中：

        #ip link set veth-b netns nstest

    验证network namespace中的网卡(lo和veth-b)：

        #ip netns exec nstest ip link

    为网卡分配ip：

        #ip addr add 10.0.0.1/24 dev veth-a

    启动网卡：

        #ip link set dev veth-a up 

    为nstest的network namespace配置IP：

        #ip netns exec nstest ip addr add 10.0.0.2/24 dev veth-b

    启动nstest的网卡：

        #ip netns exec nstest ip link set dev veth-b up

    使用ip route命令查看veth-a：

        #ip route

    查看veth-b网卡：

        #ip netns exec nstest ip route

    通过ping 命令检测ip配置路由是否成功。

        #ping 10.0.0.2

