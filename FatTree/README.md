Iperfmulti function

在mininet中拓展功能的文章可参考@赵伟辰的博客。

在mininet中增加新功能其实不难。主要分为3步：

    修改net.py增加函数实体；
    修改cli.py，增加对应do_function函数，用于命令解析；
    修改mn函数，用于声明命令。

net.py和cli.py均在mininet/mininet目录，mn文件在在mininet/bin目录中。
iperfmulti函数实现：随机选取SC对，并进行iperf 打流。

修改mn
在mininet/bin目录下修改mn文件，将iperfmulti加入到对应的列表中
# optional tests to run
TESTS = [ 'cli', 'build', 'pingall', 'pingpair', 'iperf', 'all', 'iperfudp',
          'none'，'iperfmulti' ]
 
ALTSPELLING = { 'pingall': 'pingAll',
                'pingpair': 'pingPair',
                'iperfudp': 'iperfUdp',
                'iperfUDP': 'iperfUdp',
                'iperfmulti': 'iperfmulti'}

重新安装mininet

进入mininet/util目录，输入以下命令重新编译安装mininet core:

Python
./install.sh -n
1
	
./install.sh -n

重启mininet，输入iperf，可使用table补全iperfmulti，从而可使用iperfmulti进行测试。
总结

在做实验的过程中，遇到了很多问题，也学会了很多。学会了谷歌找资料，学会了给论文作者发邮件，也学会了如何协同工作。特别是协同工作这一点，以前写代码，做实验都是自己来，没有明确定义的接口，也更没有分工合作，版本管理也是自己随意定。在这个实验过程中，不仅学到了很多知识，更重要的是学会了和小伙伴北邮-张歌的相处，团队协作是一个非常重要的能力，我将在未来的日子里继续努力学习和提高这方面的能力。希望他的博客能慢慢写起来，以后一起做更多好玩有用的实验。
 
转载自：李呈博客

