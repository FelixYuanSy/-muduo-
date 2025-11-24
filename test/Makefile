# .PHONY: all
# all: tcp_srv tcp_cli server
# tcp_srv:tcp_ser.cc
# 	g++ -g -std=c++11 $^ -o $@

tcp_cli:tcp_cli.cc
	g++ -g -std=c++11 $^ -o $@

# server:server.cc
# 	g++ -g -std=c++11 $^ -o $@

.PHONY: clean
clean:
	rm -f tcp_srv tcp_cli server