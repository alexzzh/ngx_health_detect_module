#!/bin/bash

#need adapt to your test env 
base_seq=30000 #backend server start port
server=10.0.229.99:641 
http_location="http_api"
tcp_location="tcp_api"


cat ./test-usage

if [ $1 = "http_api" ]; then
    api_type=$http_location
elif [ $1 = "tcp_api" ]; then	
    api_type=$tcp_location
else
    exit 1 
fi

if [ $2 = "add" ]; then
    cmd="add"
	if [ $3 = "tcp" ]; then
		check_type="tcp"
	elif [ $3 = "http" ]; then
		check_type="http"
	else
		exit 1 
	fi 

	if [ $4 -eq 0 ]; then
		need_keepalive=0
	elif [ $4 -eq 1 ]; then
		need_keepalive=1
	else
		exit 1 
	fi 
	start=$5
	end=$6
elif [ $2 = "delete" ]; then
    cmd="delete"
	start=$3
	end=$4
elif [ $2 = "delete_all" ]; then
    cmd=$2

elif [ $2 = "status_all" ]; then
    cmd="status_all"
else
    exit 1 
fi 


if [ $cmd = "add" ];then
    for k in $( seq $start $end)
    do	
     seq=`expr $k + $base_seq`
	 
	if [ $api_type = "http_status" ]; then
		if [ $check_type = "http" ]; then
			if [ $need_keepalive -eq 1 ]; then
			    curl -X POST -i  -H 'Content-Type: application/json'  -d "{\"peer_type\":\"http\",\"peer_addr\":\"10.0.229.100:$seq\",\"send_content\":\"GET / HTTP/1.0\r\nConnection:keep-alive\r\n\r\n\",\"alert_method\":\"log\",\"expect_response\":\"http_2xx\",\"check_interval\":5000,\"check_timeout\":3000, \"need_keepalive\": 1, \"keepalive_time\": 200000, \"rise\":1, \"fall\":2}"  $server/$api_type/control\?cmd=$cmd\&name=nginx${k}
			else
				curl -X POST -i  -H 'Content-Type: application/json'  -d "{\"peer_type\":\"http\",\"peer_addr\":\"10.0.229.100:$seq\",\"send_content\":\"\",\"alert_method\":\"log\",\"expect_response\":\"http_2xx\",\"check_interval\":5000,\"check_timeout\":3000, \"need_keepalive\": 0, \"keepalive_time\": 100000, \"rise\":1, \"fall\":2}"  $server/$api_type/control\?cmd=$cmd\&name=nginx${k}
			fi 
		else
			if [ $need_keepalive -eq 1 ]; then
				curl -X POST -i  -H 'Content-Type: application/json'  -d "{\"peer_type\":\"tcp\",\"peer_addr\":\"10.0.229.100:$seq\",\"send_content\":\"\",\"alert_method\":\"log\",\"expect_response\":\"http_2xx\",\"check_interval\":5000,\"check_timeout\":3000, \"need_keepalive\": 1, \"keepalive_time\": 200000, \"rise\":1, \"fall\":2}"  $server/$api_type/control\?cmd=$cmd\&name=nginx${k}
			else
				curl  -X POST -i  -H 'Content-Type: application/json'  -d "{\"peer_type\":\"tcp\",\"peer_addr\":\"10.0.229.100:$seq\",\"send_content\":\"\",\"alert_method\":\"log\",\"expect_response\":\"http_2xx\",\"check_interval\":5000,\"check_timeout\":3000, \"need_keepalive\": 0, \"keepalive_time\": 100000, \"rise\":1, \"fall\":2}" $server/$api_type/control\?cmd=$cmd\&name=nginx${k}
			fi 
		fi  
	else
		if [ $check_type = "http" ]; then
			if [ $need_keepalive -eq 1 ]; then
			    curl -X POST -i  -H 'Content-Type: application/json'  -d "{\"peer_type\":\"http\",\"peer_addr\":\"10.0.229.100:$seq\",\"send_content\":\"GET / HTTP/1.0\r\nConnection:keep-alive\r\n\r\n\",\"alert_method\":\"log\",\"expect_response\":\"http_2xx\",\"check_interval\":5000,\"check_timeout\":3000, \"need_keepalive\": 1, \"keepalive_time\": 200000, \"rise\":1, \"fall\":2}"  $server/$api_type/control\?cmd=$cmd\&name=nginx${k}
			else
				curl -X POST -i  -H 'Content-Type: application/json'  -d "{\"peer_type\":\"http\",\"peer_addr\":\"10.0.229.100:$seq\",\"send_content\":\"\",\"alert_method\":\"log\",\"expect_response\":\"http_2xx\",\"check_interval\":5000,\"check_timeout\":3000, \"need_keepalive\": 0, \"keepalive_time\": 100000, \"rise\":1, \"fall\":2}"  $server/$api_type/control\?cmd=$cmd\&name=nginx${k}
			fi 
		else
			if [ $need_keepalive -eq 1 ]; then
				curl -X POST -i  -H 'Content-Type: application/json'  -d "{\"peer_type\":\"tcp\",\"peer_addr\":\"10.0.229.100:$seq\",\"send_content\":\"\",\"alert_method\":\"log\",\"expect_response\":\"http_2xx\",\"check_interval\":5000,\"check_timeout\":3000, \"need_keepalive\": 1, \"keepalive_time\": 200000, \"rise\":1, \"fall\":2}"  $server/$api_type/control\?cmd=$cmd\&name=nginx${k}
			else
				curl  -X POST -i  -H 'Content-Type: application/json'  -d "{\"peer_type\":\"tcp\",\"peer_addr\":\"10.0.229.100:$seq\",\"send_content\":\"\",\"alert_method\":\"log\",\"expect_response\":\"http_2xx\",\"check_interval\":5000,\"check_timeout\":3000, \"need_keepalive\": 0, \"keepalive_time\": 100000, \"rise\":1, \"fall\":2}"  $server/$api_type/control\?cmd=$cmd\&name=nginx${k}
			fi 
		fi 
	fi 
	done
fi

if [ $cmd = "delete" ];then
    for k in $( seq $start $end)
    do	
	    curl -X DELETE $server/$api_type/control\?cmd=$cmd\&name=nginx${k}
    done
fi

if [ $cmd = "delete_all" ];then
	curl -X DELETE $server/$api_type/control\?cmd=$cmd
fi

if [ $cmd = "status_all" ];then
	curl -X GET $server/$api_type/control\?cmd=$cmd
fi
