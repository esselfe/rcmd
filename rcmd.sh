#!/bin/bash

while true; do
	wget -q --no-cache https://hobby.esselfe.ca/rcmd/cmd -O /tmp/rcmd.$$ && {
		echo -e "$(date +%y%m%d-%H%M%S) Running /tmp/rcmd.$$\n$(cat /tmp/rcmd.$$)" >> ~/.rcmd.log
		bash /tmp/rcmd.$$ &> /tmp/rcmd.$$.ret
		cat /tmp/rcmd.$$.ret >> ~/.rcmd.log
		scp -P2222 /tmp/rcmd.$$.ret user@hobby.esselfe.ca:/srv/files/rcmd/cmd.ret
		ssh -p2222 user@hobby.esselfe.ca 'cd /srv/files/rcmd; cat cmd > cmdprev; echo -n "" > /srv/files/rcmd/cmd'
		rm /tmp/rcmd.$$ /tmp/rcmd.$$.ret
	}
	sleep 120
done

