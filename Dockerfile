FROM phusion/baseimage:0.10.0

LABEL maintainer "o0tad0o@gmail.com"

CMD ["/sbin/my_init"]

# install packages
RUN apt-get update && apt-get -fy upgrade
RUN apt-get install -fy \
git \
python3 \
python3-pip

# create PKHunter dir
RUN mkdir -p /opt/PKHunter

# create share directory
RUN mkdir -p /opt/logfiles

# clone Phishing Kit Hunter from GitHub into dir
RUN git clone https://github.com/t4d/PhishingKitHunter.git /opt/PKHunter

# install requirements' file 
RUN pip3 install -r /opt/PKHunter/requirements.txt

# You can now build the docker image:
#   'docker build tad/pkhunter .'
# ... and start it with some options (as your local log files repository):
#   'docker run -d -P --name PKHunter --volume /var/log:/opt/logfiles tad/pkhunter'
# You can now execute  shell and start your analysis:
#   'docker exec -ti tad/pkhunter /bin/bash'

