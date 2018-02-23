# Set the base image
FROM ubuntu

# Update application repository list and install the Redis server. 
RUN apt-get update -y && apt-get install -y freeradius
#RUN apt-get install -qy freeradius

# Add the user account
ADD ./users /tmp/users
#RUN grep -q -F 'bob' /etc/freeradius/users || cat /tmp/users >> /etc/freeradius/users
RUN cat /tmp/users >> /etc/freeradius/users

# Add the client information
ADD ./clients.conf /tmp/clients.conf
#RUN grep -q -F 'client 0.0.0.0/0 {' /etc/freeradius/clients.conf || cat /tmp/clients.conf >> /etc/freeradius/clients.conf
RUN cat /tmp/clients.conf >> /etc/freeradius/clients.conf

# Copy in the splunk dictionary
ADD ./splunk.dictionary /etc/freeradius/splunk.dictionary

# Register the dictonary
ADD ./dictionary /tmp/dictionary
#RUN grep -q -F 'splunk.dictionary' /etc/freeradius/dictionary || cat /tmp/dictionary >> /etc/freeradius/dictionary
RUN cat /tmp/dictionary >> /etc/freeradius/dictionary

# Expose the RADIUS server
EXPOSE 1812/udp

#CMD /usr/sbin/freeradius -X

ENTRYPOINT ["/usr/sbin/freeradius","-X"]
#ENTRYPOINT ["/bin/ping","-c","3"]