# Set the base image
FROM ubuntu

# Update application repository list and install the freeradius server. 
RUN apt-get update -y && apt-get install -y freeradius

# Add the user account
ADD ./users /tmp/users
RUN cat /tmp/users >> /etc/freeradius/3.0/users

# Add the client information
ADD ./clients.conf /tmp/clients.conf
RUN cat /tmp/clients.conf >> /etc/freeradius/3.0/clients.conf

# Copy in the splunk dictionary
ADD ./splunk.dictionary /etc/freeradius/3.0/splunk.dictionary

# Register the dictonary
ADD ./dictionary /tmp/dictionary
RUN cat /tmp/dictionary >> /etc/freeradius/3.0/dictionary

# Expose the RADIUS server
EXPOSE 1812/udp

ENTRYPOINT ["/usr/sbin/freeradius", "-X"]