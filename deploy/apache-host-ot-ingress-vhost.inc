# Insert this block in every TLS VirtualHost for modbus.sitoclone.it, before the
# generic ProxyPass "/" rule.  Apache terminates TLS; the loopback receiver then
# authenticates the raw body with its sensor-bound HMAC key.
<Location "/api/host-ot/v1/events">
	AuthType None
	Require all granted
	LimitRequestBody 65536
</Location>
ProxyPass "/api/host-ot/v1/events" "http://127.0.0.1:8520/v1/events" retry=0 timeout=15
ProxyPassReverse "/api/host-ot/v1/events" "http://127.0.0.1:8520/v1/events"
