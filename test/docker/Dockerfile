ARG PHP_TAG
FROM php:${PHP_TAG}-apache

# SSH server so the scanner's SSH path has something to talk to.
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server \
 && mkdir -p /var/run/sshd \
 && echo 'root:testpass123' | chpasswd \
 && ssh-keygen -A \
 && printf 'PermitRootLogin yes\nPasswordAuthentication yes\n' > /etc/ssh/sshd_config.d/zz-test.conf \
 && rm -rf /var/lib/apt/lists/*

# expose_php is On by default, so Apache sends X-Powered-By: PHP/<version>.
RUN echo '<?php phpinfo();' > /var/www/html/index.php

RUN printf '#!/bin/sh\n/usr/sbin/sshd\nexec apache2-foreground\n' > /start.sh \
 && chmod +x /start.sh

EXPOSE 22 80
CMD ["/start.sh"]
