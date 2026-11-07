ARG BUILD_FROM
FROM $BUILD_FROM
RUN apk add --no-cache python3 curl \
 && apk add --no-cache --virtual .build build-base python3-dev \
 && python3 -m venv /opt/pppp \
 && /opt/pppp/bin/pip install --no-cache-dir aiopppp==0.2.3 \
 && apk del .build
COPY patch_main.py /opt/patch_main.py
RUN /opt/pppp/bin/python /opt/patch_main.py
COPY run.sh /run.sh
RUN chmod a+x /run.sh
CMD ["/run.sh"]
