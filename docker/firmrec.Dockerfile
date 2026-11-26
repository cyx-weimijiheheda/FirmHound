FROM xylearn/firmrec-base:latest

USER root
WORKDIR /root
COPY firmrec ./firmrec
COPY firmlib ./firmlib
COPY scripts ./scripts
COPY extractor ./extractor
COPY config.yaml ./config.yaml
ENV LC_ALL=C PARALLEL=1
# The runner uses bash -lc; Debian's login profile otherwise hides conda/JDK.
RUN printf '\nexport PATH=/root/miniconda/bin:/root/jdk/bin:$PATH\n' >> /root/.bash_profile
ENTRYPOINT ["/bin/bash"]
