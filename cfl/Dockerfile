FROM gcr.io/oss-fuzz-base/base-builder

# Enhanced ClusterFuzzLite Dockerfile
# Combined Address + Undefined Sanitizers with Full Instrumentation
# Improved Stack Tracing, Metrics Capture, and Reporting

RUN apt-get update && apt-get install -y \
  cmake \
  libxml2-dev \
  libpng-dev \
  libjpeg-turbo8-dev \
  libtiff-dev \
  nlohmann-json3-dev \
  && rm -rf /var/lib/apt/lists/*

COPY . $SRC/uci
WORKDIR $SRC/uci
COPY .clusterfuzzlite/build.sh $SRC/
