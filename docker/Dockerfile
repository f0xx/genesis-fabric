FROM alpine:3.20
RUN apk add --no-cache build-base cmake pkgconf linux-headers liburing-dev samurai
WORKDIR /src
COPY . /src
RUN cmake -S /src -B /tmp/build -DCMAKE_BUILD_TYPE=Release -DGENESIS_SANITIZER= \
    && cmake --build /tmp/build -j \
    && cmake --install /tmp/build
WORKDIR /tmp/build
CMD ["ctest", "--output-on-failure"]
