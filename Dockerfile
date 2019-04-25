FROM ubuntu:bionic

RUN apt-get update
RUN apt-get install -y git wget gcc build-essential automake python
RUN mkdir /code

# build, install valgrind
RUN wget -O /code/valgrind.tar.bz2 https://sourceware.org/pub/valgrind/valgrind-3.15.0.tar.bz2
RUN cd /code && \
    tar jxf /code/valgrind.tar.bz2 && \
    mv valgrind-3.15.0 valgrind
RUN cd /code/valgrind && \
    ./autogen.sh && \
    ./configure --prefix=`pwd`/build && \
    make && \
    make install

# clone taintgrind
RUN cd /code/valgrind && \
    git clone https://github.com/wmkhoo/taintgrind

# build capstone
RUN cd /code/valgrind/taintgrind && \
    wget https://github.com/aquynh/capstone/archive/3.0.4.tar.gz -O capstone.tar.gz && \
    tar xf capstone.tar.gz && \
    sh configure_capstone.sh `pwd`/../build && \
    cd capstone-3.0.4 && \
    sh make_capstone.sh

# build taintgrind
RUN cd /code/valgrind/taintgrind && \
    ../autogen.sh && \
    ./configure --prefix=`pwd`/../build && \
    make && \
    make install && \
    make check

# dispatch via entrypoint script
# recommend mapping the /pwd volume, probably like (for ELF file):
#
#    docker run -it --rm -v $(pwd):/pwd taintgrind /pwd/someexe
VOLUME /pwd
WORKDIR /code/valgrind/taintgrind
RUN chmod +x /code/valgrind/taintgrind/entrypoint.sh
ENTRYPOINT ["/code/valgrind/taintgrind/entrypoint.sh"]
