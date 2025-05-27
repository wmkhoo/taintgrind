FROM ubuntu:bionic

RUN apt update
RUN apt install -y git wget gcc build-essential automake python gcc-multilib
RUN mkdir /code

# build, install valgrind
RUN wget -O /code/valgrind.tar.bz2 https://sourceware.org/pub/valgrind/valgrind-3.25.1.tar.bz2
RUN cd /code && \
    tar jxf /code/valgrind.tar.bz2 && \
    mv valgrind-3.25.1 valgrind

# clone taintgrind
RUN cd /code/valgrind && \
    git clone https://github.com/wmkhoo/taintgrind

# build capstone
RUN cd /code/valgrind/taintgrind && \
    ./build_taintgrind.sh

# dispatch via entrypoint script
# recommend mapping the /pwd volume, probably like (for ELF file):
#
#    docker run -it --rm -v $(pwd):/pwd taintgrind /pwd/someexe
VOLUME /pwd
WORKDIR /code/valgrind/taintgrind
RUN chmod +x /code/valgrind/taintgrind/entrypoint.sh
ENTRYPOINT ["/code/valgrind/taintgrind/entrypoint.sh"]
