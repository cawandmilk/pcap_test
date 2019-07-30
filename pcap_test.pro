TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
SOURCES += \
    main.cpp \
    packet.cpp

HEADERS += \
    libnet/include/libnet/libnet-macros.h \
    libnet/include/libnet/libnet-headers.h \
    packet.h
