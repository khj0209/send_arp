TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap

SOURCES += \
        attack_arp.cpp \
        calcul_info.cpp \
        listen_arp.cpp \
        main.cpp \
        normal_arp.cpp

HEADERS += \
    header_struct.h \
    packet_func.h
