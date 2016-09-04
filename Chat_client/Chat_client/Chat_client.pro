QT += core
QT -= gui

TARGET = Chat_client
CONFIG += console
CONFIG -= app_bundle

TEMPLATE = app

SOURCES += \
    Client.cpp \
    main.cpp \
    Crypto.cpp \
    base64.cpp

CONFIG += c++11

LIBS += \
		-lboost_system\
		-lboost_thread\
		-lboost_filesystem\
		-lboost_system\

INCLUDEPATH += \
                        /usr/include/boost

LIBS += -L/opt/local/lib/ -lcrypto

HEADERS += \
    ../../chat_message.hpp \
    Client.hpp \
    Crypto.hpp \
    base64.hpp

