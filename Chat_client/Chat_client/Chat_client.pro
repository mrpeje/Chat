QT += core
QT -= gui

TARGET = Chat_client
CONFIG += console
CONFIG -= app_bundle

TEMPLATE = app

SOURCES += \
    main_Client.cpp

CONFIG += c++11

LIBS += \
		-lboost_system\
		-lboost_thread\
		-lboost_filesystem\
		-lboost_system\

HEADERS += \
    ../../chat_message.hpp

