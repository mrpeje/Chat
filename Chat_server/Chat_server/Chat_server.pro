QT += core
QT -= gui

TARGET = Chat_server
CONFIG += console
CONFIG -= app_bundle

TEMPLATE = app

SOURCES += \
    main_Server.cpp

CONFIG += c++11

LIBS += \
	   -lboost_system\

HEADERS += \
    ../../chat_message.hpp
