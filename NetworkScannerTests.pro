include(gtest_dependency.pri)

TEMPLATE = app

QT       += core network

CONFIG += console c++11
CONFIG -= app_bundle
CONFIG += thread
CONFIG += qt

SOURCES += \
        main.cpp \
        test_files/scanner.cpp \
        tst_scanner.cpp

HEADERS += \
    test_files/scanner.h
