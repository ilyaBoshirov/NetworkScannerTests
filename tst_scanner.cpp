
#include <gtest/gtest.h>
#include <gmock/gmock-matchers.h>

#include <QString>
#include <QList>

#include "test_files/scanner.h"


using namespace testing;

TEST(ScannerTests, GetNetworksFromString) {
    // 1st
    QString netStr{"192.168.1.0/24, 10.0.0.0/8"};
    QList<QString> resultList{"192.168.1.0/24", "10.0.0.0/8"};
    EXPECT_EQ(Scanner::getNetworksFromString(netStr), resultList);

    // 2nd
    netStr = "192.168.1.0/24 10.0.0.0/8";
    EXPECT_EQ(Scanner::getNetworksFromString(netStr), resultList);

    // 3rd
    netStr = "192.168.1.0/24; 10.0.0.0/8";
    EXPECT_EQ(Scanner::getNetworksFromString(netStr), resultList);


}

TEST(ScannerTests, IPConverter) {
    EXPECT_EQ(Scanner::ipToInteger("46.53.253.163"), 775290275);
    EXPECT_EQ(Scanner::ipToInteger("36.23.113.1"), 605516033);
    EXPECT_EQ(Scanner::ipToInteger("111.111.111.12"), 1869573900);

    EXPECT_EQ(Scanner::integerToIp(775290275), "46.53.253.163");
    EXPECT_EQ(Scanner::integerToIp(605516033), "36.23.113.1");
    EXPECT_EQ(Scanner::integerToIp(1869573900), "111.111.111.12");
}

TEST(ScannerTests, NetworkCorrectnessCheck) {
    EXPECT_EQ(Scanner::networkIsCorrect("46.53.253.0/24"), true);
    EXPECT_EQ(Scanner::networkIsCorrect("36.23.113.0/-1"), false);
    EXPECT_EQ(Scanner::networkIsCorrect("111.111.111.0/0"), false);
    EXPECT_EQ(Scanner::networkIsCorrect("67.23.98.0/44"), false);
}

TEST(ScannerTests, IPInNetworkTest) {
    EXPECT_EQ(Scanner::ipInNetwork("46.53.253.11","46.53.253.0/24"), true);
    EXPECT_EQ(Scanner::ipInNetwork("46.53.253.11", "36.23.113.0/24"), false);
    ASSERT_TRUE(Scanner::ipInNetwork("111.111.111.250", "111.111.111.0/27") == false);
}

