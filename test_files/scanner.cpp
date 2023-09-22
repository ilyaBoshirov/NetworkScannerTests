#include "scanner.h"

#include <QTcpSocket>
#include <QProcess>
#include <QFile>
#include <QTextStream>
#include <QRegularExpression>


Scanner::Scanner() {
    this->scannedNetworks = getCurrentNetworks();
    this->scannedHosts = getNetworksHosts(this->scannedNetworks);
}

Scanner::Scanner(const QList<QString>& scannedNetworks) {
    this->scannedNetworks = scannedNetworks;
    this->scannedHosts = getNetworksHosts(scannedNetworks);
}

QList<QString> Scanner::getScannedNetworks() {
    return this->scannedNetworks;
}

QList<QString> Scanner::getActiveHosts() {
    return this->activeHosts;
}

void Scanner::addActiveHost(const QString& hostIp) {
    this->activeHosts.append(hostIp);
}

void Scanner::initByCurrentNetworks() {
    this->scannedNetworks = getCurrentNetworks();
}

void Scanner::initByFile(const QString& filePath) {
    this->scannedNetworks = getNetworksFromFile(filePath);
}

void Scanner::initByNetworksString(QString& networksString) {
    auto networks = networksString.split(QRegularExpression("[,;\r\n\t ]+"));

    this->scannedNetworks.clear();
    foreach (const auto& network, networks) {
        if (!networkIsCorrect(network)) {
            this->scannedNetworks.append(network);
        }
    }
}

size_t Scanner::getAllHostNumber() {
    auto allHostNumber{0};

    if (this->scannedNetworks.size() == 0) {
        return allHostNumber;
    }

    foreach (const auto& net, this->getScannedNetworks()) {
        auto mask = net.split("/")[1].toInt();

        allHostNumber += (1 << (32 - mask)) - 2;
    }
    return allHostNumber;
}

// static methods -------------------------------------------------------------------------------------

QList<QString> Scanner::getNetworksHosts(const QList<QString>& networks) {
    QList<QString> networksHosts{};

    foreach (const auto& network, networks) {
        networksHosts += getNetworkIPs(network);
    }

    return networksHosts;
}

QList<QString> Scanner::getNetworksFromString(QString& networksString) {
    auto networks = networksString.split(QRegularExpression("[,;\r\n\t ]+"));

    QList<QString> resNet{};
    foreach (const auto& network, networks) {
        if (networkIsCorrect(network)) {
            resNet.append(network);
        }
    }

    return resNet;
}

QList<QString> Scanner::getNetworksFromFile(const QString& filePath) {
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        qDebug() << "Error open file" << filePath;
        return QList<QString>{};
    }

    QList<QString> networks{};
    QRegularExpression re("(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})/(\\d{1,2})");
    QRegularExpressionMatchIterator matchIterator;
    QRegularExpressionMatch match;
    QTextStream in(&file);

    while (!in.atEnd()) {
        auto line = in.readLine();
        matchIterator = re.globalMatch(line);

        while (matchIterator.hasNext()) {
            match = matchIterator.next();
            QString net = match.captured();
            if(networkIsCorrect(net)) {
                networks.append(net);
            }
        }
    }

    return networks;
}

QMap<QString, QString> Scanner::getPhysicalInterfaces() {
    QMap<QString, QString> ifacesAddresses{};
    auto ifaces = QNetworkInterface::allInterfaces();

    foreach (const auto& iface, ifaces) {

        if (!isPhysicalInterface(iface)) {
            continue;
        }

        auto addressEntries = iface.addressEntries();

        foreach (const auto& entry, addressEntries) {
            auto ifaceIP = entry.ip();

            if (QAbstractSocket::IPv4Protocol == ifaceIP.protocol()) {
                ifacesAddresses[iface.humanReadableName()] = getNetwork(ifaceIP, entry.netmask());
            }
        }
    }

    return ifacesAddresses;
}

QList<QString> Scanner::getCurrentNetworks() {
    QList<QString> networks{};
    auto ifaces = QNetworkInterface::allInterfaces();

    foreach (const auto& iface, ifaces) {

        if (!isPhysicalInterface(iface)) {
            continue;
        }

        auto addressEntries = iface.addressEntries();

        foreach (const auto& entry, addressEntries) {
            auto ifaceIP = entry.ip();

            if (QAbstractSocket::IPv4Protocol == ifaceIP.protocol()) {
                networks.append(getNetwork(ifaceIP, entry.netmask()));
            }
        }
    }

    return networks;
}

QMap<QString, QString> Scanner::getCurrentIPs() {
    QMap<QString, QString> ifacesAddresses;

    auto ifaces = QNetworkInterface::allInterfaces();

    foreach (const auto& iface, ifaces) {

        if (!isPhysicalInterface(iface)) {
            continue;
        }

        auto addressEntries = iface.addressEntries();

        foreach (const auto& entry, addressEntries) {
            auto ifaceIP = entry.ip();

            if (QAbstractSocket::IPv4Protocol == ifaceIP.protocol()) {
                ifacesAddresses[iface.humanReadableName()] = ifaceIP.toString();
            }
        }
    }

    return ifacesAddresses;
}

QString Scanner::getNetwork(const QHostAddress& ip, const QHostAddress& netmask) {
    auto ipOctets = ip.toString().split(".");
    auto netmaskOctets = netmask.toString().split(".");

    QString network{""};
    network.append(QString::number(ipOctets[0].toInt() & netmaskOctets[0].toInt()));
    network.append(".");

    network.append(QString::number(ipOctets[1].toInt() & netmaskOctets[1].toInt()));
    network.append(".");

    network.append(QString::number(ipOctets[2].toInt() & netmaskOctets[2].toInt()));
    network.append(".");

    network.append(QString::number(ipOctets[3].toInt() & netmaskOctets[3].toInt()));
    network.append("/");

    quint32 digitNetmask = 0;

    foreach (const auto& octet, netmaskOctets) {
        quint32 dOctet = octet.toInt();
        for(auto i{ 7 }; i >= 0; --i) {
            if (((dOctet >> i) & 0x1) == 1) {
                ++digitNetmask;
            }
            else {
                break;
            }
        }
    }

    network.append(QString::number(digitNetmask));

    return network;
}

QList<QString> Scanner::getNetworkIPs(const QString& network) {
    // network in format "192.168.0.0/24"

    auto networkParts = network.split("/");

    auto start = ipToInteger(networkParts[0]);
    auto mask = networkParts[1].toInt();

    if (mask == 32) {
        return QList<QString>{};
    }

    auto hostNumber = (1 << (32 - networkParts[1].toInt())) - 1;

    QList<QString> hosts{};
    for(auto i{1}; i < hostNumber; ++i) {
        hosts.append(integerToIp(start + i));
    }

    return hosts;
}

bool Scanner::isPhysicalInterface(const QNetworkInterface& interface) {
    auto ifaceFlags = interface.flags();

    if ((bool)(ifaceFlags & interface.IsLoopBack) == true) {
        return false;
    }

    if ((bool)(ifaceFlags & interface.IsRunning) != true) {
        return false;
    }

    auto ifaceName = interface.humanReadableName();

    if (ifaceName.contains("VMware")) {
        return false;
    }

    if (ifaceName.contains("Virtualbox")) {
        return false;
    }

    return true;
}

quint32 Scanner::ipToInteger(const QString& stringIP) {
    auto ipOctets = stringIP.split(".");

    quint32 integerIP {0};

    foreach (auto octet, ipOctets) {
        integerIP = integerIP << 8;
        integerIP ^= octet.toInt();
    }

    return integerIP;
}

QString Scanner::integerToIp(const quint32& integerIP) {
    QString stringIP{""};

    stringIP.append(QString::number((integerIP >> 24) & 0xff));
    stringIP.append(".");

    stringIP.append(QString::number((integerIP >> 16) & 0xff));
    stringIP.append(".");

    stringIP.append(QString::number((integerIP >> 8) & 0xff));
    stringIP.append(".");

    stringIP.append(QString::number(integerIP & 0xff));

    return stringIP;
}

QString Scanner::currentNetworksToQSting() {
    auto currentNetworks = getCurrentNetworks();

    QString networksString{""};

    foreach (const auto network, currentNetworks) {
        networksString.append(network);
        networksString.append(";");
    }

    return networksString;
}

bool Scanner::networkIsCorrect(const QString& networkString) {
    auto networkParts = networkString.split("/");

    if (networkParts.size() != 2) {
        return false;
    }

    auto ipOctets = networkParts[0].split(".");
    auto mask = networkParts[1].toInt();

    if (mask > 32 || mask < 1) {
        return false;
    }

    if (ipOctets.size() != 4) {
        return false;
    }

    foreach (auto octet, ipOctets) {
        auto intOctet = octet.toInt();

        if (intOctet > 255 || intOctet < 0) {
            return false;
        }
    }

    return true;
}

bool Scanner::networksStringIsCorrect(const QString& networksString) {
    if (networksString.length() == 0) {
        return false;
    }

    auto networks = networksString.split(QRegularExpression("[,;\r\n\t ]+"));

    foreach (const auto& network, networks) {
        if (!networkIsCorrect(network)) {
            return false;
        }
    }

    return true;
}

bool Scanner::ipInNetwork(const QString& ip, const QString& network) {
    auto networkParts = network.split("/");

    auto start = ipToInteger(networkParts[0]);
    auto mask = networkParts[1].toInt();
    auto hostNumber = (1 << (32 - mask)) - 1;

    auto ipInt = ipToInteger(ip);

    if (ipInt >= (start + 1) && ipInt <= (start + hostNumber - 1)) {
        return true;
    }

    return false;
}
