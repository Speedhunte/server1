#include "sslserver.h"

#include <QDataStream>
#include <QPointer>
#include <QSslPreSharedKeyAuthenticator>
#include <QMessageBox>
#include <QApplication>
#include <QSslCipher>
#include <QSslConfiguration>

SslServer::SslServer(QObject *parent)
    : QTcpServer{parent}
{

}

SslServer::~SslServer()
{
    //Разрываем все соединения при закрытии
    for (auto &socket : sockets_)
    {
        disconnect(socket.first, &QSslSocket::disconnected, this, &SslServer::Disconnect);
        socket.first->disconnectFromHost();
        socket.first->waitForDisconnected();
    }
}

void SslServer::incomingConnection(qintptr socket_escriptor)
{
    //Есть запрос на соединение
    //сначала нужно установить параметры соединения

    QPointer <QSslSocket> socket = new QSslSocket;
    QSslConfiguration conf;
    conf.setProtocol(QSsl::TlsV1_2);
    conf.setPeerVerifyMode(QSslSocket::VerifyNone);
    QList <QSslCipher> ciphers;
    for (auto &cipher : conf.supportedCiphers())
    {
        if (cipher.name() == CIPHER_NAME) ciphers.push_back(cipher);
    }
    if (!ciphers.empty())
    {
        conf.setCiphers(ciphers);
    }
    else
    {
        QMessageBox::critical(nullptr, "Критическая ошибка!", "Ошибка выбора алгоритма шифрования.");
        QApplication::exit(1);
    }
    socket->setSslConfiguration(conf);

    if (socket->setSocketDescriptor(socket_escriptor))
    {
        //теперь инициализируем сокет, если параметры применились успешно
        //и шифруем соединение

        addPendingConnection(socket);
        connect(socket, &QSslSocket::encrypted, this, &SslServer::Ready);
        connect(socket, QOverload <const QList <QSslError> &>::of(&QSslSocket::sslErrors), [this](const QList <QSslError> & /*errors*/)
        {
            emit SslError();
        });
        connect(socket, QOverload <QAbstractSocket::SocketError>::of(&QSslSocket::errorOccurred), [this](QAbstractSocket::SocketError /*error*/)
        {
            emit SslError();
        });
        connect(socket, &QSslSocket::preSharedKeyAuthenticationRequired, this, [](QSslPreSharedKeyAuthenticator* authenticator)
        {
            authenticator->setPreSharedKey(QByteArrayLiteral("XmlTLSClientServer"));
        });
        socket->startServerEncryption();
        socket.clear();
    }
    else
    {
        emit ConnectionError();
    }
}

void SslServer::ProcessMessage(QSslSocket *socket, QDataStream &in)
{
    //От клиента пришло текстовое сообщение
    //нужно отобразить его в логе и отправить всем клиентам

    QString msg;
    in >> msg;

    auto const &socket_data = sockets_[socket];

    QByteArray ba;
    QDataStream out(&ba, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_5_15);
    auto current_date_time = QDateTime::currentDateTime().toString();
    out << quint16(0) << kMessage << socket->localAddress().toString() << socket_data.username_ << current_date_time << msg;

    out.device()->seek(0);
    out << quint16(ba.size() - sizeof(quint16));

    for (auto &other_socket : sockets_)
    {
        other_socket.first->write(ba);
    }

    emit MessageReceived(socket->localAddress().toString(), socket_data.username_, current_date_time, msg);
}

void SslServer::ProcessStatus(QSslSocket *socket, QDataStream &in)
{
    //Пришёл запрос на смену статуса

    Status status;
    in >> status;

    auto &socket_data = sockets_[socket];
    socket_data.status_ = status;
    emit UserStatusChanged(socket_data.username_, status);

    //разрешаем смену статуса этому клиенту
    QByteArray ba;
    QDataStream out(&ba, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_5_15);
    QString status_string;
    switch (status)
    {
    case kAvailable:
        status_string = "Доступен";
        break;
    case kMovedAway:
        status_string = "Отошёл";
        break;
    case kDoNotDisturb:
        status_string = "Не беспокоить";
        break;
    }
    out << quint16(0) << kStatus << socket_data.username_ << status_string;

    out.device()->seek(0);
    out << quint16(ba.size() - sizeof(quint16));

    //всем остальным клиентам сообщаем, что статус этого клиента изменился
    for (auto &other_socket : sockets_)
    {
        other_socket.first->write(ba);
    }
}

void SslServer::ProcessUsername(QSslSocket *socket, QDataStream &in)
{
    //Пришёл запрос на смену имени пользователя

    QString username;
    in >> username;

    QString old_username;

    auto &socket_data = sockets_[socket];
    old_username = socket_data.username_;
    emit UsernameChanged(old_username, username);

    //Если такое имя пользователя уже есть на сервере, запрещаем изменение имени
    bool username_exists = (std::find_if(sockets_.begin(), sockets_.end(), [&username](auto const &socket_data)
    {
        if (socket_data.second.username_ == username) return true;
        return false;
    }) != sockets_.end());

    QByteArray ba;
    QDataStream out(&ba, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_5_15);

    if (username_exists)
    {
        out << quint16(0) << kInvalidUsername;
    }
    else
    {
        //если такого имени пользователя ещё нет, разрешаем смену
        socket_data.username_ = username;
        out << quint16(0) << kUsername << old_username << username;
    }

    out.device()->seek(0);
    out << quint16(ba.size() - sizeof(quint16));

    if (username_exists)
    {
        socket->write(ba);
    }
    else
    {
        //всем остальным клиентам сообщаем, что этот клиент изменил имя пользователя
        for (auto &other_socket : sockets_)
        {
            other_socket.first->write(ba);
        }
    }
}

void SslServer::Ready()
{
    //Если соединение успешно зашифровано, ждём имя пользователя от нового клиента
    QSslSocket *socket = dynamic_cast <QSslSocket *> (sender());
    if (!socket->isEncrypted())
    {
        delete socket;
        emit CryptError();
        return;
    }

    connect(socket, &QSslSocket::readyRead, this, &SslServer::ReadyForUsername);
    connect(socket, &QSslSocket::disconnected, this, &SslServer::Disconnect);
}

void SslServer::ReadyForUsername()
{
    //Получили имя пользователя от нового клиента

    QSslSocket *socket = dynamic_cast <QSslSocket *> (sender());
    QDataStream in(socket);
    in.setVersion(QDataStream::Qt_5_15);

    quint16 block_size = 0;
    for (;;)
    {
        if (!block_size)
        {
            if (socket->bytesAvailable() < (qint64)sizeof(quint16)) break;
            in >> block_size;
        }
        if (socket->bytesAvailable() < block_size) break;

        QString username;
        in >> username;
        //если такого имени пользователя на сервере ещё нет, то пользователь авторизовался успешно
        //за ним закрепляется это имя
        //иначе разрываем соединение, сообщая, что имя занято
        bool username_exists = (std::find_if(sockets_.begin(), sockets_.end(), [&username](auto const &socket_data)
        {
            if (socket_data.second.username_ == username) return true;
            return false;
        }) != sockets_.end());

        QByteArray ba;
        QDataStream out(&ba, QIODevice::WriteOnly);
        out.setVersion(QDataStream::Qt_5_15);
        out << quint16(0);

        SocketInfo *socket_info;
        if (username_exists)
        {
            out << kInvalidHello << QString("Такое имя пользователя уже существует, %1!").arg(username);
        }
        else
        {
            out << kHello << QString("Успешная авторизация, %1!").arg(username);
            socket_info = &(sockets_[socket] = SocketInfo());
            socket_info->connect_date_time_ = QDateTime::currentDateTime();
            socket_info->status_ = kAvailable;
            socket_info->username_ = username;
            socket_info->ip_ = socket->localAddress().toString();
            QList <QStringList> socket_infos;
            //При успешной авторизации посылаем клиенту также информацию обо всех клиентах которые уже есть на сервере
            for (auto &socket_data : sockets_)
            {
                QString status;
                switch (socket_data.second.status_)
                {
                case kAvailable:
                    status = "Доступен";
                    break;
                case kMovedAway:
                    status = "Отошёл";
                    break;
                case kDoNotDisturb:
                    status = "Не беспокоить";
                    break;
                }
                socket_infos.push_back(QStringList() << socket_data.second.connect_date_time_.toString() <<
                                                        status <<
                                                        socket_data.second.ip_ <<
                                                        socket_data.second.username_);
            }
            out << socket_infos;
        }

        out.device()->seek(0);
        out << quint16(ba.size() - sizeof(quint16));

        if (username_exists)
        {
            socket->write(ba);
        }
        else
        {
            //Также при успешной авторизации всем остальным клиентам сообщаем, что появился новый пользователь и отсылаем информацию о нём
            emit UserAdded(username);
            socket->write(ba);

            QByteArray ba2;
            QDataStream out2(&ba2, QIODevice::WriteOnly);

            out2 << quint16(0) << kUserAdded << socket_info->ip_ << socket_info->connect_date_time_ << socket_info->status_ << socket_info->username_;
            out2.device()->seek(0);
            out2 << quint16(ba2.size() - sizeof(quint16));
            for (auto &other_socket : sockets_)
            {
                if (other_socket.first == socket) continue;
                other_socket.first->write(ba2);
            }

            disconnect(socket, &QSslSocket::readyRead, this, &SslServer::ReadyForUsername);
            connect(socket, &QSslSocket::readyRead, this, &SslServer::Read);
        }
    }
}

void SslServer::Read()
{
    //Функция обработки любого поступившего сообщения

    QSslSocket *socket = dynamic_cast <QSslSocket *> (sender());
    QDataStream in(socket);
    in.setVersion(QDataStream::Qt_5_15);

    quint16 block_size = 0;
    for (;;)
    {
        if (!block_size)
        {
            if (socket->bytesAvailable() < (qint64)sizeof(quint16)) break;
            in >> block_size;
        }
        if (socket->bytesAvailable() < block_size) break;

        MessageType message_type;
        in >> message_type;

        //Дальнейшая обработка в зависимости от типа сообщения
        switch (message_type)
        {
        case kMessage:
            ProcessMessage(socket, in);
            break;
        case kStatus:
            ProcessStatus(socket, in);
            break;
        case kUsername:
            ProcessUsername(socket, in);
            break;
        case kInvalidUsername:
            break;
        case kInfo:
            break;
        default:
            break;
        }
    }
}

void SslServer::Disconnect()
{
    //Если клиент отключился, удаляем его из списка
    //Также сообщаем всем остальным клиентам, что он отключился

    auto socket = dynamic_cast <QSslSocket *> (sender());
    auto it = sockets_.find(socket);
    if (it != sockets_.end())
    {
        emit UserRemoved(it->second.username_);
        for (auto &other_socket : sockets_)
        {
            if (other_socket.first == socket) continue;
            QByteArray ba;
            QDataStream out(&ba, QIODevice::WriteOnly);
            out.setVersion(QDataStream::Qt_5_15);
            out << quint16(0) << kUserRemoved << it->second.username_;
            out.device()->seek(0);
            out << quint16(ba.size() - sizeof(quint16));
            for (auto &other_socket : sockets_)
            {
                if (other_socket.first == socket) continue;
                other_socket.first->write(ba);
            }
        }
        sockets_.erase(it);
    }
}
